pub mod subnet_call_context_manager;
#[cfg(test)]
mod tests;

use crate::{
    canister_state::system_state::CyclesUseCase,
    metadata_state::subnet_call_context_manager::SubnetCallContextManager,
};
use ic_base_types::CanisterId;
use ic_btc_types_internal::BlockBlob;
use ic_certification_version::{CertificationVersion, CURRENT_CERTIFICATION_VERSION};
use ic_constants::MAX_INGRESS_TTL;
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::subnet::v1 as pb_subnet,
    state::{
        canister_state_bits::v1::ConsumedCyclesByUseCase,
        ingress::v1 as pb_ingress,
        queues::v1 as pb_queues,
        system_metadata::v1::{self as pb_metadata},
    },
    types::v1 as pb_types,
};
use ic_registry_routing_table::{
    canister_id_into_u64, difference, intersection, CanisterIdRanges, CanisterMigrations,
    RoutingTable, CANISTER_IDS_PER_SUBNET,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    crypto::CryptoHash,
    ingress::{IngressState, IngressStatus},
    messages::{is_subnet_id, MessageId, RequestOrResponse},
    node_id_into_protobuf, node_id_try_from_option,
    nominal_cycles::NominalCycles,
    state_sync::{StateSyncVersion, CURRENT_STATE_SYNC_VERSION},
    subnet_id_into_protobuf, subnet_id_try_from_protobuf,
    time::{Time, UNIX_EPOCH},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue, StreamSlice},
    CountBytes, CryptoHashOfPartialState, NodeId, NumBytes, PrincipalId, SubnetId,
};
use ic_wasm_types::WasmHash;
use serde::{Deserialize, Serialize};
use std::ops::Bound::{Included, Unbounded};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::{From, TryFrom, TryInto},
    mem::size_of,
    sync::Arc,
};

/// `BTreeMap` of streams by destination `SubnetId`.
pub type StreamMap = BTreeMap<SubnetId, Stream>;

/// Replicated system metadata.  Used primarily for inter-canister messaging and
/// history queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemMetadata {
    /// History of ingress messages as they traversed through the
    /// system.
    pub ingress_history: IngressHistoryState,

    /// XNet stream state indexed by the _destination_ subnet id.
    pub(super) streams: Arc<Streams>,

    /// The canister ID ranges from which this subnet generates canister IDs.
    canister_allocation_ranges: CanisterIdRanges,
    /// The last generated canister ID; or `None` if this subnet has not
    /// generated any canister IDs yet.
    ///
    /// If present, must be within the first `CanisterIdRange` in
    /// `canister_allocation_ranges` (and the latter may not be empty).
    last_generated_canister_id: Option<CanisterId>,

    /// The hash of the previous partial canonical state.
    /// The initial state doesn't have any previous state.
    pub prev_state_hash: Option<CryptoHashOfPartialState>,

    /// The Consensus-determined time this batch was created.
    /// NOTE: this time is monotonically increasing (and not strictly
    /// increasing).
    pub batch_time: Time,

    pub network_topology: NetworkTopology,

    pub own_subnet_id: SubnetId,

    pub own_subnet_type: SubnetType,

    pub own_subnet_features: SubnetFeatures,

    /// DER-encoded public keys of the subnet's nodes.
    pub node_public_keys: BTreeMap<NodeId, Vec<u8>>,

    /// "Subnet split in progress" marker: `Some(original_subnet_id)` if this
    /// replicated state is in the process of being split from `original_subnet_id`;
    /// `None` otherwise.
    ///
    /// During a subnet split, `original_subnet_id` may be used to determine whether
    /// this is subnet A' (when equal to `own_subnet_id`) or B (when different).
    pub split_from: Option<SubnetId>,

    /// Asynchronously handled subnet messages.
    pub subnet_call_context_manager: SubnetCallContextManager,

    /// The version of StateSync protocol that should be used to compute
    /// manifest of this state.
    pub state_sync_version: StateSyncVersion,

    /// The version of certification procedure that should be used for this
    /// state.
    pub certification_version: CertificationVersion,

    /// When canisters execute and modify their heap, we track the actual delta
    /// they produced. From time to time, when consensus tells us that it is
    /// fine to drop older states, the respective deltas are dropped. This field
    /// tracks a deterministic estimate of the size of all the deltas that we
    /// are currently maintaining.
    ///
    /// The reason this field cannot track the actual delta precisely is because
    /// consensus signals the StateManager asynchronously when it can drop older
    /// states and hence the signal is handled in a non-deterministic fashion by
    /// different nodes on the subnet.
    ///
    /// We know that after MR has processed a batch with
    /// "requires_full_state_hash" set, consensus will eventually deliver a
    /// signal to the StateManager to drop states below that batches' height and
    /// this signal will be sent at the latest before consensus sends another
    /// batch with "requires_full_state_hash" set.
    ///
    /// We also use this field to limit further execution in the scheduler when
    /// the canisters have produced more delta than the subnet can handle given
    /// the hardware specs of the subnet. The scheduler's configuration contains
    /// relevant settings for the maximum delta capacity of the subnet.
    ///
    /// Therefore, if we reset this field to 0 in MR when processing a batch
    /// with "requires_full_state_hash" set after the canisters have executed
    /// then the actual total for all the deltas that we are maintaining should
    /// always be <= this field + (the maximum delta capacity of the subnet /
    /// 2).
    pub heap_delta_estimate: NumBytes,

    pub subnet_metrics: SubnetMetrics,

    /// The set of WASM modules we expect to be present in the [`Hypervisor`]'s
    /// compilation cache. This allows us to deterministically decide when we
    /// expect a compilation to be fast and ignore the compilation cost when
    /// considering the round instruction limit.
    ///
    /// Each time a canister is installed, its WASM is inserted and the set is
    /// cleared at each checkpoint.
    pub expected_compiled_wasms: BTreeSet<WasmHash>,

    /// Responses to `BitcoinGetSuccessors` can be larger than the max inter-canister
    /// response limit. To work around this limitation, large responses are paginated
    /// and are stored here temporarily until they're fetched by the calling canister.
    pub bitcoin_get_successors_follow_up_responses: BTreeMap<CanisterId, Vec<BlockBlob>>,
}

/// Full description of the IC network toplogy.
///
/// Contains [`Arc`] references, so it is only safe to serialize for read-only
/// use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub subnets: BTreeMap<SubnetId, SubnetTopology>,
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub routing_table: Arc<RoutingTable>,
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub canister_migrations: Arc<CanisterMigrations>,
    pub nns_subnet_id: SubnetId,
    /// Mapping from ECDSA key_id to a list of subnets which can sign with the
    /// given key. Keys without any signing subnets are not included in the map.
    pub ecdsa_signing_subnets: BTreeMap<EcdsaKeyId, Vec<SubnetId>>,

    /// The ID of the canister to forward bitcoin testnet requests to.
    pub bitcoin_testnet_canister_id: Option<CanisterId>,

    /// The ID of the canister to forward bitcoin mainnet requests to.
    pub bitcoin_mainnet_canister_id: Option<CanisterId>,
}

impl Default for NetworkTopology {
    fn default() -> Self {
        Self {
            subnets: Default::default(),
            routing_table: Default::default(),
            canister_migrations: Default::default(),
            nns_subnet_id: SubnetId::new(PrincipalId::new_anonymous()),
            ecdsa_signing_subnets: Default::default(),
            bitcoin_testnet_canister_id: None,
            bitcoin_mainnet_canister_id: None,
        }
    }
}

impl NetworkTopology {
    /// Returns a list of subnets where the ecdsa feature is enabled.
    pub fn ecdsa_signing_subnets(&self, key_id: &EcdsaKeyId) -> &[SubnetId] {
        self.ecdsa_signing_subnets
            .get(key_id)
            .map(|ids| &ids[..])
            .unwrap_or(&[])
    }

    /// Returns the size of the given subnet.
    pub fn get_subnet_size(&self, subnet_id: &SubnetId) -> Option<usize> {
        self.subnets
            .get(subnet_id)
            .map(|subnet_topology| subnet_topology.nodes.len())
    }
}

impl From<&NetworkTopology> for pb_metadata::NetworkTopology {
    fn from(item: &NetworkTopology) -> Self {
        Self {
            subnets: item
                .subnets
                .iter()
                .map(|(subnet_id, subnet_topology)| pb_metadata::SubnetsEntry {
                    subnet_id: Some(subnet_id_into_protobuf(*subnet_id)),
                    subnet_topology: Some(subnet_topology.into()),
                })
                .collect(),
            routing_table: Some(item.routing_table.as_ref().into()),
            nns_subnet_id: Some(subnet_id_into_protobuf(item.nns_subnet_id)),
            canister_migrations: Some(item.canister_migrations.as_ref().into()),
            ecdsa_signing_subnets: item
                .ecdsa_signing_subnets
                .iter()
                .map(|(key_id, subnet_ids)| {
                    let subnet_ids = subnet_ids
                        .iter()
                        .map(|id| subnet_id_into_protobuf(*id))
                        .collect();
                    pb_metadata::EcdsaKeyEntry {
                        key_id: Some(key_id.into()),
                        subnet_ids,
                    }
                })
                .collect(),
            bitcoin_testnet_canister_ids: match item.bitcoin_testnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
            bitcoin_mainnet_canister_ids: match item.bitcoin_mainnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
        }
    }
}

impl TryFrom<pb_metadata::NetworkTopology> for NetworkTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::NetworkTopology) -> Result<Self, Self::Error> {
        let mut subnets = BTreeMap::new();
        for entry in item.subnets {
            subnets.insert(
                subnet_id_try_from_protobuf(try_from_option_field(
                    entry.subnet_id,
                    "NetworkTopology::subnets::K",
                )?)?,
                try_from_option_field(entry.subnet_topology, "NetworkTopology::subnets::V")?,
            );
        }
        // NetworkTopology.nns_subnet_id will be removed in the following PR
        // Currently, initialise nns_subnet_id with dummy value in case not found
        let nns_subnet_id =
            match try_from_option_field(item.nns_subnet_id, "NetworkTopology::nns_subnet_id") {
                Ok(subnet_id) => subnet_id_try_from_protobuf(subnet_id)?,
                Err(_) => SubnetId::new(PrincipalId::new_anonymous()),
            };
        let mut ecdsa_signing_subnets = BTreeMap::new();
        for entry in item.ecdsa_signing_subnets {
            let mut subnet_ids = vec![];
            for subnet_id in entry.subnet_ids {
                subnet_ids.push(subnet_id_try_from_protobuf(subnet_id)?);
            }
            ecdsa_signing_subnets.insert(
                try_from_option_field(entry.key_id, "EcdsaKeyEntry::key_id")?,
                subnet_ids,
            );
        }

        let bitcoin_testnet_canister_id = match item.bitcoin_testnet_canister_ids.first() {
            Some(canister) => Some(CanisterId::try_from(canister.clone())?),
            None => None,
        };

        let bitcoin_mainnet_canister_id = match item.bitcoin_mainnet_canister_ids.first() {
            Some(canister) => Some(CanisterId::try_from(canister.clone())?),
            None => None,
        };

        Ok(Self {
            subnets,
            routing_table: try_from_option_field(
                item.routing_table,
                "NetworkTopology::routing_table",
            )
            .map(Arc::new)?,
            // `None` value needs to be allowed here because all the existing states don't have this field yet.
            canister_migrations: item
                .canister_migrations
                .map(CanisterMigrations::try_from)
                .transpose()?
                .unwrap_or_default()
                .into(),
            nns_subnet_id,
            ecdsa_signing_subnets,
            bitcoin_testnet_canister_id,
            bitcoin_mainnet_canister_id,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetTopology {
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// https://sdk.dfinity.org/docs/interface-spec/index.html#certification)
    pub public_key: Vec<u8>,
    pub nodes: BTreeSet<NodeId>,
    pub subnet_type: SubnetType,
    pub subnet_features: SubnetFeatures,
    /// ECDSA keys held by this subnet. Just because a subnet holds an ECDSA key
    /// doesn't mean the subnet has been enabled to sign with that key. This
    /// will happen when a key is shared with a second subnet which holds it as
    /// a backup. An additional NNS proposal will be needed to allow the subnet
    /// holding the key as backup to actually produce signatures.
    pub ecdsa_keys_held: BTreeSet<EcdsaKeyId>,
}

impl From<&SubnetTopology> for pb_metadata::SubnetTopology {
    fn from(item: &SubnetTopology) -> Self {
        Self {
            public_key: item.public_key.clone(),
            nodes: item
                .nodes
                .iter()
                .map(|node_id| pb_metadata::SubnetTopologyEntry {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                })
                .collect(),
            subnet_type: i32::from(item.subnet_type),
            subnet_features: Some(pb_subnet::SubnetFeatures::from(item.subnet_features)),
            ecdsa_keys_held: item.ecdsa_keys_held.iter().map(|k| k.into()).collect(),
        }
    }
}

impl TryFrom<pb_metadata::SubnetTopology> for SubnetTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetTopology) -> Result<Self, Self::Error> {
        let mut nodes = BTreeSet::<NodeId>::new();
        for entry in item.nodes {
            nodes.insert(node_id_try_from_option(entry.node_id)?);
        }

        let mut ecdsa_keys_held = BTreeSet::new();
        for key in item.ecdsa_keys_held {
            ecdsa_keys_held.insert(EcdsaKeyId::try_from(key)?);
        }

        Ok(Self {
            public_key: item.public_key,
            nodes,
            // It is fine to use an arbitrary value here. We always reset the
            // field before we actually use it. We pick the value of least
            // privilege just to be sure.
            subnet_type: SubnetType::try_from(item.subnet_type).unwrap_or(SubnetType::Application),
            subnet_features: item
                .subnet_features
                .map(SubnetFeatures::from)
                .unwrap_or_default(),
            ecdsa_keys_held,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SubnetMetrics {
    pub consumed_cycles_by_deleted_canisters: NominalCycles,
    pub consumed_cycles_http_outcalls: NominalCycles,
    pub consumed_cycles_ecdsa_outcalls: NominalCycles,
    consumed_cycles_by_use_case: BTreeMap<CyclesUseCase, NominalCycles>,
    pub ecdsa_signature_agreements: u64,
}

impl SubnetMetrics {
    pub fn observe_consumed_cycles_with_use_case(
        &mut self,
        use_case: CyclesUseCase,
        cycles: NominalCycles,
    ) {
        *self
            .consumed_cycles_by_use_case
            .entry(use_case)
            .or_insert_with(|| NominalCycles::from(0)) += cycles;
    }

    pub fn get_consumed_cycles_by_use_case(&self) -> &BTreeMap<CyclesUseCase, NominalCycles> {
        &self.consumed_cycles_by_use_case
    }
}

impl From<&SubnetMetrics> for pb_metadata::SubnetMetrics {
    fn from(item: &SubnetMetrics) -> Self {
        Self {
            consumed_cycles_by_deleted_canisters: Some(
                (&item.consumed_cycles_by_deleted_canisters).into(),
            ),
            consumed_cycles_http_outcalls: Some((&item.consumed_cycles_http_outcalls).into()),
            consumed_cycles_ecdsa_outcalls: Some((&item.consumed_cycles_ecdsa_outcalls).into()),
            ecdsa_signature_agreements: Some(item.ecdsa_signature_agreements),
            consumed_cycles_by_use_case: item
                .consumed_cycles_by_use_case
                .clone()
                .into_iter()
                .map(|entry| ConsumedCyclesByUseCase {
                    use_case: entry.0.into(),
                    cycles: Some((&entry.1).into()),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::SubnetMetrics> for SubnetMetrics {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetMetrics) -> Result<Self, Self::Error> {
        Ok(Self {
            consumed_cycles_by_deleted_canisters: try_from_option_field(
                item.consumed_cycles_by_deleted_canisters,
                "SubnetMetrics::consumed_cycles_by_deleted_canisters",
            )?,
            consumed_cycles_http_outcalls: try_from_option_field(
                item.consumed_cycles_http_outcalls,
                "SubnetMetrics::consumed_cycles_http_outcalls",
            )
            .unwrap_or_else(|_| NominalCycles::from(0_u128)),
            consumed_cycles_ecdsa_outcalls: try_from_option_field(
                item.consumed_cycles_ecdsa_outcalls,
                "SubnetMetrics::consumed_cycles_ecdsa_outcalls",
            )
            .unwrap_or_else(|_| NominalCycles::from(0_u128)),
            ecdsa_signature_agreements: item.ecdsa_signature_agreements.unwrap_or_default(),
            consumed_cycles_by_use_case: item
                .consumed_cycles_by_use_case
                .into_iter()
                .map(|ConsumedCyclesByUseCase { use_case, cycles }| {
                    (
                        CyclesUseCase::from(use_case),
                        NominalCycles::try_from(cycles.unwrap_or_default()).unwrap_or_default(),
                    )
                })
                .collect(),
        })
    }
}

impl From<&SystemMetadata> for pb_metadata::SystemMetadata {
    fn from(item: &SystemMetadata) -> Self {
        // We do not store the subnet type when we serialize SystemMetadata. We rely on
        // `load_checkpoint()` to properly set this value.
        Self {
            own_subnet_id: Some(subnet_id_into_protobuf(item.own_subnet_id)),
            canister_allocation_ranges: Some(item.canister_allocation_ranges.clone().into()),
            last_generated_canister_id: item.last_generated_canister_id.map(Into::into),
            prev_state_hash: item
                .prev_state_hash
                .clone()
                .map(|prev_hash| prev_hash.get().0),
            batch_time_nanos: item.batch_time.as_nanos_since_unix_epoch(),
            streams: item
                .streams
                .iter()
                .map(|(subnet_id, stream)| pb_queues::StreamEntry {
                    subnet_id: Some(subnet_id_into_protobuf(*subnet_id)),
                    subnet_stream: Some(stream.into()),
                })
                .collect(),
            network_topology: Some((&item.network_topology).into()),
            subnet_call_context_manager: Some((&item.subnet_call_context_manager).into()),
            state_sync_version: item.state_sync_version as u32,
            certification_version: item.certification_version as u32,
            heap_delta_estimate: item.heap_delta_estimate.get(),
            own_subnet_features: Some(item.own_subnet_features.into()),
            subnet_metrics: Some((&item.subnet_metrics).into()),
            bitcoin_get_successors_follow_up_responses: item
                .bitcoin_get_successors_follow_up_responses
                .clone()
                .into_iter()
                .map(
                    |(sender, payloads)| pb_metadata::BitcoinGetSuccessorsFollowUpResponses {
                        sender: Some(sender.into()),
                        payloads,
                    },
                )
                .collect(),
            node_public_keys: item
                .node_public_keys
                .iter()
                .map(|(node_id, public_key)| pb_metadata::NodePublicKeyEntry {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                    public_key: public_key.clone(),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::SystemMetadata> for SystemMetadata {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_metadata::SystemMetadata) -> Result<Self, Self::Error> {
        let mut streams = BTreeMap::<SubnetId, Stream>::new();
        for entry in item.streams {
            streams.insert(
                subnet_id_try_from_protobuf(try_from_option_field(
                    entry.subnet_id,
                    "SystemMetadata::streams::K",
                )?)?,
                try_from_option_field(entry.subnet_stream, "SystemMetadata::streams::V")?,
            );
        }

        let canister_allocation_ranges: CanisterIdRanges = match item.canister_allocation_ranges {
            Some(canister_allocation_ranges) => canister_allocation_ranges.try_into()?,
            None => Default::default(),
        };
        let last_generated_canister_id = item
            .last_generated_canister_id
            .map(TryInto::try_into)
            .transpose()?;
        // Validate that `last_generated_canister_id` (if not `None`) is within the
        // first `canister_allocation_ranges` range.
        if let Some(last_generated_canister_id) = last_generated_canister_id {
            match canister_allocation_ranges.iter().next() {
                Some(first_allocation_range)
                    if first_allocation_range.contains(&last_generated_canister_id) => {}
                _ => return Err(ProxyDecodeError::Other(format!(
                    "SystemMetadata::last_generated_canister_id ({}) not in the first SystemMetadata::canister_allocation_ranges range ({:?})",
                    last_generated_canister_id, canister_allocation_ranges
                ))),
            }
        }

        let mut bitcoin_get_successors_follow_up_responses = BTreeMap::new();
        for response in item.bitcoin_get_successors_follow_up_responses {
            let sender_pb: pb_types::CanisterId = try_from_option_field(
                response.sender,
                "BitcoinGetSuccessorsFollowUpResponses::sender",
            )?;

            let sender = CanisterId::try_from(sender_pb)?;

            bitcoin_get_successors_follow_up_responses.insert(sender, response.payloads);
        }

        let batch_time = Time::from_nanos_since_unix_epoch(item.batch_time_nanos);

        let mut node_public_keys = BTreeMap::<NodeId, Vec<u8>>::new();
        for entry in item.node_public_keys {
            node_public_keys.insert(node_id_try_from_option(entry.node_id)?, entry.public_key);
        }

        Ok(Self {
            own_subnet_id: subnet_id_try_from_protobuf(try_from_option_field(
                item.own_subnet_id,
                "SystemMetadata::own_subnet_id",
            )?)?,
            // WARNING! Setting to the default value which can be incorrect. We do not store the
            // actual value when we serialize SystemMetadata. We rely on `load_checkpoint()` to
            // properly set this value.
            own_subnet_type: SubnetType::default(),
            own_subnet_features: item.own_subnet_features.unwrap_or_default().into(),
            node_public_keys,
            // Note: `load_checkpoint()` will set this to the contents of `split_marker.pbuf`,
            // when present.
            split_from: None,
            canister_allocation_ranges,
            last_generated_canister_id,
            prev_state_hash: item.prev_state_hash.map(|b| CryptoHash(b).into()),
            batch_time,
            // Ingress history is persisted separately. We rely on `load_checkpoint()` to
            // properly set this value.
            ingress_history: Default::default(),
            streams: Arc::new(Streams {
                responses_size_bytes: Streams::calculate_stats(&streams),
                streams,
            }),
            network_topology: try_from_option_field(
                item.network_topology,
                "SystemMetadata::network_topology",
            )?,
            state_sync_version: item
                .state_sync_version
                .try_into()
                .map_err(|_| ProxyDecodeError::UnknownStateSyncVersion(item.state_sync_version))?,
            certification_version: item.certification_version.try_into().map_err(|_| {
                ProxyDecodeError::UnknownCertificationVersion(item.certification_version)
            })?,
            subnet_call_context_manager: match item.subnet_call_context_manager {
                Some(manager) => SubnetCallContextManager::try_from((batch_time, manager))?,
                None => Default::default(),
            },

            heap_delta_estimate: NumBytes::from(item.heap_delta_estimate),
            subnet_metrics: match item.subnet_metrics {
                Some(subnet_metrics) => subnet_metrics.try_into()?,
                None => SubnetMetrics::default(),
            },
            expected_compiled_wasms: BTreeSet::new(),
            bitcoin_get_successors_follow_up_responses,
        })
    }
}

impl SystemMetadata {
    /// Creates a new empty system metadata state.
    pub fn new(own_subnet_id: SubnetId, own_subnet_type: SubnetType) -> Self {
        Self {
            own_subnet_id,
            own_subnet_type,
            ingress_history: Default::default(),
            streams: Default::default(),
            canister_allocation_ranges: Default::default(),
            last_generated_canister_id: None,
            batch_time: UNIX_EPOCH,
            network_topology: Default::default(),
            subnet_call_context_manager: Default::default(),
            own_subnet_features: SubnetFeatures::default(),
            node_public_keys: Default::default(),
            split_from: None,
            // StateManager populates proper values of these fields before
            // committing each state.
            prev_state_hash: Default::default(),
            state_sync_version: CURRENT_STATE_SYNC_VERSION,
            // NB. State manager relies on the root hash of the hash tree
            // corresponding to the initial state to be a constant.  Thus we fix
            // the certification version that we use for the initial state. If
            // we used CURRENT_CERTIFICATION_VERSION here, the state hash would
            // NOT be guaranteed to be constant, potentially leading to
            // hard-to-track bugs in state manager.
            certification_version: CertificationVersion::V0,
            heap_delta_estimate: NumBytes::from(0),
            subnet_metrics: Default::default(),
            expected_compiled_wasms: BTreeSet::new(),
            bitcoin_get_successors_follow_up_responses: BTreeMap::default(),
        }
    }

    pub fn time(&self) -> Time {
        self.batch_time
    }

    /// Returns a reference to the streams.
    pub fn streams(&self) -> &Streams {
        &self.streams
    }

    /// One-off initialization: populate `canister_allocation_ranges` with the only
    /// `[N * 2^20, (N+1) * 2^20 - 1]` range fully hosted by the subnet as per the
    /// routing table; and initialize `last_generated_canister_id` based on
    /// `generated_id_counter`.
    ///
    /// This is done under the assumption that the registry always assigns exactly
    /// 2^20 canister IDs to every newly created subnet (and at this point in time
    /// no canisters have yet been migrated).
    ///
    /// Canister ID allocation range assignment will be made explicit in a follow-up
    /// change.
    ///
    /// Returns `Ok` if `canister_allocation_ranges` is not empty (whether it was
    /// populated by this call or not); `Err` if empty (and the subnet is unable
    /// to generate new canister IDs).
    pub fn init_allocation_ranges_if_empty(&mut self) -> Result<(), String> {
        if !self.canister_allocation_ranges.is_empty() {
            return Ok(());
        }

        let routing_table_ranges = self
            .network_topology
            .routing_table
            .ranges(self.own_subnet_id);
        for range in routing_table_ranges.iter().rev() {
            let start = canister_id_into_u64(range.start);
            let end = canister_id_into_u64(range.end);
            if start % CANISTER_IDS_PER_SUBNET == 0 && end == start + CANISTER_IDS_PER_SUBNET - 1 {
                // Found the `[N * 2^20, (N+1) * 2^20 - 1]` (sub)range, use it as allocation
                // range.
                //
                // Unwrapping is safe because the only reason why we would fail to convert is if
                // we provided set of ranges that was not well formed. This is not the case
                // here, as we are creating a `CanisterIdRanges` out of one non-empty range.
                self.canister_allocation_ranges = vec![*range].try_into().unwrap();
                break;
            }
        }

        if self.canister_allocation_ranges.is_empty() {
            return Err("No range of length CANISTER_IDS_PER_SUBNET in routing table".into());
        }
        Ok(())
    }

    /// Generates a new canister ID.
    ///
    /// If a canister ID from a second canister allocation range is generated, the
    /// first range is dropped. The last canister allocation range is never dropped.
    ///
    /// Returns `Err` iff no more canister IDs can be generated.
    pub fn generate_new_canister_id(&mut self) -> Result<CanisterId, String> {
        // Start off with
        //     (canister_allocation_ranges
        //          ∩ routing_table.ranges(own_subnet_id))
        //          \ canister_migrations.ranges()
        let own_subnet_ranges = self
            .network_topology
            .routing_table
            .ranges(self.own_subnet_id);
        let canister_allocation_ranges = intersection(
            self.canister_allocation_ranges.iter(),
            own_subnet_ranges.iter(),
        )
        .map_err(|err| {
            format!(
                "intersection({:?}, {:?}) is not well formed: {:?}",
                self.canister_allocation_ranges, own_subnet_ranges, err
            )
        })?;
        let canister_allocation_ranges = difference(
            canister_allocation_ranges.iter(),
            self.network_topology.canister_migrations.ranges(),
        )
        .map_err(|err| {
            format!(
                "difference({:?}, {:?}) is not well formed: {:?}",
                canister_allocation_ranges, self.network_topology.canister_migrations, err
            )
        })?;

        let res = canister_allocation_ranges.generate_canister_id(self.last_generated_canister_id);

        if let Some(res) = &res {
            self.last_generated_canister_id = Some(*res);

            while self.canister_allocation_ranges.len() > 1
                && !self
                    .canister_allocation_ranges
                    .iter()
                    .next()
                    .unwrap()
                    .contains(res)
            {
                // Drop the first canister allocation range iff consumed and more allocation
                // ranges are available.
                self.canister_allocation_ranges.drop_first();
            }
        }

        res.ok_or_else(|| "Canister ID allocation was consumed".into())
    }

    /// Returns the number of canister IDs that can still be generated.
    pub fn available_canister_ids(&self) -> u64 {
        let generated_canister_ids = match (
            self.canister_allocation_ranges.start(),
            self.last_generated_canister_id,
        ) {
            (Some(start), Some(last)) => {
                canister_id_into_u64(last) + 1 - canister_id_into_u64(start)
            }
            _ => 0,
        };
        self.canister_allocation_ranges.total_count() as u64 - generated_canister_ids
    }

    /// Splits the `MetadataState` as part of subnet splitting phase 1:
    ///  * for the split subnet (B), produces a new `MetadataState`, with the given
    ///    batch time (if `Some`) or the original subnet's batch time (if `None`);
    ///  * for the subnet that retains the original subnet's ID (A'), returns it
    ///    unmodified (apart from setting the split marker).
    ///
    /// A subnet split starts with a subnet A and results in two subnets, A' and B.
    /// For the sake of clarity, comments refer to the two resulting subnets as
    /// *subnet A'* and *subnet B*. And to the original subnet as *subnet A*.
    /// Because subnet A' retains the subnet ID of subnet A, it is identified by
    /// having `new_subnet_id == self.own_subnet_id`. Conversely, subnet B has
    /// `new_subnet_id != self.own_subnet_id`.
    ///
    /// In this first phase, the ingress history is left untouched on both subnets,
    /// in order to make it trivial to verify that no tampering has occurred. A
    /// split marker is added to both subnets, containing the original subnet ID.
    ///
    /// In phase 2 (see [`Self::after_split()`]) the ingress history is pruned and
    /// the split marker is reset.
    pub fn split(
        mut self,
        subnet_id: SubnetId,
        new_subnet_batch_time: Option<Time>,
    ) -> Result<Self, String> {
        assert_eq!(0, self.heap_delta_estimate.get());
        assert!(self.expected_compiled_wasms.is_empty());

        // No-op for subnet A'.
        if self.own_subnet_id == subnet_id {
            if new_subnet_batch_time.is_some() {
                return Err("Cannot apply a new batch time to the original subnet".into());
            }

            // Set the split marker to the original subnet ID.
            self.split_from = Some(self.own_subnet_id);

            return Ok(self);
        }

        // This is subnet B: use `subnet_id` as its subnet ID.
        let mut res = SystemMetadata::new(subnet_id, self.own_subnet_type);

        // Set the split marker to the original subnet ID (that of subnet A).
        res.split_from = Some(self.own_subnet_id);

        // Preserve ingress history.
        res.ingress_history = self.ingress_history;

        // Ensure monotonic time for migrated canisters: apply `new_subnet_batch_time`
        // if specified and not smaller than `self.batch_time`; else, default to
        // `self.batch_time`.
        res.batch_time = if let Some(batch_time) = new_subnet_batch_time {
            if batch_time < self.batch_time {
                return Err(format!(
                    "Provided batch_time ({}) is before original subnet batch time ({})",
                    batch_time, self.batch_time
                ));
            }
            batch_time
        } else {
            self.batch_time
        };

        // All other fields have been reset to default.
        Ok(res)
    }

    /// Adjusts the `MetadataState` as part of the second phase of subnet splitting,
    /// during the new subnets' startup.
    ///
    /// A subnet split starts with a subnet A and results in two subnets, A' and B,
    /// with canisters split among the two subnets according to the routing table.
    /// Because subnet A' retains the subnet ID of subnet A, it is identified by
    /// having `self.split_from == Some(self.own_subnet_id)`. Conversely, subnet B
    /// has `self.split_from != Some(self.own_subnet_id)`.
    ///
    /// In the first phase (see [`Self::split()`]), the ingress history was left
    /// untouched on both subnets, in order to make it trivial to verify that no
    /// tampering had occurred. Streams, subnet call contexts and metrics and all
    /// other metadata were preserved on subnet A' and set to default on subnet B.
    ///
    /// In this second phase, `ingress_history` is pruned, retaining only messages
    /// in terminal states and messages addressed to local canisters.
    ///
    /// Notes:
    ///  * `prev_state_hash` has just been set by `take_tip()` to the checkpoint
    ///    hash (checked against the hash in the CUP). It must be preserved.
    ///  * `own_subnet_type` has just been set during `load_checkpoint()`, based on
    ///    the registry subnet record of the subnet that this node is part of.
    ///  * `batch_time`, `network_topology` and `own_subnet_features` will be set
    ///    by Message Routing before the start of the next round.
    ///  * `state_sync_version` and `certification_version` will be set by
    ///    `commit_and_certify()` at the end of the round; and not used before.
    ///  * `heap_delta_estimate` and `expected_compiled_wasms` are expected to be
    ///    empty/zero.
    #[allow(dead_code)]
    pub(crate) fn after_split<F>(self, is_local_canister: F) -> Self
    where
        F: Fn(&CanisterId) -> bool,
    {
        // Take apart `self` and put it back together, in order for the compiler to
        // enforce an explicit decision whenever new fields are added.
        let SystemMetadata {
            mut ingress_history,
            streams,
            canister_allocation_ranges,
            last_generated_canister_id,
            prev_state_hash,
            // Overwritten as soon as the round begins, no explicit action needed.
            batch_time,
            // Overwritten as soon as the round begins, no explicit action needed.
            network_topology,
            own_subnet_id,
            // `own_subnet_type` has been set by `load_checkpoint()` based on the subnet
            // registry record of B, do not touch it.
            own_subnet_type,
            // Overwritten as soon as the round begins, no explicit action needed.
            own_subnet_features,
            // Overwritten as soon as the round begins, no explicit action needed.
            node_public_keys,
            split_from,
            subnet_call_context_manager,
            // Set by `commit_and_certify()` at the end of the round. Not used before.
            state_sync_version,
            // Set by `commit_and_certify()` at the end of the round. Not used before.
            certification_version,
            heap_delta_estimate,
            subnet_metrics,
            expected_compiled_wasms,
            bitcoin_get_successors_follow_up_responses,
        } = self;

        let split_from = split_from.expect("Not a state resulting from a subnet split");

        assert_eq!(0, heap_delta_estimate.get());
        assert!(expected_compiled_wasms.is_empty());

        // Prune the ingress history.
        ingress_history = ingress_history.prune_after_split(|canister_id: &CanisterId| {
            // An actual local canister.
            is_local_canister(canister_id)
                // Or this is subnet A' and message is addressed to the management canister.
                || split_from == own_subnet_id && is_subnet_id(*canister_id, own_subnet_id)
        });

        SystemMetadata {
            ingress_history,
            streams,
            canister_allocation_ranges,
            last_generated_canister_id,
            prev_state_hash,
            batch_time,
            network_topology,
            own_subnet_id,
            own_subnet_type,
            own_subnet_features,
            node_public_keys,
            // Split complete, reset split marker.
            split_from: None,
            subnet_call_context_manager,
            state_sync_version,
            certification_version,
            heap_delta_estimate,
            subnet_metrics,
            expected_compiled_wasms,
            bitcoin_get_successors_follow_up_responses,
        }
    }
}

/// Stream is the state of bi-directional communication session with a remote
/// subnet.  It contains outgoing messages having that subnet as their
/// destination and signals for inducted messages received from that subnet.
///
/// Conceptually we use a gap-free queue containing one signal for each inducted
/// message; but because most signals are `Accept` we represent that queue as a
/// combination of `signals_end` (pointing just beyond the last signal) plus a
/// collection of `reject_signals`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    /// Indexed queue of outgoing messages.
    messages: StreamIndexedQueue<RequestOrResponse>,

    /// Index of the next expected reverse stream message.
    ///
    /// Conceptually we use a gap-free queue containing one signal for each
    /// inducted message; but because these signals are all "Accept" (as we
    /// generate responses when rejecting messages), that queue can be safely
    /// represented by its end index (pointing just beyond the last signal).
    signals_end: StreamIndex,

    /// Stream indices of rejected messages, in ascending order.
    reject_signals: VecDeque<StreamIndex>,

    /// Estimated byte size of `self.messages`.
    messages_size_bytes: usize,
}

impl Default for Stream {
    fn default() -> Self {
        let messages = Default::default();
        let signals_end = Default::default();
        let reject_signals = VecDeque::default();
        let messages_size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
        }
    }
}

impl From<&Stream> for pb_queues::Stream {
    fn from(item: &Stream) -> Self {
        let reject_signals = item.reject_signals.iter().map(|i| i.get()).collect();
        Self {
            messages_begin: item.messages.begin().get(),
            messages: item
                .messages
                .iter()
                .map(|(_, req_or_resp)| req_or_resp.into())
                .collect(),
            signals_end: item.signals_end.get(),
            reject_signals,
        }
    }
}

impl TryFrom<pb_queues::Stream> for Stream {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::Stream) -> Result<Self, Self::Error> {
        let mut messages = StreamIndexedQueue::with_begin(item.messages_begin.into());
        for req_or_resp in item.messages {
            messages.push(req_or_resp.try_into()?);
        }
        let messages_size_bytes = Self::size_bytes(&messages);

        let reject_signals = item
            .reject_signals
            .iter()
            .map(|i| StreamIndex::new(*i))
            .collect();

        Ok(Self {
            messages,
            signals_end: item.signals_end.into(),
            reject_signals,
            messages_size_bytes,
        })
    }
}

impl Stream {
    /// Creates a new `Stream` with the given `messages` and `signals_end`.
    pub fn new(messages: StreamIndexedQueue<RequestOrResponse>, signals_end: StreamIndex) -> Self {
        let messages_size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            reject_signals: VecDeque::new(),
            messages_size_bytes,
        }
    }

    /// Creates a new `Stream` with the given `messages` and `signals_end`.
    pub fn with_signals(
        messages: StreamIndexedQueue<RequestOrResponse>,
        signals_end: StreamIndex,
        reject_signals: VecDeque<StreamIndex>,
    ) -> Self {
        let messages_size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
        }
    }

    /// Creates a slice starting from index `from` and containing at most
    /// `count` messages from this stream.
    pub fn slice(&self, from: StreamIndex, count: Option<usize>) -> StreamSlice {
        let messages = self.messages.slice(from, count);
        StreamSlice::new(self.header(), messages)
    }

    /// Creates a header for this stream.
    pub fn header(&self) -> StreamHeader {
        StreamHeader {
            begin: self.messages.begin(),
            end: self.messages.end(),
            signals_end: self.signals_end,
            reject_signals: self.reject_signals.clone(),
        }
    }

    /// Returns a reference to the message queue.
    pub fn messages(&self) -> &StreamIndexedQueue<RequestOrResponse> {
        &self.messages
    }

    /// Returns the stream's begin index.
    pub fn messages_begin(&self) -> StreamIndex {
        self.messages.begin()
    }

    /// Returns the stream's end index.
    pub fn messages_end(&self) -> StreamIndex {
        self.messages.end()
    }

    /// Appends the given message to the tail of the stream.
    pub fn push(&mut self, message: RequestOrResponse) {
        self.messages_size_bytes += message.count_bytes();
        self.messages.push(message);
        debug_assert_eq!(Self::size_bytes(&self.messages), self.messages_size_bytes);
    }

    /// Garbage collects messages before `new_begin`, collecting and returning all
    /// messages for which a reject signal was received.
    pub fn discard_messages_before(
        &mut self,
        new_begin: StreamIndex,
        reject_signals: &VecDeque<StreamIndex>,
    ) -> Vec<RequestOrResponse> {
        assert!(
            new_begin >= self.messages.begin(),
            "Begin index ({}) has already advanced past requested begin index ({})",
            self.messages.begin(),
            new_begin
        );
        assert!(
            new_begin <= self.messages.end(),
            "Cannot advance begin index ({}) beyond end index ({})",
            new_begin,
            self.messages.end()
        );

        // Skip any reject signals before `self.messages.begin()`.
        //
        // This may happen legitimately if the remote subnet has not yet GC-ed a signal
        // because it has not yet seen our `messages.begin()` advance past it.
        let messages_begin = self.messages.begin();
        let mut reject_signals = reject_signals
            .iter()
            .skip_while(|&reject_signal| reject_signal < &messages_begin);
        let mut next_reject_signal = reject_signals.next().unwrap_or(&new_begin);

        // Garbage collect all messages up to `new_begin`.
        let mut rejected_messages = Vec::new();
        while self.messages.begin() < new_begin {
            let (index, msg) = self.messages.pop().unwrap();

            // Deduct every discarded message from the stream's byte size.
            self.messages_size_bytes -= msg.count_bytes();
            debug_assert_eq!(Self::size_bytes(&self.messages), self.messages_size_bytes);

            // If we received a reject signal for this message, collect it in
            // `rejected_messages`.
            if next_reject_signal == &index {
                rejected_messages.push(msg);
                next_reject_signal = reject_signals.next().unwrap_or(&new_begin);
            }
        }
        rejected_messages
    }

    /// Garbage collects signals before `new_signals_begin`.
    pub fn discard_signals_before(&mut self, new_signals_begin: StreamIndex) {
        while let Some(signal_index) = self.reject_signals.front() {
            if *signal_index < new_signals_begin {
                self.reject_signals.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns a reference to the reject signals.
    pub fn reject_signals(&self) -> &VecDeque<StreamIndex> {
        &self.reject_signals
    }

    /// Returns the index just beyond the last sent signal.
    pub fn signals_end(&self) -> StreamIndex {
        self.signals_end
    }

    /// Increments the index of the last sent signal.
    pub fn increment_signals_end(&mut self) {
        self.signals_end.inc_assign()
    }

    /// Appends the given reject signal to the tail of the reject signals.
    pub fn push_reject_signal(&mut self, index: StreamIndex) {
        assert_eq!(index, self.signals_end);
        if let Some(&last_signal) = self.reject_signals.back() {
            assert!(
                last_signal < index,
                "The signal to be pushed ({}) should be larger than the last signal ({})",
                index,
                last_signal
            );
        }
        self.reject_signals.push_back(index)
    }

    /// Calculates the estimated byte size of the given messages.
    fn size_bytes(messages: &StreamIndexedQueue<RequestOrResponse>) -> usize {
        messages.iter().map(|(_, m)| m.count_bytes()).sum()
    }
}

impl CountBytes for Stream {
    fn count_bytes(&self) -> usize {
        // Count one byte per reject signal, same as the payload builder.
        size_of::<Stream>() + self.messages_size_bytes + self.reject_signals.len()
    }
}

impl From<Stream> for StreamSlice {
    fn from(val: Stream) -> Self {
        StreamSlice::new(
            StreamHeader {
                begin: val.messages.begin(),
                end: val.messages.end(),
                signals_end: val.signals_end,
                reject_signals: val.reject_signals,
            },
            val.messages,
        )
    }
}

/// Wrapper around a private `StreamMap` plus stats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Streams {
    /// Map of streams by destination `SubnetId`.
    streams: StreamMap,

    /// Map of response sizes in bytes by respondent `CanisterId`.
    responses_size_bytes: BTreeMap<CanisterId, usize>,
}

impl Streams {
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns a reference to the wrapped `StreamMap`.
    pub fn streams(&self) -> &StreamMap {
        &self.streams
    }

    /// Returns a reference to the stream for the given destination subnet.
    pub fn get(&self, destination: &SubnetId) -> Option<&Stream> {
        self.streams.get(destination)
    }

    /// Returns an iterator over all `(&SubnetId, &Stream)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&SubnetId, &Stream)> {
        self.streams.iter()
    }

    /// Returns an iterator over all `&SubnetId` keys.
    pub fn keys(&self) -> impl Iterator<Item = &SubnetId> {
        self.streams.keys()
    }

    /// Pushes the given message onto the stream for the given destination
    /// subnet.
    pub fn push(&mut self, destination: SubnetId, msg: RequestOrResponse) {
        if let RequestOrResponse::Response(response) = &msg {
            *self
                .responses_size_bytes
                .entry(response.respondent)
                .or_default() += msg.count_bytes();
        }
        self.streams.entry(destination).or_default().push(msg);
        debug_assert_eq!(
            Streams::calculate_stats(&self.streams),
            self.responses_size_bytes
        );
    }

    /// Returns a mutable reference to the stream for the given destination
    /// subnet.
    pub fn get_mut(&mut self, destination: &SubnetId) -> Option<StreamHandle> {
        // Can't (easily) validate stats when `StreamHandle` gets dropped, but we should
        // at least do it before.
        debug_assert_eq!(
            Streams::calculate_stats(&self.streams),
            self.responses_size_bytes
        );

        match self.streams.get_mut(destination) {
            Some(stream) => Some(StreamHandle::new(stream, &mut self.responses_size_bytes)),
            None => None,
        }
    }

    /// Returns a mutable reference to the stream for the given destination
    /// subnet, inserting it if it doesn't already exist.
    pub fn get_mut_or_insert(&mut self, destination: SubnetId) -> StreamHandle {
        // Can't (easily) validate stats when `StreamHandle` gets dropped, but we should
        // at least do it before.
        debug_assert_eq!(
            Streams::calculate_stats(&self.streams),
            self.responses_size_bytes
        );

        StreamHandle::new(
            self.streams.entry(destination).or_default(),
            &mut self.responses_size_bytes,
        )
    }

    /// Returns the response sizes by responder canister stat.
    pub fn responses_size_bytes(&self) -> &BTreeMap<CanisterId, usize> {
        &self.responses_size_bytes
    }

    /// Computes the `responses_size_bytes` map from scratch. Used when
    /// deserializing and in asserts.
    ///
    /// Time complexity: O(num_messages).
    pub fn calculate_stats(streams: &StreamMap) -> BTreeMap<CanisterId, usize> {
        let mut responses_size_bytes: BTreeMap<CanisterId, usize> = BTreeMap::new();
        for (_, stream) in streams.iter() {
            for (_, msg) in stream.messages().iter() {
                if let RequestOrResponse::Response(response) = msg {
                    *responses_size_bytes.entry(response.respondent).or_default() +=
                        msg.count_bytes();
                }
            }
        }
        responses_size_bytes
    }
}

/// A mutable reference to a stream owned by a `Streams` struct; bundled with
/// the `Streams`' stats, to be updated on stream mutations.
pub struct StreamHandle<'a> {
    stream: &'a mut Stream,

    #[allow(unused)]
    responses_size_bytes: &'a mut BTreeMap<CanisterId, usize>,
}

impl<'a> StreamHandle<'a> {
    pub fn new(
        stream: &'a mut Stream,
        responses_size_bytes: &'a mut BTreeMap<CanisterId, usize>,
    ) -> Self {
        Self {
            stream,
            responses_size_bytes,
        }
    }

    /// Returns a reference to the message queue.
    pub fn messages(&self) -> &StreamIndexedQueue<RequestOrResponse> {
        self.stream.messages()
    }

    /// Returns the stream's begin index.
    pub fn messages_begin(&self) -> StreamIndex {
        self.stream.messages_begin()
    }

    /// Returns the stream's end index.
    pub fn messages_end(&self) -> StreamIndex {
        self.stream.messages_end()
    }

    /// Returns a reference to the reject signals.
    pub fn reject_signals(&self) -> &VecDeque<StreamIndex> {
        self.stream.reject_signals()
    }

    /// Returns the index just beyond the last sent signal.
    pub fn signals_end(&self) -> StreamIndex {
        self.stream.signals_end
    }

    /// Appends the given message to the tail of the stream.
    pub fn push(&mut self, message: RequestOrResponse) {
        if let RequestOrResponse::Response(response) = &message {
            *self
                .responses_size_bytes
                .entry(response.respondent)
                .or_default() += message.count_bytes();
        }
        self.stream.push(message);
    }

    /// Increments the index of the last sent signal.
    pub fn increment_signals_end(&mut self) {
        self.stream.increment_signals_end();
    }

    /// Appends the given reject signal to the tail of the reject signals.
    pub fn push_reject_signal(&mut self, index: StreamIndex) {
        self.stream.push_reject_signal(index)
    }

    /// Garbage collects messages before `new_begin`, collecting and returning all
    /// messages for which a reject signal was received.
    pub fn discard_messages_before(
        &mut self,
        new_begin: StreamIndex,
        reject_signals: &VecDeque<StreamIndex>,
    ) -> Vec<RequestOrResponse> {
        // Update stats for each discarded message.
        for (index, msg) in self.stream.messages().iter() {
            if index >= new_begin {
                break;
            }
            if let RequestOrResponse::Response(response) = &msg {
                let canister_responses_size_bytes = self
                    .responses_size_bytes
                    .get_mut(&response.respondent)
                    .expect("No `responses_size_bytes` entry for discarded response");
                *canister_responses_size_bytes -= msg.count_bytes();
                // Drop zero counts.
                if *canister_responses_size_bytes == 0 {
                    self.responses_size_bytes.remove(&response.respondent);
                }
            }
        }

        self.stream
            .discard_messages_before(new_begin, reject_signals)
    }

    /// Garbage collects signals before `new_signals_begin`.
    pub fn discard_signals_before(&mut self, new_signals_begin: StreamIndex) {
        self.stream.discard_signals_before(new_signals_begin);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// State associated with the history of statuses of ingress messages as they
/// traversed through the system.
pub struct IngressHistoryState {
    statuses: Arc<BTreeMap<MessageId, Arc<IngressStatus>>>,
    /// Ingress messages in terminal states (`Completed`, `Failed` or `Done`)
    /// grouped by their respective expiration times.
    pruning_times: Arc<BTreeMap<Time, BTreeSet<MessageId>>>,
    /// The earliest time in `pruning_times` with associated message IDs that
    /// may still be of type completed or failed.
    next_terminal_time: Time,
    /// Transient: memory usage of the ingress history.
    memory_usage: usize,
}

impl Default for IngressHistoryState {
    fn default() -> Self {
        Self {
            statuses: Arc::new(BTreeMap::new()),
            pruning_times: Arc::new(BTreeMap::new()),
            next_terminal_time: UNIX_EPOCH,
            memory_usage: 0,
        }
    }
}

impl From<&IngressHistoryState> for pb_ingress::IngressHistoryState {
    fn from(item: &IngressHistoryState) -> Self {
        let statuses = item
            .statuses()
            .map(|(message_id, status)| pb_ingress::IngressStatusEntry {
                message_id: message_id.as_bytes().to_vec(),
                status: Some(status.into()),
            })
            .collect();
        let pruning_times = item
            .pruning_times()
            .map(|(time, messages)| pb_ingress::PruningEntry {
                time_nanos: time.as_nanos_since_unix_epoch(),
                messages: messages.iter().map(|m| m.as_bytes().to_vec()).collect(),
            })
            .collect();

        debug_assert_eq!(
            IngressHistoryState::compute_memory_usage(&item.statuses),
            item.memory_usage
        );

        pb_ingress::IngressHistoryState {
            statuses,
            pruning_times,
            next_terminal_time: item.next_terminal_time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_ingress::IngressHistoryState> for IngressHistoryState {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::IngressHistoryState) -> Result<Self, Self::Error> {
        let mut statuses = BTreeMap::<MessageId, Arc<IngressStatus>>::new();
        let mut pruning_times = BTreeMap::<Time, BTreeSet<MessageId>>::new();

        for entry in item.statuses {
            let msg_id = entry.message_id.as_slice().try_into()?;
            let ingres_status = try_from_option_field(entry.status, "IngressStatusEntry::status")?;

            statuses.insert(msg_id, Arc::new(ingres_status));
        }

        for entry in item.pruning_times {
            let time = Time::from_nanos_since_unix_epoch(entry.time_nanos);
            let messages = entry
                .messages
                .iter()
                .map(|message_id| message_id.as_slice().try_into())
                .collect::<Result<BTreeSet<_>, _>>()?;

            pruning_times.insert(time, messages);
        }

        let memory_usage = IngressHistoryState::compute_memory_usage(&statuses);

        Ok(IngressHistoryState {
            statuses: Arc::new(statuses),
            pruning_times: Arc::new(pruning_times),
            next_terminal_time: Time::from_nanos_since_unix_epoch(item.next_terminal_time),
            memory_usage,
        })
    }
}

impl IngressHistoryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new entry in the ingress history. If an entry with `message_id` is
    /// already present this entry will be overwritten. If `status` is a terminal
    /// status (`completed`, `failed`, or `done`) the entry will also be enrolled
    /// to be pruned at `time + MAX_INGRESS_TTL`.
    pub fn insert(
        &mut self,
        message_id: MessageId,
        status: IngressStatus,
        time: Time,
        ingress_memory_capacity: NumBytes,
    ) {
        // Store the associated expiry time for the given message id only for a
        // "terminal" ingress status. This way we are not risking deleting any status
        // for a message that is still not in a terminal status.
        if let IngressStatus::Known { state, .. } = &status {
            if state.is_terminal() {
                let timeout = time + MAX_INGRESS_TTL;

                // Reset `self.next_terminal_time` in case it is after the current timout
                // and the entry is completed or failed.
                if self.next_terminal_time > timeout && state.is_terminal_with_payload() {
                    self.next_terminal_time = timeout;
                }
                Arc::make_mut(&mut self.pruning_times)
                    .entry(timeout)
                    .or_default()
                    .insert(message_id.clone());
            }
        }
        self.memory_usage += status.payload_bytes();
        if let Some(old) = Arc::make_mut(&mut self.statuses).insert(message_id, Arc::new(status)) {
            self.memory_usage -= old.payload_bytes();
        }

        if self.memory_usage > ingress_memory_capacity.get() as usize {
            self.forget_terminal_statuses(ingress_memory_capacity);
        }

        debug_assert_eq!(
            Self::compute_memory_usage(&self.statuses),
            self.memory_usage
        );
    }

    /// Returns an iterator over response statuses, sorted lexicographically by
    /// message id.
    pub fn statuses(&self) -> impl Iterator<Item = (&MessageId, &IngressStatus)> {
        self.statuses
            .iter()
            .map(|(id, status)| (id, status.as_ref()))
    }

    /// Returns an iterator over pruning times statuses, sorted
    /// lexicographically by time.
    pub fn pruning_times(&self) -> impl Iterator<Item = (&Time, &BTreeSet<MessageId>)> {
        self.pruning_times.iter()
    }

    /// Retrieves an entry from the ingress history given a `MessageId`.
    pub fn get(&self, message_id: &MessageId) -> Option<&IngressStatus> {
        self.statuses.get(message_id).map(|status| status.as_ref())
    }

    /// Returns the number of statuses kept in the ingress history.
    pub fn len(&self) -> usize {
        self.statuses.len()
    }

    /// Returns true if the ingress history is empty.
    pub fn is_empty(&self) -> bool {
        self.statuses.is_empty()
    }

    /// Removes ingress history entries that are associated with a pruning_time
    /// that's older than the given time.
    pub fn prune(&mut self, time: Time) {
        let new_pruning_times = Arc::make_mut(&mut self.pruning_times).split_off(&time);

        let statuses = Arc::make_mut(&mut self.statuses);
        for pruning_times in self.pruning_times.as_ref().values() {
            for message_id in pruning_times {
                if let Some(removed) = statuses.remove(message_id) {
                    self.memory_usage -= removed.payload_bytes();
                }
            }
        }
        self.pruning_times = Arc::new(new_pruning_times);

        debug_assert_eq!(
            Self::compute_memory_usage(&self.statuses),
            self.memory_usage
        );
    }

    /// Goes over the `pruning_times` from oldest to newest and transitions
    /// the referenced `Completed` and/or `Failed` statuses to `Done` (i.e.,
    /// forgets the replies). It will stop at the pruning time where the memory
    /// usage is below `target_size` for the first time. To handle repeated calls
    /// efficiently it remembers the pruning time it stopped at.
    ///
    /// Note that this function must remain private and should only be
    /// called from within `insert` to ensure that `next_terminal_time`
    /// is consistently updated and we don't miss any completed statuses.
    fn forget_terminal_statuses(&mut self, target_size: NumBytes) {
        // Before certification version 8 no done statuses are produced
        if CURRENT_CERTIFICATION_VERSION < CertificationVersion::V8 {
            return;
        }

        // In debug builds we store the length of the statuses map here so that
        // we can later debug_assert that no status disappeared.
        #[cfg(debug_assertions)]
        let statuses_len_before = self.statuses.len();

        let target_size = target_size.get() as usize;
        let statuses = Arc::make_mut(&mut self.statuses);

        for (time, ids) in self
            .pruning_times
            .range((Included(self.next_terminal_time), Unbounded))
        {
            self.next_terminal_time = *time;

            if self.memory_usage <= target_size {
                break;
            }

            for id in ids.iter() {
                match statuses.get(id).map(Arc::as_ref) {
                    Some(IngressStatus::Known {
                        receiver,
                        user_id,
                        time,
                        state,
                    }) if state.is_terminal_with_payload() => {
                        let done_status = Arc::new(IngressStatus::Known {
                            receiver: *receiver,
                            user_id: *user_id,
                            time: *time,
                            state: IngressState::Done,
                        });
                        self.memory_usage += done_status.payload_bytes();

                        // We can safely unwrap here because we know there must be an
                        // ingress status with the given `id` in `statuses` in this
                        // branch.
                        let old_status = statuses.insert(id.clone(), done_status).unwrap();
                        self.memory_usage -= old_status.payload_bytes();
                    }
                    _ => continue,
                }
            }
        }

        #[cfg(debug_assertions)]
        debug_assert_eq!(self.statuses.len(), statuses_len_before);
        debug_assert_eq!(
            Self::compute_memory_usage(&self.statuses),
            self.memory_usage
        );
    }

    /// Returns the memory usage of the statuses in the ingress history. See the
    /// documentation of `IngressStatus` for how the byte size of an individual
    /// `IngressStatus` is computed.
    pub fn memory_usage(&self) -> NumBytes {
        NumBytes::new(self.memory_usage as u64)
    }

    fn compute_memory_usage(statuses: &BTreeMap<MessageId, Arc<IngressStatus>>) -> usize {
        statuses.values().map(|status| status.payload_bytes()).sum()
    }

    /// Prunes the ingress history (as part of subnet splitting phase 2), retaining:
    ///
    ///  * all terminal states (since they are immutable and will get pruned); and
    ///  * all non-terminal states for ingress messages addressed to local receivers
    ///    (canisters or subnet; as determined by the provided predicate).
    fn prune_after_split<F>(self, is_local_receiver: F) -> Self
    where
        F: Fn(&CanisterId) -> bool,
    {
        // Take apart `self` and put it back together, in order for the compiler to
        // enforce an explicit decision whenever any structural changes are made.
        let Self {
            mut statuses,
            pruning_times,
            next_terminal_time,
            memory_usage: _,
        } = self;

        // Filters for messages in terminal states or addressed to local canisters.
        let should_retain = |status: &IngressStatus| match status {
            IngressStatus::Known {
                receiver, state, ..
            } => state.is_terminal() || is_local_receiver(&CanisterId::new(*receiver).unwrap()),
            IngressStatus::Unknown => false,
        };

        // Filter `statuses`. `pruning_times` stay the same on both subnets because we
        // preserved all messages in terminal states, regardless of canister.
        let mut_statuses = Arc::make_mut(&mut statuses);
        let message_ids_to_retain: BTreeSet<_> = mut_statuses
            .iter()
            .filter(|(_, status)| should_retain(status.as_ref()))
            .map(|(message_id, _)| message_id.clone())
            .collect();
        mut_statuses.retain(|message_id, _| message_ids_to_retain.contains(message_id));
        let memory_usage = Self::compute_memory_usage(mut_statuses);

        Self {
            statuses,
            pruning_times,
            next_terminal_time,
            memory_usage,
        }
    }
}

pub(crate) mod testing {
    use super::{StreamMap, Streams};

    /// Testing only: Exposes `Streams` internals for use in other modules'
    /// tests.
    pub trait StreamsTesting {
        /// Testing only: Modifies `SystemMetadata::streams` by applying the
        /// provided function.
        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F);
    }

    impl StreamsTesting for Streams {
        fn modify_streams<F: FnOnce(&mut StreamMap)>(&mut self, f: F) {
            f(&mut self.streams);

            // Recompute stats from scratch.
            self.responses_size_bytes = Streams::calculate_stats(&self.streams);
        }
    }
}
