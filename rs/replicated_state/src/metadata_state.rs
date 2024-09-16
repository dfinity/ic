pub mod subnet_call_context_manager;
#[cfg(test)]
mod tests;

use crate::metadata_state::subnet_call_context_manager::SubnetCallContextManager;
use crate::CanisterQueues;
use crate::{canister_state::system_state::CyclesUseCase, CheckpointLoadingMetrics};
use ic_base_types::CanisterId;
use ic_btc_replica_types::BlockBlob;
use ic_certification_version::{CertificationVersion, CURRENT_CERTIFICATION_VERSION};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_limits::MAX_INGRESS_TTL;
use ic_management_canister_types::{MasterPublicKeyId, NodeMetrics, NodeMetricsHistoryResponse};
use ic_protobuf::state::system_metadata::v1::ThresholdSignatureAgreementsEntry;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::subnet::v1 as pb_subnet,
    state::{
        canister_state_bits::v1::{ConsumedCyclesByUseCase, CyclesUseCase as pbCyclesUseCase},
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
    batch::BlockmakerMetrics,
    crypto::CryptoHash,
    ingress::{IngressState, IngressStatus},
    messages::{
        is_subnet_id, CanisterCall, MessageId, Payload, RejectContext, RequestOrResponse, Response,
        NO_DEADLINE,
    },
    node_id_into_protobuf, node_id_try_from_option,
    nominal_cycles::NominalCycles,
    state_sync::{StateSyncVersion, CURRENT_STATE_SYNC_VERSION},
    subnet_id_into_protobuf, subnet_id_try_from_protobuf,
    time::{Time, UNIX_EPOCH},
    xnet::{
        RejectReason, RejectSignal, StreamFlags, StreamHeader, StreamIndex, StreamIndexedQueue,
        StreamSlice,
    },
    CountBytes, CryptoHashOfPartialState, NodeId, NumBytes, PrincipalId, SubnetId,
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
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
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
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

    pub api_boundary_nodes: BTreeMap<NodeId, ApiBoundaryNodeEntry>,

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

    /// The set of Wasm modules we expect to be present in the [`Hypervisor`]'s
    /// compilation cache. This allows us to deterministically decide when we
    /// expect a compilation to be fast and ignore the compilation cost when
    /// considering the round instruction limit.
    ///
    /// Each time a canister is installed, its Wasm is inserted and the set is
    /// cleared at each checkpoint.
    pub expected_compiled_wasms: BTreeSet<WasmHash>,

    /// Responses to `BitcoinGetSuccessors` can be larger than the max inter-canister
    /// response limit. To work around this limitation, large responses are paginated
    /// and are stored here temporarily until they're fetched by the calling canister.
    #[validate_eq(Ignore)]
    pub bitcoin_get_successors_follow_up_responses: BTreeMap<CanisterId, Vec<BlockBlob>>,

    /// Metrics collecting blockmaker stats (block proposed and failures to propose a block)
    /// by aggregating them and storing a running total over multiple days by node id and
    /// timestamp. Observations of blockmaker stats are performed each time a batch is processed.
    pub blockmaker_metrics_time_series: BlockmakerMetricsTimeSeries,
}

/// Full description of the IC network toplogy.
///
/// Contains [`Arc`] references, so it is only safe to serialize for read-only
/// use.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct NetworkTopology {
    pub subnets: BTreeMap<SubnetId, SubnetTopology>,
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub routing_table: Arc<RoutingTable>,
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub canister_migrations: Arc<CanisterMigrations>,
    pub nns_subnet_id: SubnetId,

    /// Mapping from iDKG key_id to a list of subnets which can sign with the
    /// given key. Keys without any signing subnets are not included in the map.
    pub idkg_signing_subnets: BTreeMap<MasterPublicKeyId, Vec<SubnetId>>,

    /// The ID of the canister to forward bitcoin testnet requests to.
    pub bitcoin_testnet_canister_id: Option<CanisterId>,

    /// The ID of the canister to forward bitcoin mainnet requests to.
    pub bitcoin_mainnet_canister_id: Option<CanisterId>,
}

/// Full description of the API Boundary Node, which is saved in the metadata.
/// This entry is formed from two registry records - ApiBoundaryNodeRecord and NodeRecord.
/// If an ApiBoundaryNodeRecord exists, then a corresponding NodeRecord must exist.
/// The converse statement is not true.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ApiBoundaryNodeEntry {
    /// Domain name, required field from NodeRecord
    pub domain: String,
    /// Ipv4, optional field from NodeRecord
    pub ipv4_address: Option<String>,
    /// Ipv6, required field from NodeRecord
    pub ipv6_address: String,
    pub pubkey: Option<Vec<u8>>,
}

impl Default for NetworkTopology {
    fn default() -> Self {
        Self {
            subnets: Default::default(),
            routing_table: Default::default(),
            canister_migrations: Default::default(),
            nns_subnet_id: SubnetId::new(PrincipalId::new_anonymous()),
            idkg_signing_subnets: Default::default(),
            bitcoin_testnet_canister_id: None,
            bitcoin_mainnet_canister_id: None,
        }
    }
}

impl NetworkTopology {
    /// Returns a list of subnets where the iDKG feature is enabled.
    pub fn idkg_signing_subnets(&self, key_id: &MasterPublicKeyId) -> &[SubnetId] {
        self.idkg_signing_subnets
            .get(key_id)
            .map_or(&[], |ids| &ids[..])
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
            bitcoin_testnet_canister_ids: match item.bitcoin_testnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
            bitcoin_mainnet_canister_ids: match item.bitcoin_mainnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
            idkg_signing_subnets: item
                .idkg_signing_subnets
                .iter()
                .map(|(key_id, subnet_ids)| {
                    let subnet_ids = subnet_ids
                        .iter()
                        .map(|id| subnet_id_into_protobuf(*id))
                        .collect();
                    pb_metadata::IDkgKeyEntry {
                        key_id: Some(key_id.into()),
                        subnet_ids,
                    }
                })
                .collect(),
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

        let nns_subnet_id = subnet_id_try_from_protobuf(try_from_option_field(
            item.nns_subnet_id,
            "NetworkTopology::nns_subnet_id",
        )?)?;

        let mut idkg_signing_subnets = BTreeMap::new();
        for entry in item.idkg_signing_subnets {
            let mut subnet_ids = vec![];
            for subnet_id in entry.subnet_ids {
                subnet_ids.push(subnet_id_try_from_protobuf(subnet_id)?);
            }
            idkg_signing_subnets.insert(
                try_from_option_field(entry.key_id, "IDkgKeyEntry::key_id")?,
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
            idkg_signing_subnets,
            bitcoin_testnet_canister_id,
            bitcoin_mainnet_canister_id,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct SubnetTopology {
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// https://internetcomputer.org/docs/current/references/ic-interface-spec#certification)
    pub public_key: Vec<u8>,
    pub nodes: BTreeSet<NodeId>,
    pub subnet_type: SubnetType,
    pub subnet_features: SubnetFeatures,
    /// iDKG keys held by this subnet. Just because a subnet holds an iDKG key
    /// doesn't mean the subnet has been enabled to sign with that key. This
    /// will happen when a key is shared with a second subnet which holds it as
    /// a backup. An additional NNS proposal will be needed to allow the subnet
    /// holding the key as backup to actually produce signatures.
    pub idkg_keys_held: BTreeSet<MasterPublicKeyId>,
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
            idkg_keys_held: item.idkg_keys_held.iter().map(|k| k.into()).collect(),
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

        let mut idkg_keys_held = BTreeSet::new();
        for key in item.idkg_keys_held {
            idkg_keys_held.insert(MasterPublicKeyId::try_from(key)?);
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
            idkg_keys_held,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct SubnetMetrics {
    pub consumed_cycles_by_deleted_canisters: NominalCycles,
    pub consumed_cycles_http_outcalls: NominalCycles,
    pub consumed_cycles_ecdsa_outcalls: NominalCycles,
    consumed_cycles_by_use_case: BTreeMap<CyclesUseCase, NominalCycles>,
    pub threshold_signature_agreements: BTreeMap<MasterPublicKeyId, u64>,
    /// The number of canisters that exist on this subnet.
    pub num_canisters: u64,
    /// The total size of the state taken by canisters on this subnet in bytes.
    pub canister_state_bytes: NumBytes,
    /// The total number of transactions processed on this subnet.
    ///
    /// Transactions here refer to all messages processed in replicated mode.
    pub update_transactions_total: u64,
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

    pub fn consumed_cycles_total(&self) -> NominalCycles {
        let mut total = NominalCycles::from(0);

        total += self.consumed_cycles_by_deleted_canisters;
        total += self.consumed_cycles_http_outcalls;
        total += self.consumed_cycles_ecdsa_outcalls;

        for (use_case, cycles) in self.consumed_cycles_by_use_case.iter() {
            match use_case {
                // For ecdsa outcalls, http outcalls and deleted canisters, skip
                // updating the total using the use case specific metric as the
                // update above should be sufficient (the old metric is a superset).
                CyclesUseCase::ECDSAOutcalls
                | CyclesUseCase::HTTPOutcalls
                | CyclesUseCase::DeletedCanisters => {}
                // Non consumed cycles should not be counted towards the total consumed.
                CyclesUseCase::NonConsumed => {}
                // For the remaining use cases simply add the values to the total.
                CyclesUseCase::Memory
                | CyclesUseCase::ComputeAllocation
                | CyclesUseCase::IngressInduction
                | CyclesUseCase::Instructions
                | CyclesUseCase::RequestAndResponseTransmission
                | CyclesUseCase::Uninstall
                | CyclesUseCase::CanisterCreation
                | CyclesUseCase::SchnorrOutcalls
                | CyclesUseCase::BurnedCycles => total += *cycles,
            }
        }

        total
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
            threshold_signature_agreements: item
                .threshold_signature_agreements
                .iter()
                .map(|(key_id, &count)| ThresholdSignatureAgreementsEntry {
                    key_id: Some(key_id.into()),
                    count,
                })
                .collect(),
            consumed_cycles_by_use_case: item
                .consumed_cycles_by_use_case
                .clone()
                .into_iter()
                .map(|(use_case, cycles)| ConsumedCyclesByUseCase {
                    use_case: pbCyclesUseCase::from(use_case).into(),
                    cycles: Some((&cycles).into()),
                })
                .collect(),
            num_canisters: Some(item.num_canisters),
            canister_state_bytes: Some(item.canister_state_bytes.get()),
            update_transactions_total: Some(item.update_transactions_total),
        }
    }
}

impl TryFrom<pb_metadata::SubnetMetrics> for SubnetMetrics {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetMetrics) -> Result<Self, Self::Error> {
        let mut consumed_cycles_by_use_case = BTreeMap::new();
        for x in item.consumed_cycles_by_use_case.into_iter() {
            consumed_cycles_by_use_case.insert(
                CyclesUseCase::try_from(pbCyclesUseCase::try_from(x.use_case).map_err(|_| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "CyclesUseCase",
                        err: format!("Unexpected value of cycles use case: {}", x.use_case),
                    }
                })?)?,
                NominalCycles::try_from(x.cycles.unwrap_or_default()).unwrap_or_default(),
            );
        }
        let mut threshold_signature_agreements = BTreeMap::new();
        for x in item.threshold_signature_agreements.into_iter() {
            threshold_signature_agreements.insert(
                try_from_option_field(
                    x.key_id,
                    "SubnetMetrics::threshold_signature_agreements:key_id",
                )?,
                x.count,
            );
        }
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
            threshold_signature_agreements,
            consumed_cycles_by_use_case,
            num_canisters: try_from_option_field(
                item.num_canisters,
                "SubnetMetrics::num_canisters",
            )?,
            canister_state_bytes: try_from_option_field(
                item.canister_state_bytes,
                "SubnetMetrics::canister_state_bytes",
            )?,
            update_transactions_total: try_from_option_field(
                item.update_transactions_total,
                "SubnetMetrics::update_transactions_total",
            )?,
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
            api_boundary_nodes: item
                .api_boundary_nodes
                .iter()
                .map(
                    |(node_id, api_boundary_node_entry)| pb_metadata::ApiBoundaryNodeEntry {
                        node_id: Some(node_id_into_protobuf(*node_id)),
                        domain: api_boundary_node_entry.domain.clone(),
                        ipv4_address: api_boundary_node_entry.ipv4_address.clone(),
                        ipv6_address: api_boundary_node_entry.ipv6_address.clone(),
                        pubkey: api_boundary_node_entry.pubkey.clone(),
                    },
                )
                .collect(),
            blockmaker_metrics_time_series: Some((&item.blockmaker_metrics_time_series).into()),
        }
    }
}

/// Decodes a `SystemMetadata` proto. The metrics are provided as a side-channel
/// for recording errors without being forced to return `Err(_)`.
impl TryFrom<(pb_metadata::SystemMetadata, &dyn CheckpointLoadingMetrics)> for SystemMetadata {
    type Error = ProxyDecodeError;

    fn try_from(
        (item, metrics): (pb_metadata::SystemMetadata, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
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

        let mut api_boundary_nodes = BTreeMap::<NodeId, ApiBoundaryNodeEntry>::new();
        for entry in item.api_boundary_nodes {
            api_boundary_nodes.insert(
                node_id_try_from_option(entry.node_id)?,
                ApiBoundaryNodeEntry {
                    domain: entry.domain,
                    ipv4_address: entry.ipv4_address,
                    ipv6_address: entry.ipv6_address,
                    pubkey: entry.pubkey,
                },
            );
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
            api_boundary_nodes,
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
                guaranteed_responses_size_bytes: Streams::calculate_stats(&streams),
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
            blockmaker_metrics_time_series: match item.blockmaker_metrics_time_series {
                Some(blockmaker_metrics) => (blockmaker_metrics, metrics).try_into()?,
                None => BlockmakerMetricsTimeSeries::default(),
            },
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
            api_boundary_nodes: Default::default(),
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
            certification_version: CURRENT_CERTIFICATION_VERSION,
            heap_delta_estimate: NumBytes::from(0),
            subnet_metrics: Default::default(),
            expected_compiled_wasms: BTreeSet::new(),
            bitcoin_get_successors_follow_up_responses: BTreeMap::default(),
            blockmaker_metrics_time_series: BlockmakerMetricsTimeSeries::default(),
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
    /// in terminal states and messages addressed to local canisters. Additionally,
    /// on subnet A' we reject all management canister calls whose execution is in
    /// progress on one of the canisters migrated to subnet B (hence the
    /// `subnet_queues` argument); and silently discard the corresponding tasks and
    /// roll back `Stopping` states on all subnet B canisters.
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
    pub(crate) fn after_split<F>(
        &mut self,
        is_local_canister: F,
        subnet_queues: &mut CanisterQueues,
    ) where
        F: Fn(CanisterId) -> bool,
    {
        // Destructure `self` in order for the compiler to enforce an explicit decision
        // whenever new fields are added.
        //
        // (!) DO NOT USE THE ".." WILDCARD, THIS SERVES THE SAME FUNCTION AS a `match`!
        let SystemMetadata {
            ref mut ingress_history,
            streams: _,
            canister_allocation_ranges: _,
            last_generated_canister_id: _,
            prev_state_hash: _,
            // Overwritten as soon as the round begins, no explicit action needed.
            batch_time: _,
            // Overwritten as soon as the round begins, no explicit action needed.
            network_topology: _,
            ref own_subnet_id,
            // `own_subnet_type` has been set by `load_checkpoint()` based on the subnet
            // registry record of B, do not touch it.
            own_subnet_type: _,
            // Overwritten as soon as the round begins, no explicit action needed.
            own_subnet_features: _,
            // Overwritten as soon as the round begins, no explicit action needed.
            node_public_keys: _,
            api_boundary_nodes: _,
            ref mut split_from,
            subnet_call_context_manager: _,
            // Set by `commit_and_certify()` at the end of the round. Not used before.
            state_sync_version: _,
            // Set by `commit_and_certify()` at the end of the round. Not used before.
            certification_version: _,
            ref heap_delta_estimate,
            subnet_metrics: _,
            ref expected_compiled_wasms,
            bitcoin_get_successors_follow_up_responses: _,
            blockmaker_metrics_time_series: _,
        } = self;

        let split_from_subnet = split_from.expect("Not a state resulting from a subnet split");

        assert_eq!(0, heap_delta_estimate.get());
        assert!(expected_compiled_wasms.is_empty());

        // Prune the ingress history.
        ingress_history.prune_after_split(|canister_id: CanisterId| {
            // An actual local canister.
            is_local_canister(canister_id)
                // Or this is subnet A' and message is addressed to the management canister.
                || split_from_subnet == *own_subnet_id && is_subnet_id(canister_id, *own_subnet_id)
        });

        // Split complete, reset split marker.
        *split_from = None;

        // Reject in-progress subnet messages that cannot be handled on this
        // subnet.
        self.reject_in_progress_management_calls_after_split(&is_local_canister, subnet_queues);
    }

    /// Creates rejects for all in-progress management messages that cannot or should
    /// not be handled on this subnet in the second phase of a subnet split.
    /// Enqueues reject responses into the provided `subnet_queues` for calls originating
    /// from canisters; and records a `Failed` state in `self.ingress_history` for calls
    /// originating from ingress messages. The rejects are created for:
    ///     - All in-progress subnet messages whose target canisters are no longer
    ///     on this subnet.
    ///       On the other subnet (which must be *subnet B*), the execution of these same
    ///     messages, now without matching subnet call contexts, will be silently
    ///     aborted / rolled back (without producing a response). This is the only way
    ///     to ensure consistency for a message that would otherwise be executing on one
    ///     subnet, but for which a response may only be produced by another subnet.
    ///     - Specific requests that must be entirely handled by the local subnet where
    ///    the originator canister exists.
    fn reject_in_progress_management_calls_after_split<F>(
        &mut self,
        is_local_canister: F,
        subnet_queues: &mut CanisterQueues,
    ) where
        F: Fn(CanisterId) -> bool,
    {
        for install_code_call in self
            .subnet_call_context_manager
            .remove_non_local_install_code_calls(&is_local_canister)
        {
            self.reject_management_call_after_split(
                install_code_call.call,
                install_code_call.effective_canister_id,
                subnet_queues,
            );
        }

        for stop_canister_call in self
            .subnet_call_context_manager
            .remove_non_local_stop_canister_calls(&is_local_canister)
        {
            self.reject_management_call_after_split(
                stop_canister_call.call,
                stop_canister_call.effective_canister_id,
                subnet_queues,
            );
        }

        // Management `RawRand` requests are rejected if the sender has migrated to another subnet.
        for raw_rand_context in self
            .subnet_call_context_manager
            .remove_non_local_raw_rand_calls(&is_local_canister)
        {
            let migrated_canister_id = raw_rand_context.request.sender();
            self.reject_management_call_after_split(
                CanisterCall::Request(Arc::new(raw_rand_context.request)),
                migrated_canister_id,
                subnet_queues,
            );
        }
    }

    /// Rejects the given subnet call targeting `canister_id`, which has migrated to
    /// a new subnet following a subnet split.
    ///
    /// * If the call originated from a canister, enqueues an output reject response
    ///   on behalf of the subnet into the provided `subnet_queues`.
    /// * If the call originated from an ingress message, sets its ingress state in
    ///   `self.ingress_history` to `Failed`.
    fn reject_management_call_after_split(
        &mut self,
        call: CanisterCall,
        canister_id: CanisterId,
        subnet_queues: &mut CanisterQueues,
    ) {
        match call {
            CanisterCall::Request(request) => {
                // Rejecting a request from a canister.
                let response = Response {
                    originator: request.sender(),
                    respondent: request.receiver,
                    originator_reply_callback: request.sender_reply_callback,
                    refund: request.payment,
                    response_payload: Payload::Reject(RejectContext::new(
                        RejectCode::SysTransient,
                        format!("Canister {} migrated during a subnet split", canister_id),
                    )),
                    deadline: request.deadline,
                };
                subnet_queues.push_output_response(response.into());
            }
            CanisterCall::Ingress(ingress) => {
                let status = IngressStatus::Known {
                    receiver: ingress.receiver.get(),
                    user_id: ingress.source,
                    time: self.time(),
                    state: IngressState::Failed(UserError::new(
                        ErrorCode::CanisterNotFound,
                        format!("Canister {} migrated during a subnet split", canister_id),
                    )),
                };

                if let Some(current_status) = self.ingress_history.get(&ingress.message_id) {
                    assert!(
                        current_status.is_valid_state_transition(&status),
                        "message (id='{}', current_status='{:?}') cannot be transitioned to '{:?}'",
                        ingress.message_id,
                        current_status,
                        status
                    );
                }
                self.ingress_history.insert(
                    ingress.message_id.clone(),
                    status,
                    self.time(),
                    u64::MAX.into(), // No need to enforce ingress memory limits,
                );
            }
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
/// collection of exceptions, i.e. `reject_signals`.
#[derive(Clone, Eq, PartialEq, Debug)]
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

    /// Reject signals, in ascending stream index order.
    reject_signals: VecDeque<RejectSignal>,

    /// Estimated byte size of `self.messages`.
    messages_size_bytes: usize,

    /// Stream flags observed in the header of the reverse stream.
    reverse_stream_flags: StreamFlags,
}

impl Default for Stream {
    fn default() -> Self {
        let messages = Default::default();
        let signals_end = Default::default();
        let reject_signals = VecDeque::default();
        let messages_size_bytes = Self::size_bytes(&messages);
        let reverse_stream_flags = StreamFlags {
            deprecated_responses_only: false,
        };
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags,
        }
    }
}

impl From<&Stream> for pb_queues::Stream {
    fn from(item: &Stream) -> Self {
        let reject_signals = item
            .reject_signals()
            .iter()
            .map(|signal| pb_queues::RejectSignal {
                reason: pb_queues::RejectReason::from(signal.reason).into(),
                index: signal.index.get(),
            })
            .collect();
        Self {
            messages_begin: item.messages.begin().get(),
            messages: item
                .messages
                .iter()
                .map(|(_, req_or_resp)| req_or_resp.into())
                .collect(),
            signals_end: item.signals_end.get(),
            reject_signals,
            reverse_stream_flags: Some(pb_queues::StreamFlags {
                deprecated_responses_only: item.reverse_stream_flags.deprecated_responses_only,
            }),
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

        let signals_end = item.signals_end.into();
        let reject_signals = item
            .reject_signals
            .iter()
            .map(|signal| {
                Ok(RejectSignal {
                    reason: pb_queues::RejectReason::try_from(signal.reason)
                        .map_err(ProxyDecodeError::DecodeError)?
                        .try_into()?,
                    index: signal.index.into(),
                })
            })
            .collect::<Result<VecDeque<_>, ProxyDecodeError>>()?;

        // Check reject signals are sorted and below `signals_end`.
        let iter = reject_signals.iter().map(|signal| signal.index);
        for (index, next_index) in iter
            .clone()
            .zip(iter.skip(1).chain(std::iter::once(item.signals_end.into())))
        {
            if index >= next_index {
                return Err(ProxyDecodeError::Other(format!(
                    "reject signals not strictly sorted, received [{:?}, {:?}]",
                    index, next_index,
                )));
            }
        }

        Ok(Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags: item
                .reverse_stream_flags
                .map(|flags| StreamFlags {
                    deprecated_responses_only: flags.deprecated_responses_only,
                })
                .unwrap_or_default(),
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
            reverse_stream_flags: Default::default(),
        }
    }

    /// Creates a new `Stream` with the given `messages`, `signals_end` and `reject_signals`.
    pub fn with_signals(
        messages: StreamIndexedQueue<RequestOrResponse>,
        signals_end: StreamIndex,
        reject_signals: VecDeque<RejectSignal>,
    ) -> Self {
        let messages_size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags: Default::default(),
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
        StreamHeader::new(
            self.messages.begin(),
            self.messages.end(),
            self.signals_end,
            self.reject_signals.clone(),
            StreamFlags::default(),
        )
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
        reject_signals: &VecDeque<RejectSignal>,
    ) -> Vec<(RejectReason, RequestOrResponse)> {
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
            .skip_while(|reject_signal| reject_signal.index < messages_begin)
            .peekable();

        // Garbage collect all messages up to `new_begin`.
        let mut rejected_messages = Vec::new();
        while self.messages.begin() < new_begin {
            let (index, msg) = self.messages.pop().unwrap();

            // Deduct every discarded message from the stream's byte size.
            self.messages_size_bytes -= msg.count_bytes();
            debug_assert_eq!(Self::size_bytes(&self.messages), self.messages_size_bytes);

            // If we received a reject signal for this message, collect it in
            // `rejected_messages`.
            if let Some(reject_signal) = reject_signals.peek() {
                if reject_signal.index == index {
                    rejected_messages.push((reject_signal.reason, msg));
                    reject_signals.next();
                }
            }
        }
        rejected_messages
    }

    /// Garbage collects signals before `new_signals_begin`.
    pub fn discard_signals_before(&mut self, new_signals_begin: StreamIndex) {
        while let Some(reject_signal) = self.reject_signals.front() {
            if reject_signal.index < new_signals_begin {
                self.reject_signals.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns a reference to the reject signals.
    pub fn reject_signals(&self) -> &VecDeque<RejectSignal> {
        &self.reject_signals
    }

    /// Returns the index just beyond the last sent signal.
    pub fn signals_end(&self) -> StreamIndex {
        self.signals_end
    }

    /// Pushes an accept signal. Since these are not explicitly encoded, this
    /// just increments `signals_end`.
    pub fn push_accept_signal(&mut self) {
        self.signals_end.inc_assign()
    }

    /// Appends a reject signal (the current `signals_end`) to the tail of the
    /// reject signals; and then increments `signals_end`.
    pub fn push_reject_signal(&mut self, reason: RejectReason) {
        self.reject_signals
            .push_back(RejectSignal::new(reason, self.signals_end));
        self.signals_end.inc_assign();
    }

    /// Calculates the estimated byte size of the given messages.
    fn size_bytes(messages: &StreamIndexedQueue<RequestOrResponse>) -> usize {
        messages.iter().map(|(_, m)| m.count_bytes()).sum()
    }

    /// Returns a reference to the reverse stream flags.
    pub fn reverse_stream_flags(&self) -> &StreamFlags {
        &self.reverse_stream_flags
    }

    /// Sets the reverse stream flags.
    pub fn set_reverse_stream_flags(&mut self, flags: StreamFlags) {
        self.reverse_stream_flags = flags;
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
        StreamSlice::new(val.header(), val.messages)
    }
}

/// Wrapper around a private `StreamMap` plus stats.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Streams {
    /// Map of streams by destination `SubnetId`.
    streams: StreamMap,

    /// Map of response sizes in bytes by respondent `CanisterId`.
    guaranteed_responses_size_bytes: BTreeMap<CanisterId, usize>,
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
            if response.deadline == NO_DEADLINE {
                *self
                    .guaranteed_responses_size_bytes
                    .entry(response.respondent)
                    .or_default() += msg.count_bytes();
            }
        }

        self.streams.entry(destination).or_default().push(msg);

        #[cfg(debug_assertions)]
        self.debug_validate_stats();
    }

    /// Returns a mutable reference to the stream for the given destination
    /// subnet.
    pub fn get_mut(&mut self, destination: &SubnetId) -> Option<StreamHandle> {
        // Can't (easily) validate stats when `StreamHandle` gets dropped, but we should
        // at least do it before.
        #[cfg(debug_assertions)]
        self.debug_validate_stats();

        match self.streams.get_mut(destination) {
            Some(stream) => Some(StreamHandle::new(
                stream,
                &mut self.guaranteed_responses_size_bytes,
            )),
            None => None,
        }
    }

    /// Returns a mutable reference to the stream for the given destination
    /// subnet, inserting it if it doesn't already exist.
    pub fn get_mut_or_insert(&mut self, destination: SubnetId) -> StreamHandle {
        // Can't (easily) validate stats when `StreamHandle` gets dropped, but we should
        // at least do it before.
        #[cfg(debug_assertions)]
        self.debug_validate_stats();

        StreamHandle::new(
            self.streams.entry(destination).or_default(),
            &mut self.guaranteed_responses_size_bytes,
        )
    }

    /// Returns the guaranteed response sizes by responder canister stat.
    pub fn guaranteed_responses_size_bytes(&self) -> &BTreeMap<CanisterId, usize> {
        &self.guaranteed_responses_size_bytes
    }

    /// Prunes zero-valued guaranteed response sizes entries.
    ///
    /// This is triggered explicitly by `ReplicatedState` after it has updated the
    /// canisters' copies of these values (including the zeroes).
    pub fn prune_zero_guaranteed_responses_size_bytes(&mut self) {
        self.guaranteed_responses_size_bytes
            .retain(|_, &mut value| value != 0);
    }

    /// Computes the `guaranteed_responses_size_bytes` map from scratch. Used when
    /// deserializing and in asserts.
    ///
    /// Time complexity: O(num_messages).
    pub fn calculate_stats(streams: &StreamMap) -> BTreeMap<CanisterId, usize> {
        let mut guaranteed_responses_size_bytes: BTreeMap<CanisterId, usize> = BTreeMap::new();
        for (_, stream) in streams.iter() {
            for (_, msg) in stream.messages().iter() {
                if let RequestOrResponse::Response(response) = msg {
                    if response.deadline == NO_DEADLINE {
                        *guaranteed_responses_size_bytes
                            .entry(response.respondent)
                            .or_default() += msg.count_bytes();
                    }
                }
            }
        }
        guaranteed_responses_size_bytes
    }

    /// Checks that the running accounting of the sizes of responses in streams is
    /// accurate.
    #[cfg(debug_assertions)]
    fn debug_validate_stats(&self) {
        let mut nonzero_guaranteed_responses_size_bytes =
            self.guaranteed_responses_size_bytes.clone();
        nonzero_guaranteed_responses_size_bytes.retain(|_, &mut value| value != 0);
        debug_assert_eq!(
            Streams::calculate_stats(&self.streams),
            nonzero_guaranteed_responses_size_bytes
        );
    }
}

/// A mutable reference to a stream owned by a `Streams` struct; bundled with
/// the `Streams`' stats, to be updated on stream mutations.
pub struct StreamHandle<'a> {
    stream: &'a mut Stream,

    guaranteed_responses_size_bytes: &'a mut BTreeMap<CanisterId, usize>,
}

impl<'a> StreamHandle<'a> {
    pub fn new(
        stream: &'a mut Stream,
        guaranteed_responses_size_bytes: &'a mut BTreeMap<CanisterId, usize>,
    ) -> Self {
        Self {
            stream,
            guaranteed_responses_size_bytes,
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
    pub fn reject_signals(&self) -> &VecDeque<RejectSignal> {
        self.stream.reject_signals()
    }

    /// Returns the index just beyond the last sent signal.
    pub fn signals_end(&self) -> StreamIndex {
        self.stream.signals_end
    }

    /// Appends the given message to the tail of the stream.
    ///
    /// Returns the byte size of the pushed message.
    pub fn push(&mut self, message: RequestOrResponse) -> usize {
        let size_bytes = message.count_bytes();
        if let RequestOrResponse::Response(response) = &message {
            if response.deadline == NO_DEADLINE {
                *self
                    .guaranteed_responses_size_bytes
                    .entry(response.respondent)
                    .or_default() += size_bytes;
            }
        }
        self.stream.push(message);
        size_bytes
    }

    /// Pushes an accept signal. Since these are not explicitly encoded, this
    /// just increments `signals_end`.
    pub fn push_accept_signal(&mut self) {
        self.stream.push_accept_signal();
    }

    /// Appends a reject signal (the current `signals_end`) to the tail of the
    /// reject signals; and then increments `signals_end`.
    pub fn push_reject_signal(&mut self, reason: RejectReason) {
        self.stream.push_reject_signal(reason);
    }

    /// Garbage collects messages before `new_begin`, collecting and returning all
    /// messages for which a reject signal was received.
    pub fn discard_messages_before(
        &mut self,
        new_begin: StreamIndex,
        reject_signals: &VecDeque<RejectSignal>,
    ) -> Vec<(RejectReason, RequestOrResponse)> {
        // Update stats for each discarded message.
        for (index, msg) in self.stream.messages().iter() {
            if index >= new_begin {
                break;
            }
            if let RequestOrResponse::Response(response) = &msg {
                if response.deadline == NO_DEADLINE {
                    let canister_guaranteed_responses_size_bytes = self
                        .guaranteed_responses_size_bytes
                        .get_mut(&response.respondent)
                        .expect(
                            "No `guaranteed_responses_size_bytes` entry for discarded response",
                        );
                    *canister_guaranteed_responses_size_bytes -= msg.count_bytes();
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

    /// Returns a reference to the reverse stream flags.
    pub fn reverse_stream_flags(&self) -> &StreamFlags {
        &self.stream.reverse_stream_flags
    }

    /// Sets the reverse stream flags.
    pub fn set_reverse_stream_flags(&mut self, flags: StreamFlags) {
        self.stream.set_reverse_stream_flags(flags);
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
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

                // Reset `self.next_terminal_time` in case it is after the current timeout
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
    fn prune_after_split<F>(&mut self, is_local_receiver: F)
    where
        F: Fn(CanisterId) -> bool,
    {
        // Destructure `self` in order for the compiler to enforce an explicit decision
        // whenever new fields are added.
        //
        // (!) DO NOT USE THE ".." WILDCARD, THIS SERVES THE SAME FUNCTION AS a `match`!
        let Self {
            ref mut statuses,
            pruning_times: _,
            next_terminal_time: _,
            ref mut memory_usage,
        } = self;

        // Filters for messages in terminal states or addressed to local canisters.
        let should_retain = |status: &IngressStatus| match status {
            IngressStatus::Known {
                receiver, state, ..
            } => {
                state.is_terminal()
                    || is_local_receiver(CanisterId::unchecked_from_principal(*receiver))
            }
            IngressStatus::Unknown => false,
        };

        // Filter `statuses`. `pruning_times` stay the same on both subnets because we
        // preserved all messages in terminal states, regardless of canister.
        let mut_statuses = Arc::make_mut(statuses);
        let message_ids_to_retain: BTreeSet<_> = mut_statuses
            .iter()
            .filter(|(_, status)| should_retain(status.as_ref()))
            .map(|(message_id, _)| message_id.clone())
            .collect();
        mut_statuses.retain(|message_id, _| message_ids_to_retain.contains(message_id));
        *memory_usage = Self::compute_memory_usage(mut_statuses);
    }
}

/// The number of snapshots retained in the `BlockmakerMetricsTimeSeries`.
const BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS: usize = 60;

/// Converts `Time` to days since Unix epoch. This simply divides the timestamp by
/// 24 hours.
pub(crate) fn days_since_unix_epoch(time: Time) -> u64 {
    time.as_nanos_since_unix_epoch() / (24 * 3600 * 1_000_000_000)
}

/// Metrics for a time series aggregated from the `BlockmakerMetrics` present in each batch.
///
/// Blockmaker stats are continuously accumulated for each node ID. On the first
/// observation of each day (as determined by `days_since_unix_epoch()`) a snapshot along
/// with a timestamp of the last observation on the previous day is stored in the metrics.
/// For each day metrics were aggregated since the first observation, there is exactly one
/// snapshot in the series (including 'today').
///
/// The number of snapshots is capped at `BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS` by
/// discarding the oldest snapshot(s) once this limit is exceeded.
///
/// To ensure the roster of node IDs does not grow indefinitely, Node IDs whose stats are
/// equal in two consecutive snapshots, are pruned from the metrics such that they are missing
/// from that point on. If such a node reappears later on, it will be added as a new node with
/// restarted stats.
///
/// There is a runtime invariant (excluding checks at deserialization):
/// - There are at most `BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS` snapshots.
///
/// There is an invariant (including checks at deserialization):
/// - Each timestamp corresponding to a snapshot maps onto a unique day (as determined
///   by `days_since_unix_epoch()`).
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BlockmakerMetricsTimeSeries(BTreeMap<Time, BlockmakerStatsMap>);

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BlockmakerStats {
    /// Successfully proposed blocks (blocks that became part of the blockchain).
    blocks_proposed_total: u64,
    /// Failures to propose a block (when the node was block maker rank R but the
    /// subnet accepted the block from the block maker with rank S > R).
    blocks_not_proposed_total: u64,
}

/// Per-node and overall blockmaker stats.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BlockmakerStatsMap {
    /// Maps a node ID to it's blockmaker stats.
    node_stats: BTreeMap<NodeId, BlockmakerStats>,
    /// Overall blockmaker stats for all node IDs.
    subnet_stats: BlockmakerStats,
}

impl BlockmakerStatsMap {
    /// Observes blockmaker metrics and then returns `self`.
    fn and_observe(mut self, metrics: &BlockmakerMetrics) -> Self {
        self.node_stats
            .entry(metrics.blockmaker)
            .or_default()
            .blocks_proposed_total += 1;
        for failed_blockmaker in &metrics.failed_blockmakers {
            self.node_stats
                .entry(*failed_blockmaker)
                .or_default()
                .blocks_not_proposed_total += 1;
        }
        self.subnet_stats.blocks_proposed_total += 1;
        self.subnet_stats.blocks_not_proposed_total += metrics.failed_blockmakers.len() as u64;

        self
    }
}

impl BlockmakerMetricsTimeSeries {
    /// Observes blockmaker metrics corresponding to a certain batch time.
    pub fn observe(&mut self, batch_time: Time, metrics: &BlockmakerMetrics) {
        let running_stats = match self.0.pop_last() {
            Some((time, running_stats)) if time > batch_time => {
                // Outdated metrics are ignored.
                self.0.insert(time, running_stats);
                return;
            }
            Some((time, mut running_stats)) => {
                if days_since_unix_epoch(time) < days_since_unix_epoch(batch_time) {
                    // Prune stale node IDs from `running_stats` by comparing its stats with
                    // those of the previous day.
                    if let Some(last_snapshot) =
                        self.0.last_key_value().map(|(_, val)| &val.node_stats)
                    {
                        running_stats.node_stats.retain(|node_id, stats| {
                            match last_snapshot.get(node_id) {
                                // Retain node IDs that are not present in the last snapshot;
                                // and node IDs that are present, but have unequal stats.
                                None => true,
                                Some(last_stats) => last_stats != stats,
                            }
                        });
                    }

                    // A new day has started, insert a new snapshot.
                    self.0.insert(time, running_stats.clone());
                }

                running_stats
            }
            None => BlockmakerStatsMap::default(),
        };

        // Observe the new metrics and replace `running_stats`.
        self.0
            .insert(batch_time, running_stats.and_observe(metrics));

        // Ensure the time series is capped in length.
        while self.0.len() > BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS {
            self.0.pop_first();
        }

        debug_assert!(self.check_soft_invariants().is_ok());
    }

    /// Check if any soft invariant is violated. We use soft invariants to refer
    /// to any invariants that the code maintains at all times, but the correctness
    /// of the code is not influenced if they break.
    ///
    /// Also see note [Replicated State Invariants].
    fn check_soft_invariants(&self) -> Result<(), String> {
        if self
            .0
            .iter()
            .zip(self.0.iter().skip(1))
            .any(|((before, _), (after, _))| {
                days_since_unix_epoch(*before) == days_since_unix_epoch(*after)
            })
        {
            return Err("Found two timestamps on the same day.".into());
        }

        if self.0.len() > BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS {
            return Err(format!(
                "Current metrics len ({}) exceeds limit ({}).",
                self.0.len(),
                BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS,
            ));
        }
        Ok(())
    }

    /// Returns a reference to the running stats (if any).
    pub fn running_stats(&self) -> Option<(&Time, &BlockmakerStatsMap)> {
        self.0.last_key_value()
    }

    /// Returns an iterator pointing at the first element of a chronologically sorted time series
    /// whose timestamp is above or equal to the given time (excluding the running stats for today).
    pub fn metrics_since(&self, time: Time) -> impl Iterator<Item = (&Time, &BlockmakerStatsMap)> {
        // TODO(MR-524): This could be made simpler if the internal data representation would be different. Consider changing this.
        self.0
            .iter()
            .take(self.0.len().saturating_sub(1))
            .filter(move |(batch_time, _)| *batch_time >= &time)
            .take(BLOCKMAKER_METRICS_TIME_SERIES_NUM_SNAPSHOTS)
    }

    pub fn node_metrics_history(&self, time: Time) -> Vec<NodeMetricsHistoryResponse> {
        self.metrics_since(time)
            .map(|(time, stats_map)| {
                let node_metrics = stats_map
                    .node_stats
                    .iter()
                    .map(|(node_id, stats)| NodeMetrics {
                        node_id: node_id.get(),
                        num_blocks_proposed_total: stats.blocks_proposed_total,
                        num_block_failures_total: stats.blocks_not_proposed_total,
                    })
                    .collect();
                NodeMetricsHistoryResponse {
                    timestamp_nanos: time.as_nanos_since_unix_epoch(),
                    node_metrics,
                }
            })
            .collect()
    }
}

impl From<&BlockmakerStatsMap> for pb_metadata::BlockmakerStatsMap {
    fn from(item: &BlockmakerStatsMap) -> Self {
        Self {
            node_stats: item
                .node_stats
                .iter()
                .map(|(node_id, stats)| pb_metadata::NodeBlockmakerStats {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                    blocks_proposed_total: stats.blocks_proposed_total,
                    blocks_not_proposed_total: stats.blocks_not_proposed_total,
                })
                .collect::<Vec<_>>(),
            blocks_proposed_total: item.subnet_stats.blocks_proposed_total,
            blocks_not_proposed_total: item.subnet_stats.blocks_not_proposed_total,
        }
    }
}

impl From<&BlockmakerMetricsTimeSeries> for pb_metadata::BlockmakerMetricsTimeSeries {
    fn from(item: &BlockmakerMetricsTimeSeries) -> Self {
        Self {
            time_stamp_map: item
                .0
                .iter()
                .map(|(time, map)| (time.as_nanos_since_unix_epoch(), map.into()))
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::BlockmakerStatsMap> for BlockmakerStatsMap {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_metadata::BlockmakerStatsMap) -> Result<Self, Self::Error> {
        Ok(Self {
            node_stats: item
                .node_stats
                .into_iter()
                .map(|e| {
                    Ok((
                        node_id_try_from_option(e.node_id)?,
                        BlockmakerStats {
                            blocks_proposed_total: e.blocks_proposed_total,
                            blocks_not_proposed_total: e.blocks_not_proposed_total,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Self::Error>>()?,
            subnet_stats: BlockmakerStats {
                blocks_proposed_total: item.blocks_proposed_total,
                blocks_not_proposed_total: item.blocks_not_proposed_total,
            },
        })
    }
}

/// Decodes a `BlockmakerMetricsTimeSeries` proto. The metrics are provided as a
/// side-channel for recording errors and stats without being forced to return
/// `Err(_)`.
impl
    TryFrom<(
        pb_metadata::BlockmakerMetricsTimeSeries,
        &dyn CheckpointLoadingMetrics,
    )> for BlockmakerMetricsTimeSeries
{
    type Error = ProxyDecodeError;

    fn try_from(
        (item, metrics): (
            pb_metadata::BlockmakerMetricsTimeSeries,
            &dyn CheckpointLoadingMetrics,
        ),
    ) -> Result<Self, Self::Error> {
        let time_series = Self(
            item.time_stamp_map
                .into_iter()
                .map(|(time_nanos, blockmaker_stats_map)| {
                    Ok((
                        Time::from_nanos_since_unix_epoch(time_nanos),
                        blockmaker_stats_map.try_into()?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Self::Error>>()?,
        );

        if let Err(err) = time_series.check_soft_invariants() {
            metrics.observe_broken_soft_invariant(err);
        }

        Ok(time_series)
    }
}

pub(crate) mod testing {
    use super::*;

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

            // Update `guaranteed_responses_size_bytes`, retaining all previous keys with a
            // default byte size of zero (so that the respective canister's
            // `transient_stream_guaranteed_responses_size_bytes` is correctly reset to
            // zero).
            self.guaranteed_responses_size_bytes
                .values_mut()
                .for_each(|size| *size = 0);
            for (canister_id, size_bytes) in Streams::calculate_stats(&self.streams) {
                self.guaranteed_responses_size_bytes
                    .insert(canister_id, size_bytes);
            }
        }
    }

    /// Early warning system / stumbling block forcing the authors of changes adding
    /// or removing replicated state fields to think about and/or ask the Message
    /// Routing team to think about any repercussions to the subnet splitting logic.
    ///
    /// If you do find yourself having to make changes to this function, it is quite
    /// possible that you have not broken anything. But there is a non-zero chance
    /// for changes to the structure of the replicated state to also require changes
    /// to the subnet splitting logic or risk breaking it. Which is why this brute
    /// force check exists.
    ///
    /// See `ReplicatedState::split()` and `ReplicatedState::after_split()` for more
    /// context.
    #[allow(dead_code)]
    fn subnet_splitting_change_guard_do_not_modify_without_reading_doc_comment() {
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let ingress_history = IngressHistoryState {
            statuses: Default::default(),
            pruning_times: Default::default(),
            next_terminal_time: UNIX_EPOCH,
            memory_usage: Default::default(),
        };
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let _system_metadata = SystemMetadata {
            own_subnet_id: SubnetId::new(PrincipalId::new_subnet_test_id(13)),
            own_subnet_type: SubnetType::Application,
            ingress_history,
            // No need to cover streams, they always stay with the subnet.
            streams: Default::default(),
            canister_allocation_ranges: Default::default(),
            last_generated_canister_id: None,
            batch_time: UNIX_EPOCH,
            // Not relevant, gets populated every round.
            network_topology: Default::default(),
            // Covered in `super::subnet_call_context_manager::testing`.
            subnet_call_context_manager: Default::default(),
            own_subnet_features: SubnetFeatures::default(),
            node_public_keys: Default::default(),
            api_boundary_nodes: Default::default(),
            split_from: None,
            prev_state_hash: Default::default(),
            state_sync_version: CURRENT_STATE_SYNC_VERSION,
            certification_version: CertificationVersion::V0,
            heap_delta_estimate: Default::default(),
            subnet_metrics: Default::default(),
            expected_compiled_wasms: Default::default(),
            bitcoin_get_successors_follow_up_responses: Default::default(),
            blockmaker_metrics_time_series: BlockmakerMetricsTimeSeries::default(),
        };
    }
}
