pub mod proto;
pub mod subnet_call_context_manager;
#[cfg(test)]
mod tests;

use crate::CanisterQueues;
use crate::metadata_state::subnet_call_context_manager::SubnetCallContextManager;
use crate::{CheckpointLoadingMetrics, canister_state::system_state::CyclesUseCase};
use ic_base_types::{CanisterId, SnapshotId};
use ic_btc_replica_types::BlockBlob;
use ic_certification_version::{CURRENT_CERTIFICATION_VERSION, CertificationVersion};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_limits::MAX_INGRESS_TTL;
use ic_management_canister_types_private::{
    IC_00, MasterPublicKeyId, NodeMetrics, NodeMetricsHistoryResponse,
};
use ic_registry_routing_table::{
    CANISTER_IDS_PER_SUBNET, CanisterIdRanges, CanisterMigrations, RoutingTable,
    canister_id_into_u64, difference, intersection,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    CountBytes, CryptoHashOfPartialState, NodeId, NumBytes, PrincipalId, SubnetId,
    batch::BlockmakerMetrics,
    crypto::CryptoHash,
    ingress::{IngressState, IngressStatus},
    messages::{CanisterCall, MessageId, Payload, RejectContext, Response, StreamMessage},
    node_id_into_protobuf, node_id_try_from_option,
    nominal_cycles::NominalCycles,
    state_sync::{CURRENT_STATE_SYNC_VERSION, StateSyncVersion},
    subnet_id_into_protobuf, subnet_id_try_from_protobuf,
    time::{Time, UNIX_EPOCH},
    xnet::{
        RejectReason, RejectSignal, StreamFlags, StreamHeader, StreamIndex, StreamIndexedQueue,
        StreamSlice,
    },
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
    pub(super) streams: Arc<StreamMap>,

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

    /// This flag determines whether cycles are charged. The flag is pulled from
    /// the registry every round.
    pub cost_schedule: CanisterCyclesCostSchedule,

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

    /// Modifications to the state that have not been applied yet to the next checkpoint.
    /// This field is transient and is emptied before writing the next checkpoint.
    pub unflushed_checkpoint_ops: UnflushedCheckpointOps,
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

    /// Mapping from master public key_id to a list of subnets which can use the
    /// given key. Keys without any chain-key enabled subnets are not included in the map.
    pub chain_key_enabled_subnets: BTreeMap<MasterPublicKeyId, Vec<SubnetId>>,

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
            chain_key_enabled_subnets: Default::default(),
            bitcoin_testnet_canister_id: None,
            bitcoin_mainnet_canister_id: None,
        }
    }
}

impl NetworkTopology {
    /// Returns a list of subnets where the chain key feature is enabled.
    pub fn chain_key_enabled_subnets(&self, key_id: &MasterPublicKeyId) -> &[SubnetId] {
        self.chain_key_enabled_subnets
            .get(key_id)
            .map_or(&[], |ids| &ids[..])
    }

    /// Returns the size of the given subnet.
    pub fn get_subnet_size(&self, subnet_id: &SubnetId) -> Option<usize> {
        self.subnets
            .get(subnet_id)
            .map(|subnet_topology| subnet_topology.nodes.len())
    }

    /// Find the subnet for `principal_id`. The input can either be a canister id, or a subnet id.
    pub fn route(&self, principal_id: PrincipalId) -> Option<SubnetId> {
        let as_subnet_id = SubnetId::from(principal_id);
        if self.subnets.contains_key(&as_subnet_id) {
            return Some(as_subnet_id);
        }

        // If the `principal_id` was not a subnet, it must be a `CanisterId` (otherwise
        // we can't route to it).
        match CanisterId::try_from(principal_id) {
            Ok(canister_id) => self
                .routing_table
                .lookup_entry(canister_id)
                .map(|(_range, subnet_id)| subnet_id),
            // Cannot route to any subnet as we couldn't convert to a `CanisterId`.
            Err(_) => None,
        }
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
    /// Chain keys held by this subnet. Just because a subnet holds a Chain key
    /// doesn't mean the subnet has been enabled to use that key. This
    /// will happen when a key is shared with a second subnet which holds it as
    /// a backup. An additional NNS proposal will be needed to allow the subnet
    /// holding the key as backup to actually produce signatures or VetKd key derivations.
    pub chain_keys_held: BTreeSet<MasterPublicKeyId>,
    pub cost_schedule: CanisterCyclesCostSchedule,
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
        if cycles.get() == 0 {
            return;
        }
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
                | CyclesUseCase::VetKd
                | CyclesUseCase::DroppedMessages
                | CyclesUseCase::BurnedCycles => total += *cycles,
            }
        }

        total
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
            certification_version: CURRENT_CERTIFICATION_VERSION,

            heap_delta_estimate: NumBytes::from(0),
            subnet_metrics: Default::default(),
            expected_compiled_wasms: BTreeSet::new(),
            bitcoin_get_successors_follow_up_responses: BTreeMap::default(),
            blockmaker_metrics_time_series: BlockmakerMetricsTimeSeries::default(),
            unflushed_checkpoint_ops: Default::default(),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        }
    }

    pub fn time(&self) -> Time {
        self.batch_time
    }

    /// Returns a reference to the streams.
    pub fn streams(&self) -> &StreamMap {
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
            if start.is_multiple_of(CANISTER_IDS_PER_SUBNET)
                && end == start + CANISTER_IDS_PER_SUBNET - 1
            {
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

    /// Returns `true` iff the given `specified_id` is valid when used in `provisional_create_canister_with_cycles`, i.e.,
    /// iff the given `specified_id` does not belong to the canister allocation ranges.
    pub fn validate_specified_id(&self, specified_id: &CanisterId) -> bool {
        !self
            .canister_allocation_ranges
            .iter()
            .any(|range| range.contains(specified_id))
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
        // (!) DO NOT USE THE ".." WILDCARD, THIS SERVES THE SAME FUNCTION AS A `match`!
        let &mut SystemMetadata {
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
            // `own_subnet_type` has been set by `load_checkpoint()` based on the respective
            // subnet registry record, do not touch it.
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
            unflushed_checkpoint_ops: _,
            // Overwritten as soon as the round begins, no explicit action needed.
            cost_schedule: _,
        } = self;

        let split_from_subnet = split_from.expect("Not a state resulting from a subnet split");

        assert_eq!(0, heap_delta_estimate.get());
        assert!(expected_compiled_wasms.is_empty());

        // Prune the ingress history.
        ingress_history.prune_after_split(|canister_id: CanisterId| {
            // An actual local canister.
            is_local_canister(canister_id)
                // Or this is subnet A' and message is addressed to the management canister.
                || split_from_subnet == *own_subnet_id && canister_id == IC_00
        });

        // Split complete, reset split marker.
        *split_from = None;

        // Reject in-progress subnet messages that cannot be handled on this
        // subnet.
        self.reject_in_progress_management_calls_after_split(&is_local_canister, subnet_queues);
    }

    /// Creates rejects for all in-progress management messages that can no longer
    /// be handled on *subnet A'* following a subnet split.
    ///
    /// Enqueues reject responses into the provided `subnet_queues` for canister
    /// calls; and records a `Failed` state in `ingress_history` for calls
    /// originating from ingress messages.
    ///
    /// Rejects are created for:
    ///
    ///  * All in-progress subnet messages whose target canisters are no longer
    ///    on this subnet (e.g. install, stop).
    ///
    ///    On *subnet B*, the execution of these same messages, now without matching
    ///    subnet call contexts, will be silently aborted / rolled back (without
    ///    producing a response). This is the only way to ensure consistency for a
    ///    message that would otherwise be executing on *subnet B*, but for which a
    ///    only a response from *subnet A'* could be inducted.
    ///
    ///  * Specific requests that must be entirely handled by the local subnet where
    ///    the originator canister exists (e.g. `raw_rand`).
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
                        format!("Canister {canister_id} migrated during a subnet split"),
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
                        format!("Canister {canister_id} migrated during a subnet split"),
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
                    |_| {},
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
    messages: StreamIndexedQueue<StreamMessage>,

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

    /// Number of guaranteed responses per responding canister.
    guaranteed_response_counts: BTreeMap<CanisterId, usize>,
}

impl Default for Stream {
    fn default() -> Self {
        let messages = Default::default();
        let signals_end = Default::default();
        let reject_signals = VecDeque::default();
        let messages_size_bytes = Self::calculate_size_bytes(&messages);
        let reverse_stream_flags = StreamFlags {
            deprecated_responses_only: false,
        };
        let guaranteed_response_counts = BTreeMap::default();
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags,
            guaranteed_response_counts,
        }
    }
}

impl Stream {
    /// Creates a new `Stream` with the given `messages` and `signals_end`.
    pub fn new(messages: StreamIndexedQueue<StreamMessage>, signals_end: StreamIndex) -> Self {
        let messages_size_bytes = Self::calculate_size_bytes(&messages);
        let guaranteed_response_counts = Self::calculate_guaranteed_response_counts(&messages);
        Self {
            messages,
            signals_end,
            reject_signals: VecDeque::new(),
            messages_size_bytes,
            reverse_stream_flags: Default::default(),
            guaranteed_response_counts,
        }
    }

    /// Creates a new `Stream` with the given `messages`, `signals_end` and `reject_signals`.
    pub fn with_signals(
        messages: StreamIndexedQueue<StreamMessage>,
        signals_end: StreamIndex,
        reject_signals: VecDeque<RejectSignal>,
    ) -> Self {
        let messages_size_bytes = Self::calculate_size_bytes(&messages);
        let guaranteed_response_counts = Self::calculate_guaranteed_response_counts(&messages);
        Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags: Default::default(),
            guaranteed_response_counts,
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
    pub fn messages(&self) -> &StreamIndexedQueue<StreamMessage> {
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

    /// Returns the number of guaranteed responses in the stream for each responding canister.
    pub fn guaranteed_response_counts(&self) -> &BTreeMap<CanisterId, usize> {
        &self.guaranteed_response_counts
    }

    /// Appends the given message to the tail of the stream.
    pub fn push(&mut self, message: StreamMessage) {
        self.messages_size_bytes += message.count_bytes();
        if let StreamMessage::Response(response) = &message
            && !response.is_best_effort()
        {
            *self
                .guaranteed_response_counts
                .entry(response.respondent)
                .or_insert(0) += 1;
        }
        self.messages.push(message);
        debug_assert_eq!(
            Self::calculate_size_bytes(&self.messages),
            self.messages_size_bytes
        );
        debug_assert_eq!(
            Self::calculate_guaranteed_response_counts(&self.messages),
            self.guaranteed_response_counts
        );
    }

    /// Garbage collects messages before `new_begin`, collecting and returning all
    /// messages for which a reject signal was received.
    pub fn discard_messages_before(
        &mut self,
        new_begin: StreamIndex,
        reject_signals: &VecDeque<RejectSignal>,
    ) -> Vec<(RejectReason, StreamMessage)> {
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
            debug_assert_eq!(
                Self::calculate_size_bytes(&self.messages),
                self.messages_size_bytes
            );

            if let StreamMessage::Response(response) = &msg
                && !response.is_best_effort()
            {
                match self
                    .guaranteed_response_counts
                    .get_mut(&response.respondent)
                {
                    Some(0) | None => {
                        debug_assert!(false);
                        self.guaranteed_response_counts.remove(&response.respondent);
                    }
                    Some(1) => {
                        self.guaranteed_response_counts.remove(&response.respondent);
                    }
                    Some(count) => *count -= 1,
                }
            }
            debug_assert_eq!(
                Self::calculate_guaranteed_response_counts(&self.messages),
                self.guaranteed_response_counts
            );

            // If we received a reject signal for this message, collect it in
            // `rejected_messages`.
            if let Some(reject_signal) = reject_signals.peek()
                && reject_signal.index == index
            {
                rejected_messages.push((reject_signal.reason, msg));
                reject_signals.next();
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
    fn calculate_size_bytes(messages: &StreamIndexedQueue<StreamMessage>) -> usize {
        messages.iter().map(|(_, m)| m.count_bytes()).sum()
    }

    fn calculate_guaranteed_response_counts(
        messages: &StreamIndexedQueue<StreamMessage>,
    ) -> BTreeMap<CanisterId, usize> {
        let mut result = BTreeMap::new();
        for (_, msg) in messages.iter() {
            // We only count guaranteed responses
            if let StreamMessage::Response(response) = msg
                && !response.is_best_effort()
            {
                *result.entry(response.respondent).or_insert(0) += 1;
            }
        }
        result
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

impl IngressHistoryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new entry in the ingress history. If an entry with `message_id` is
    /// already present this entry will be overwritten. If `status` is a terminal
    /// status (`completed`, `failed`, or `done`) the entry will also be enrolled
    /// to be pruned at `time + MAX_INGRESS_TTL`.
    ///
    /// Returns the previous status associated with `message_id`.
    pub fn insert(
        &mut self,
        message_id: MessageId,
        status: IngressStatus,
        time: Time,
        ingress_memory_capacity: NumBytes,
        observe_time_in_terminal_state: impl Fn(u64),
    ) -> Arc<IngressStatus> {
        // Store the associated expiry time for the given message id only for a
        // "terminal" ingress status. This way we are not risking deleting any status
        // for a message that is still not in a terminal status.
        if let IngressStatus::Known { state, .. } = &status
            && state.is_terminal()
        {
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
        self.memory_usage += status.payload_bytes();
        let old_status = Arc::make_mut(&mut self.statuses).insert(message_id, Arc::new(status));
        if let Some(old) = &old_status {
            self.memory_usage -= old.payload_bytes();
        }

        if self.memory_usage > ingress_memory_capacity.get() as usize {
            self.forget_terminal_statuses(
                ingress_memory_capacity,
                time,
                observe_time_in_terminal_state,
            );
        }

        debug_assert_eq!(
            Self::compute_memory_usage(&self.statuses),
            self.memory_usage
        );

        old_status.unwrap_or_else(|| IngressStatus::Unknown.into())
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
    fn forget_terminal_statuses(
        &mut self,
        target_size: NumBytes,
        now: Time,
        observe_time_in_terminal_state: impl Fn(u64),
    ) {
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

            // We keep track of entries by how much they are evicted before their "pruning_time".
            let time_until_pruning = time.saturating_duration_since(now);
            let time_in_ingress_history_secs =
                MAX_INGRESS_TTL.saturating_sub(time_until_pruning).as_secs();

            for id in ids.iter() {
                observe_time_in_terminal_state(time_in_ingress_history_secs);
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
            statuses,
            pruning_times: _,
            next_terminal_time: _,
            memory_usage,
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

/// Modifications to the state that require explicit tracking in order to be correctly applied
/// by the checkpointing logic.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum UnflushedCheckpointOp {
    /// A new snapshot was taken from a canister.
    TakeSnapshot(CanisterId, SnapshotId),
    /// A snapshot was loaded to a canister.
    LoadSnapshot(CanisterId, SnapshotId),
    /// A canister was renamed.
    RenameCanister(CanisterId, CanisterId),
}

/// A collection of unflushed checkpoint operations in the order that they were applied to the state.
/// Entries are added by the execution code and read by the checkpointing logic.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct UnflushedCheckpointOps {
    operations: Vec<UnflushedCheckpointOp>,
}

impl UnflushedCheckpointOps {
    pub fn take(&mut self) -> Vec<UnflushedCheckpointOp> {
        std::mem::take(&mut self.operations)
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn take_snapshot(&mut self, canister_id: CanisterId, snapshot_id: SnapshotId) {
        self.operations.push(UnflushedCheckpointOp::TakeSnapshot(
            canister_id,
            snapshot_id,
        ));
    }

    pub fn load_snapshot(&mut self, canister_id: CanisterId, snapshot_id: SnapshotId) {
        self.operations.push(UnflushedCheckpointOp::LoadSnapshot(
            canister_id,
            snapshot_id,
        ));
    }

    pub fn rename_canister(&mut self, old_canister_id: CanisterId, new_canister_id: CanisterId) {
        self.operations.push(UnflushedCheckpointOp::RenameCanister(
            old_canister_id,
            new_canister_id,
        ));
    }
}

pub(crate) mod testing {
    use super::*;

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
            cost_schedule: CanisterCyclesCostSchedule::Normal,
            node_public_keys: Default::default(),
            api_boundary_nodes: Default::default(),
            split_from: None,
            prev_state_hash: Default::default(),
            state_sync_version: CURRENT_STATE_SYNC_VERSION,
            certification_version: CURRENT_CERTIFICATION_VERSION,
            heap_delta_estimate: Default::default(),
            subnet_metrics: Default::default(),
            expected_compiled_wasms: Default::default(),
            bitcoin_get_successors_follow_up_responses: Default::default(),
            blockmaker_metrics_time_series: BlockmakerMetricsTimeSeries::default(),
            unflushed_checkpoint_ops: Default::default(),
        };
    }
}
