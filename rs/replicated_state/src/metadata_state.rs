use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    crypto::{
        threshold_sig::ni_dkg::{id::ni_dkg_target_id, NiDkgTargetId},
        CryptoHash,
    },
    ingress::{IngressStatus, MAX_INGRESS_TTL},
    messages::{CallbackId, MessageId, Request, RequestOrResponse},
    node_id_into_protobuf, node_id_try_from_protobuf, subnet_id_into_protobuf,
    subnet_id_try_from_protobuf,
    time::{Time, UNIX_EPOCH},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue, StreamSlice},
    CountBytes, CryptoHashOfPartialState, NodeId, NumBytes, PrincipalId, RegistryVersion, SubnetId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
    sync::Arc,
};

pub type Streams = BTreeMap<SubnetId, Stream>;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        ingress::v1 as pb_ingress, queues::v1 as pb_queues, system_metadata::v1 as pb_metadata,
    },
};
use std::{
    convert::{From, TryFrom, TryInto},
    time::Duration,
};

/// Replicated system metadata.  Used primarily for inter-canister messaging and
/// history queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemMetadata {
    /// History of ingress messages as they traversed through the
    /// system.
    pub ingress_history: IngressHistoryState,

    /// CrossNet stream state indexed by the _destination_ subnet id.
    pub streams: Arc<Streams>,

    /// A counter used for generating new canister ids.
    /// Used for canister creation.
    pub generated_id_counter: u64,

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

    /// Asynchronously handled subnet messages.
    pub subnet_call_context_manager: SubnetCallContextManager,

    /// The version of StateSync protocol that should be used to compute
    /// manifest of this state.
    pub state_sync_version: u32,

    /// The version of certification procedure that should be used for this
    /// state.
    pub certification_version: u32,

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTopology {
    pub subnets: BTreeMap<SubnetId, SubnetTopology>,
    pub routing_table: RoutingTable,
    pub nns_subnet_id: SubnetId,
}

impl Default for NetworkTopology {
    fn default() -> Self {
        Self {
            subnets: Default::default(),
            routing_table: Default::default(),
            nns_subnet_id: SubnetId::new(PrincipalId::new_anonymous()),
        }
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
            routing_table: Some(item.routing_table.clone().into()),
            nns_subnet_id: Some(subnet_id_into_protobuf(item.nns_subnet_id)),
        }
    }
}

impl TryFrom<pb_metadata::NetworkTopology> for NetworkTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::NetworkTopology) -> Result<Self, Self::Error> {
        let mut subnets = BTreeMap::<SubnetId, SubnetTopology>::new();
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

        Ok(Self {
            subnets,
            routing_table: try_from_option_field(
                item.routing_table,
                "NetworkTopology::routing_table",
            )?,
            nns_subnet_id,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubnetTopology {
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// https://sdk.dfinity.org/docs/interface-spec/index.html#certification)
    pub public_key: Vec<u8>,
    pub nodes: BTreeMap<NodeId, NodeTopology>,
    pub subnet_type: SubnetType,
}

impl From<&SubnetTopology> for pb_metadata::SubnetTopology {
    fn from(item: &SubnetTopology) -> Self {
        Self {
            public_key: item.public_key.clone(),
            nodes: item
                .nodes
                .iter()
                .map(|(node_id, node_toplogy)| pb_metadata::SubnetTopologyEntry {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                    node_topology: Some(node_toplogy.into()),
                })
                .collect(),
            subnet_type: i32::from(item.subnet_type),
        }
    }
}

impl TryFrom<pb_metadata::SubnetTopology> for SubnetTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetTopology) -> Result<Self, Self::Error> {
        let mut nodes = BTreeMap::<NodeId, NodeTopology>::new();
        for entry in item.nodes {
            nodes.insert(
                node_id_try_from_protobuf(try_from_option_field(
                    entry.node_id,
                    "SubnetTopology::nodes::K",
                )?)?,
                try_from_option_field(entry.node_topology, "SubnetTopology::nodes::V")?,
            );
        }

        Ok(Self {
            public_key: item.public_key,
            nodes,
            // It is fine to use an arbitrary value here. We always reset the
            // field before we actually use it. We pick the value of least
            // privilege just to be sure.
            subnet_type: SubnetType::try_from(item.subnet_type).unwrap_or(SubnetType::Application),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeTopology {
    pub ip_address: String,
    pub http_port: u16,
}

impl From<&NodeTopology> for pb_metadata::NodeTopology {
    fn from(item: &NodeTopology) -> Self {
        Self {
            ip_address: item.ip_address.clone(),
            http_port: item.http_port as u32,
        }
    }
}

impl TryFrom<pb_metadata::NodeTopology> for NodeTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::NodeTopology) -> Result<Self, Self::Error> {
        Ok(Self {
            ip_address: item.ip_address,
            http_port: item.http_port as u16,
        })
    }
}

impl From<&SystemMetadata> for pb_metadata::SystemMetadata {
    fn from(item: &SystemMetadata) -> Self {
        // We do not store the subnet type when we serialize SystemMetadata. We rely on
        // `load_checkpoint()` to properly set this value.
        Self {
            own_subnet_id: Some(subnet_id_into_protobuf(item.own_subnet_id)),
            generated_id_counter: item.generated_id_counter,
            prev_state_hash: item
                .prev_state_hash
                .clone()
                .map(|prev_hash| prev_hash.get().0),
            batch_time_nanos: item.batch_time.as_nanos_since_unix_epoch(),
            ingress_history: Some((&item.ingress_history).into()),
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
            state_sync_version: item.state_sync_version,
            certification_version: item.certification_version,
            heap_delta_estimate: item.heap_delta_estimate.get(),
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
        Ok(Self {
            own_subnet_id: subnet_id_try_from_protobuf(try_from_option_field(
                item.own_subnet_id,
                "SystemMetadata::own_subnet_id",
            )?)?,
            // WARNING! Setting to the default value which can be incorrect. We do not store the
            // actual value when we serialize SystemMetadata. We rely on `load_checkpoint()` to
            // properly set this value.
            own_subnet_type: SubnetType::default(),
            generated_id_counter: item.generated_id_counter,
            prev_state_hash: item.prev_state_hash.map(|b| CryptoHash(b).into()),
            batch_time: Time::from_nanos_since_unix_epoch(item.batch_time_nanos),
            ingress_history: try_from_option_field(
                item.ingress_history,
                "SystemMetadata::ingress_history",
            )?,
            streams: Arc::new(streams),
            network_topology: try_from_option_field(
                item.network_topology,
                "SystemMetadata::network_topology",
            )?,
            state_sync_version: item.state_sync_version,
            certification_version: item.certification_version,
            subnet_call_context_manager: match item.subnet_call_context_manager {
                Some(manager) => SubnetCallContextManager::try_from(manager)?,
                None => Default::default(),
            },

            heap_delta_estimate: NumBytes::from(item.heap_delta_estimate),
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
            generated_id_counter: Default::default(),
            batch_time: UNIX_EPOCH,
            network_topology: Default::default(),
            subnet_call_context_manager: Default::default(),
            // StateManager populates proper values of these fields before
            // committing each state.
            prev_state_hash: Default::default(),
            state_sync_version: 0,
            certification_version: 0,
            heap_delta_estimate: NumBytes::from(0),
        }
    }

    pub fn time(&self) -> Time {
        self.batch_time
    }

    /// Returns the difference in time between blocks. If the time of the
    /// previous block is `UNIX_EPOCH`, then this must be the first block being
    /// handled and hence `Duration::from_secs(0)` is returned.
    pub fn duration_between_batches(&self, time_of_previous_batch: Time) -> Duration {
        assert!(
            self.batch_time >= time_of_previous_batch,
            "Expect the time of the current batch to be >= the time of the previous batch"
        );
        if time_of_previous_batch == UNIX_EPOCH {
            Duration::from_secs(0)
        } else {
            self.batch_time - time_of_previous_batch
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubnetCallContextManager {
    next_callback_id: u64,
    pub contexts: BTreeMap<CallbackId, SubnetCallContext>,
}

impl SubnetCallContextManager {
    pub fn push(&mut self, context: SubnetCallContext) {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;

        self.contexts.insert(callback_id, context);
    }
}

impl From<&SubnetCallContextManager> for pb_metadata::SubnetCallContextManager {
    fn from(item: &SubnetCallContextManager) -> Self {
        Self {
            next_callback_id: item.next_callback_id,
            contexts: item
                .contexts
                .iter()
                .map(
                    |(callback_id, context)| pb_metadata::SubnetCallContextTree {
                        callback_id: callback_id.get(),
                        context: Some(context.into()),
                    },
                )
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::SubnetCallContextManager> for SubnetCallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetCallContextManager) -> Result<Self, Self::Error> {
        let mut contexts = BTreeMap::<CallbackId, SubnetCallContext>::new();
        for entry in item.contexts {
            let context: SubnetCallContext = try_from_option_field(
                entry.context,
                "SystemMetadata::SubnetCallContextManager::SubnetCallContext",
            )?;
            contexts.insert(CallbackId::new(entry.callback_id), context);
        }
        Ok(Self {
            next_callback_id: item.next_callback_id,
            contexts,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubnetCallContext {
    SetupInitialDKGContext {
        request: Request,
        nodes_in_target_subnet: BTreeSet<NodeId>,
        target_id: NiDkgTargetId,
        registry_version: RegistryVersion,
    },
}

impl From<&SubnetCallContext> for pb_metadata::SubnetCallContext {
    fn from(context: &SubnetCallContext) -> Self {
        match context {
            SubnetCallContext::SetupInitialDKGContext {
                request,
                nodes_in_target_subnet,
                target_id,
                registry_version,
            } => Self {
                setup_initial_dkg_context: Some(pb_metadata::SetupInitialDkgContext {
                    request: Some(request.into()),
                    nodes_in_subnet: nodes_in_target_subnet
                        .iter()
                        .map(|node_id| node_id_into_protobuf(*node_id))
                        .collect(),
                    target_id: target_id.to_vec(),
                    registry_version: registry_version.get(),
                }),
            },
        }
    }
}

impl TryFrom<pb_metadata::SubnetCallContext> for SubnetCallContext {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetCallContext) -> Result<Self, Self::Error> {
        match item.setup_initial_dkg_context {
            Some(context) => {
                let mut nodes_in_target_subnet = BTreeSet::<NodeId>::new();
                for node_id in context.nodes_in_subnet {
                    nodes_in_target_subnet.insert(node_id_try_from_protobuf(node_id)?);
                }
                Ok(SubnetCallContext::SetupInitialDKGContext {
                    request: try_from_option_field(context.request, "SubnetCallContext::request")?,
                    nodes_in_target_subnet,
                    target_id: match ni_dkg_target_id(context.target_id.as_slice()) {
                        Ok(target_id) => target_id,
                        Err(_) => {
                            return Err(Self::Error::Other(
                                "target_id is not 32 bytes.".to_string(),
                            ))
                        }
                    },
                    registry_version: RegistryVersion::from(context.registry_version),
                })
            }
            None => Err(ProxyDecodeError::MissingField(
                "SubnetCallContext::setup_initial_dkg_context",
            )),
        }
    }
}

/// Stream is the state of bi-directional communication session with a remote
/// subnet.  It contains outgoing messages having that subnet as their
/// destination and signals for inducted messages received from that subnet.
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

    /// Estimated stream byte size.
    size_bytes: usize,
}

impl Default for Stream {
    fn default() -> Self {
        let messages = Default::default();
        let signals_end = Default::default();
        let size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            size_bytes,
        }
    }
}

impl From<&Stream> for pb_queues::Stream {
    fn from(item: &Stream) -> Self {
        Self {
            messages_begin: item.messages.begin().get(),
            messages: item
                .messages
                .iter()
                .map(|(_, req_or_resp)| req_or_resp.into())
                .collect(),
            signals_end: item.signals_end.get(),
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
        let size_bytes = Self::size_bytes(&messages);

        Ok(Self {
            messages,
            signals_end: item.signals_end.into(),
            size_bytes,
        })
    }
}

impl Stream {
    /// Creates a new `Stream` with the given `messages` and `signals_end`.
    pub fn new(messages: StreamIndexedQueue<RequestOrResponse>, signals_end: StreamIndex) -> Self {
        let size_bytes = Self::size_bytes(&messages);
        Self {
            messages,
            signals_end,
            size_bytes,
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
        self.size_bytes += message.count_bytes();
        self.messages.push(message);
        debug_assert_eq!(Self::size_bytes(&self.messages), self.size_bytes);
    }

    /// Garbage collects messages before `new_begin`.
    pub fn discard_before(&mut self, new_begin: StreamIndex) {
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

        while self.messages.begin() < new_begin {
            self.size_bytes -= self.messages.pop().unwrap().1.count_bytes();
            debug_assert_eq!(Self::size_bytes(&self.messages), self.size_bytes);
        }
    }

    /// Returns the index just beyond the last sent signal.
    pub fn signals_end(&self) -> StreamIndex {
        self.signals_end
    }

    /// Increments the index of the last sent signal.
    pub fn increment_signals_end(&mut self) {
        self.signals_end.inc_assign()
    }

    /// Calculates the byte size of a `Stream` holding the given messages.
    fn size_bytes(messages: &StreamIndexedQueue<RequestOrResponse>) -> usize {
        let messages_bytes: usize = messages.iter().map(|(_, m)| m.count_bytes()).sum();
        size_of::<Stream>() + messages_bytes
    }
}

impl CountBytes for Stream {
    fn count_bytes(&self) -> usize {
        self.size_bytes
    }
}

impl From<Stream> for StreamSlice {
    fn from(val: Stream) -> Self {
        StreamSlice::new(
            StreamHeader {
                begin: val.messages.begin(),
                end: val.messages.end(),
                signals_end: val.signals_end,
            },
            val.messages,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// State associated with the history of statuses of ingress messages as they
/// traversed through the system.
pub struct IngressHistoryState {
    statuses: Arc<BTreeMap<MessageId, IngressStatus>>,
    pruning_times: Arc<BTreeMap<Time, BTreeSet<MessageId>>>,
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

        pb_ingress::IngressHistoryState {
            statuses,
            pruning_times,
        }
    }
}

impl TryFrom<pb_ingress::IngressHistoryState> for IngressHistoryState {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::IngressHistoryState) -> Result<Self, Self::Error> {
        let mut statuses = BTreeMap::<MessageId, IngressStatus>::new();
        let mut pruning_times = BTreeMap::<Time, BTreeSet<MessageId>>::new();

        for entry in item.statuses {
            let msg_id = entry.message_id.as_slice().try_into()?;
            let ingres_status = try_from_option_field(entry.status, "IngressStatusEntry::status")?;

            statuses.insert(msg_id, ingres_status);
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

        Ok(IngressHistoryState {
            statuses: Arc::new(statuses),
            pruning_times: Arc::new(pruning_times),
        })
    }
}

impl IngressHistoryState {
    pub fn new() -> Self {
        Self {
            statuses: Arc::new(BTreeMap::new()),
            pruning_times: Arc::new(BTreeMap::new()),
        }
    }

    /// Inserts a new entry in the ingress history.
    pub fn insert(&mut self, message_id: MessageId, status: IngressStatus, time: Time) {
        // Store the associated expiry time for the given message id only for a
        // "terminal" ingress status. This way we are not risking deleting any status
        // for a message that is still not in a terminal status.
        if let IngressStatus::Completed { .. } | IngressStatus::Failed { .. } = status {
            Arc::make_mut(&mut self.pruning_times)
                .entry(time + MAX_INGRESS_TTL)
                .or_default()
                .insert(message_id.clone());
        }
        Arc::make_mut(&mut self.statuses).insert(message_id, status);
    }

    /// Returns an iterator over response statuses, sorted lexicographically by
    /// message id.
    pub fn statuses(&self) -> impl Iterator<Item = (&MessageId, &IngressStatus)> {
        self.statuses.iter()
    }

    /// Returns an iterator over pruning times statuses, sorted
    /// lexicographically by time.
    pub fn pruning_times(&self) -> impl Iterator<Item = (&Time, &BTreeSet<MessageId>)> {
        self.pruning_times.iter()
    }

    /// Retrieves an entry from the ingress history given a `MessageId`.
    pub fn get(&self, message_id: &MessageId) -> Option<&IngressStatus> {
        self.statuses.get(message_id)
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
        for t in self.pruning_times.as_ref().keys() {
            for message_id in self.pruning_times.get(t).unwrap() {
                statuses.remove(message_id);
            }
        }

        self.pruning_times = Arc::new(new_pruning_times);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::{
        mock_time,
        types::ids::{canister_test_id, message_test_id, user_test_id},
    };
    use ic_types::ingress::{WasmResult, MAX_INGRESS_TTL};

    #[test]
    fn can_prune_old_ingress_history_entries() {
        let mut ingress_history = IngressHistoryState::new();

        let message_id1 = MessageId::from([1_u8; 32]);
        let message_id2 = MessageId::from([2_u8; 32]);
        let message_id3 = MessageId::from([3_u8; 32]);

        let time = mock_time();
        ingress_history.insert(
            message_id1.clone(),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(vec![]),
                time: mock_time(),
            },
            time,
        );
        ingress_history.insert(
            message_id2.clone(),
            IngressStatus::Completed {
                receiver: canister_test_id(2).get(),
                user_id: user_test_id(2),
                result: WasmResult::Reply(vec![]),
                time: mock_time(),
            },
            time,
        );
        ingress_history.insert(
            message_id3.clone(),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(vec![]),
                time: mock_time(),
            },
            time + MAX_INGRESS_TTL / 2,
        );

        // Pretend that the time has advanced
        let time = time + MAX_INGRESS_TTL + std::time::Duration::from_secs(10);

        ingress_history.prune(time);
        assert!(ingress_history.get(&message_id1).is_none());
        assert!(ingress_history.get(&message_id2).is_none());
        assert!(ingress_history.get(&message_id3).is_some());
    }

    #[test]
    fn entries_sorted_lexicographically() {
        let mut ingress_history = IngressHistoryState::new();
        let time = mock_time();

        for i in (0..10u64).rev() {
            ingress_history.insert(
                message_test_id(i),
                IngressStatus::Received {
                    receiver: canister_test_id(1).get(),
                    user_id: user_test_id(1),
                    time,
                },
                time,
            );
        }
        let mut expected: Vec<_> = (0..10u64).map(message_test_id).collect();
        expected.sort();

        let actual: Vec<_> = ingress_history
            .statuses()
            .map(|(id, _)| id.clone())
            .collect();

        assert_eq!(actual, expected);
    }
}
