pub mod subnet_call_context_manager;
#[cfg(test)]
mod tests;

use crate::metadata_state::subnet_call_context_manager::SubnetCallContextManager;
use ic_base_types::CanisterId;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        ingress::v1 as pb_ingress,
        queues::v1 as pb_queues,
        system_metadata::v1::{self as pb_metadata, TimeOfLastAllocationCharge},
    },
};
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    crypto::CryptoHash,
    ingress::{IngressStatus, MAX_INGRESS_TTL},
    messages::{MessageId, RequestOrResponse},
    node_id_into_protobuf, node_id_try_from_protobuf, subnet_id_into_protobuf,
    subnet_id_try_from_protobuf,
    time::{Time, UNIX_EPOCH},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue, StreamSlice},
    CountBytes, CryptoHashOfPartialState, NodeId, NumBytes, PrincipalId, SubnetId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{From, TryFrom, TryInto},
    mem::size_of,
    sync::Arc,
    time::Duration,
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

    pub own_subnet_features: SubnetFeatures,

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

    /// The last time when canisters were charged for compute and storage
    /// allocation.
    ///
    /// Charging for compute and storage is done periodically, so this is
    /// needed to calculate how much time should be charged for when charging
    /// does occur.
    pub time_of_last_allocation_charge: Time,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTopology {
    pub subnets: BTreeMap<SubnetId, SubnetTopology>,
    pub routing_table: Arc<RoutingTable>,
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
            routing_table: Some(item.routing_table.as_ref().into()),
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
            )
            .map(Arc::new)?,
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
            own_subnet_features: Some(item.own_subnet_features.into()),
            time_of_last_allocation_charge_nanos: Some(TimeOfLastAllocationCharge {
                time_of_last_allocation_charge_nanos: item
                    .time_of_last_allocation_charge
                    .as_nanos_since_unix_epoch(),
            }),
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
            own_subnet_features: item.own_subnet_features.unwrap_or_default().into(),
            generated_id_counter: item.generated_id_counter,
            prev_state_hash: item.prev_state_hash.map(|b| CryptoHash(b).into()),
            batch_time: Time::from_nanos_since_unix_epoch(item.batch_time_nanos),
            ingress_history: try_from_option_field(
                item.ingress_history,
                "SystemMetadata::ingress_history",
            )?,
            streams: Arc::new(Streams {
                responses_size_bytes: Streams::calculate_stats(&streams),
                streams,
            }),
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
            time_of_last_allocation_charge: match item.time_of_last_allocation_charge_nanos {
                Some(last_charge) => Time::from_nanos_since_unix_epoch(
                    last_charge.time_of_last_allocation_charge_nanos,
                ),
                None => Time::from_nanos_since_unix_epoch(item.batch_time_nanos),
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
            generated_id_counter: Default::default(),
            batch_time: UNIX_EPOCH,
            network_topology: Default::default(),
            subnet_call_context_manager: Default::default(),
            own_subnet_features: SubnetFeatures::default(),
            // StateManager populates proper values of these fields before
            // committing each state.
            prev_state_hash: Default::default(),
            state_sync_version: 0,
            certification_version: 0,
            heap_delta_estimate: NumBytes::from(0),
            time_of_last_allocation_charge: UNIX_EPOCH,
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

    /// Returns a reference to the streams.
    pub fn streams(&self) -> &Streams {
        &self.streams
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

    /// Returns the stream's begin index.
    pub fn messages_begin(&self) -> StreamIndex {
        self.stream.messages_begin()
    }

    /// Returns the stream's end index.
    pub fn messages_end(&self) -> StreamIndex {
        self.stream.messages_end()
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

    /// Garbage collects messages before `new_begin`.
    pub fn discard_before(&mut self, new_begin: StreamIndex) {
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

        self.stream.discard_before(new_begin);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// State associated with the history of statuses of ingress messages as they
/// traversed through the system.
pub struct IngressHistoryState {
    statuses: Arc<BTreeMap<MessageId, Arc<IngressStatus>>>,
    pruning_times: Arc<BTreeMap<Time, BTreeSet<MessageId>>>,
    memory_usage: usize,
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
            memory_usage,
        })
    }
}

impl IngressHistoryState {
    pub fn new() -> Self {
        Self {
            statuses: Arc::new(BTreeMap::new()),
            pruning_times: Arc::new(BTreeMap::new()),
            memory_usage: 0,
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
        self.memory_usage += status.count_bytes();
        if let Some(old) = Arc::make_mut(&mut self.statuses).insert(message_id, Arc::new(status)) {
            self.memory_usage -= old.count_bytes();
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
        for t in self.pruning_times.as_ref().keys() {
            for message_id in self.pruning_times.get(t).unwrap() {
                if let Some(removed) = statuses.remove(message_id) {
                    self.memory_usage -= removed.count_bytes();
                }
            }
        }
        self.pruning_times = Arc::new(new_pruning_times);

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
        statuses.values().map(|status| status.count_bytes()).sum()
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
