//! Conversion from `ReplicatedState` to `LazyTree`.

use crate::{
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION, MIN_SUPPORTED_CERTIFICATION_VERSION,
    encoding::{
        encode_controllers, encode_message, encode_metadata, encode_stream_header,
        encode_subnet_canister_ranges, encode_subnet_metrics,
    },
};
use LazyTree::Blob;
use ic_canonical_state_tree_hash::lazy_tree::{Lazy, LazyFork, LazyTree, blob, fork, num, string};
use ic_crypto_tree_hash::Label;
use ic_error_types::ErrorCode;
use ic_error_types::RejectCode;
use ic_registry_routing_table::RoutingTable;
use ic_replicated_state::{
    ExecutionState, ReplicatedState, Stream,
    canister_state::CanisterState,
    metadata_state::{
        ApiBoundaryNodeEntry, IngressHistoryState, StreamMap, SubnetMetrics, SubnetTopology,
        SystemMetadata,
    },
    replicated_state::ReplicatedStateMessageRouting,
};
use ic_types::{
    CanisterId, NodeId, PrincipalId, SubnetId,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{EXPECTED_MESSAGE_ID_LENGTH, MessageId},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue},
};
use std::convert::{AsRef, TryFrom, TryInto};
use std::iter::once;
use std::sync::Arc;
use std::{collections::BTreeMap, marker::PhantomData};

/// The maximum number of disjoint ranges a single leaf of the routing table can contain.
/// Changes to this constant require a new certification version.
const MAX_RANGES_PER_ROUTING_TABLE_LEAF: usize = 5;

/// A simple map from a label to a tree. It should be mostly used for static
/// subtrees where all the labels are known in advance.
#[derive(Default)]
struct FiniteMap<'a>(BTreeMap<Label, Lazy<'a, LazyTree<'a>>>);

impl<'a> FiniteMap<'a> {
    /// Adds a function returning a subtree with the specified label to this map.
    pub fn with<B, T>(mut self, blob: B, func: T) -> Self
    where
        B: AsRef<[u8]>,
        T: Fn() -> LazyTree<'a> + 'a + Send + Sync,
    {
        self.0.insert(Label::from(blob), Lazy::Func(Arc::new(func)));
        self
    }

    /// Adds a subtree with the specified label to this map.
    pub fn with_tree<B: AsRef<[u8]>>(mut self, label: B, tree: LazyTree<'a>) -> Self {
        self.0.insert(Label::from(label), Lazy::Value(tree));
        self
    }

    /// If condition is true, adds a function returning a subtree with the specified label to this map.
    /// Otherwise does nothing.
    pub fn with_if<B, T>(mut self, condition: bool, blob: B, func: T) -> Self
    where
        B: AsRef<[u8]>,
        T: Fn() -> LazyTree<'a> + 'a + Send + Sync,
    {
        if condition {
            self.0.insert(Label::from(blob), Lazy::Func(Arc::new(func)));
        }
        self
    }

    /// If condition is true, adds a new subtree to this map.
    /// Otherwise does nothing.
    pub fn with_tree_if<B: AsRef<[u8]>>(
        mut self,
        condition: bool,
        label: B,
        tree: LazyTree<'a>,
    ) -> Self {
        if condition {
            self.0.insert(Label::from(label), Lazy::Value(tree));
        }
        self
    }

    /// If the optional field is `Some` value, adds a new subtree to this map.
    /// Otherwise does nothing.
    /// The subtree is constructed by applying `func` to the value extracted from the optional field.
    pub fn with_optional_tree<B, T, F>(
        mut self,
        optional_field: Option<T>,
        label: B,
        func: F,
    ) -> Self
    where
        B: AsRef<[u8]>,
        F: Fn(T) -> LazyTree<'a>,
    {
        if let Some(field) = optional_field {
            self.0.insert(Label::from(label), Lazy::Value(func(field)));
        }
        self
    }
}

impl<'a> LazyFork<'a> for FiniteMap<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        self.0.get(label).map(|lazy| lazy.force())
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.0.keys().cloned())
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        Box::new(self.0.iter().map(|(l, lazy)| (l.clone(), lazy.force())))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// LabelLike defines a (partial) conversion between a type and a label.
pub trait LabelLike: Sized {
    fn to_label(&self) -> Label;
    fn from_label(label: &[u8]) -> Option<Self>;
}

impl LabelLike for u64 {
    fn to_label(&self) -> Label {
        Label::from(self.to_be_bytes())
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        if label.len() != 8 {
            return None;
        }
        let be_bytes: [u8; 8] = label.try_into().ok()?;
        Some(u64::from_be_bytes(be_bytes))
    }
}

impl LabelLike for String {
    fn to_label(&self) -> Label {
        Label::from(self.as_bytes())
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        String::from_utf8(Vec::from(label)).ok()
    }
}

impl<T: LabelLike, Tag> LabelLike for phantom_newtype::Id<Tag, T> {
    fn to_label(&self) -> Label {
        self.get_ref().to_label()
    }
    fn from_label(label: &[u8]) -> Option<Self> {
        T::from_label(label).map(Self::new)
    }
}

impl<T: LabelLike + Copy, Tag> LabelLike for phantom_newtype::AmountOf<Tag, T> {
    fn to_label(&self) -> Label {
        self.get().to_label()
    }
    fn from_label(label: &[u8]) -> Option<Self> {
        T::from_label(label).map(Self::new)
    }
}

impl LabelLike for PrincipalId {
    fn to_label(&self) -> Label {
        Label::from(self.as_slice())
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        PrincipalId::try_from(label).ok()
    }
}

impl LabelLike for CanisterId {
    fn to_label(&self) -> Label {
        self.get_ref().to_label()
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        PrincipalId::from_label(label).map(Self::unchecked_from_principal)
    }
}

/// A filter for use with `MapTransformFork`, to optionally filter out specific
/// map entries (e.g. the loopback stream)
trait MapFilter<K, V> {
    /// Returns true if the entry with key `k` should be output.
    fn should_output(&self, k: &K) -> bool;

    /// Returns the adjusted map length, after filtering.
    ///
    /// This must be consistent with `should_output()`.
    fn filtered_len(&self, map: &BTreeMap<K, V>) -> usize;
}

/// Default no-op `MapFilter` that outputs all entries.
struct NoFilter;
impl<K, V> MapFilter<K, V> for NoFilter {
    #[inline]
    fn should_output(&self, _k: &K) -> bool {
        true
    }

    #[inline]
    fn filtered_len(&self, map: &BTreeMap<K, V>) -> usize {
        map.len()
    }
}

/// A type of fork that constructs a lazy tree view of a typed Map without
/// copying the underlying data.
#[derive(Clone)]
struct MapTransformFork<'a, K, V, MF, F>
where
    F: Fn(K, &'a V, CertificationVersion) -> LazyTree<'a>,
    MF: MapFilter<K, V>,
{
    map: &'a BTreeMap<K, V>,
    map_filter: MF,
    certification_version: CertificationVersion,
    mk_tree: F,
}

impl<'a, K, V, MF, F> LazyFork<'a> for MapTransformFork<'a, K, V, MF, F>
where
    K: Ord + LabelLike + Clone + Send + Sync,
    V: Send + Sync,
    MF: MapFilter<K, V> + Send + Sync,
    F: Fn(K, &'a V, CertificationVersion) -> LazyTree<'a> + Send + Sync,
{
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let k = K::from_label(label.as_bytes())?;
        if !self.map_filter.should_output(&k) {
            return None;
        }
        self.map
            .get(&k)
            .map(move |v| (self.mk_tree)(k, v, self.certification_version))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(
            self.map
                .keys()
                .filter(|&k| self.map_filter.should_output(k))
                .map(|l| l.to_label()),
        )
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        Box::new(
            self.map
                .iter()
                .filter(|(k, _)| self.map_filter.should_output(k))
                .map(move |(k, v)| {
                    (
                        k.to_label(),
                        (self.mk_tree)(k.clone(), v, self.certification_version),
                    )
                }),
        )
    }

    fn len(&self) -> usize {
        self.map_filter.filtered_len(self.map)
    }
}

/// A special type of fork that describes a stream-indexed queue.
#[derive(Clone)]
struct StreamQueueFork<'a, T>
where
    T: Send + Sync,
{
    queue: &'a StreamIndexedQueue<T>,
    certification_version: CertificationVersion,
    mk_tree: fn(StreamIndex, &'a T, CertificationVersion) -> LazyTree<'a>,
}

impl<'a, T: Send + Sync> LazyFork<'a> for StreamQueueFork<'a, T> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let idx = StreamIndex::from_label(label.as_bytes())?;
        self.queue
            .get(idx)
            .map(move |v| (self.mk_tree)(idx, v, self.certification_version))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new((self.queue.begin().get()..self.queue.end().get()).map(|i| i.to_label()))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        Box::new(self.queue.iter().map(move |(idx, v)| {
            (
                idx.to_label(),
                (self.mk_tree)(idx, v, self.certification_version),
            )
        }))
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

/// The subtree under /canister_ranges/<subnet_id>/, consisting of any number of leaves, each encoding a small number of canister ranges
/// and labelled by the smallest canister id contained.
struct CanisterRangesFork<'a> {
    /// List of ranges to represent in a tree.
    /// If None, then the list of ranges is empty. This case can happen if a subnet exists but has no canisters assigned to it. Also see `EMTPY_RANGES_LABEL`.
    split_ranges: Option<Arc<SplitRanges>>,
    /// This `PhantomData` is necessary so that the compiler knows that 'a from `LazyFork<'a>` always outlives this struct.
    phantom: PhantomData<&'a ()>,
}

/// Subnets with no assigned ranges are represented by a single child with label `EMPTY_RANGES_LABEL` and a value encoding an empty set.
const EMPTY_RANGES_LABEL: CanisterId = CanisterId::from_u64(0);

impl<'a> LazyFork<'a> for CanisterRangesFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let idx = CanisterId::from_label(label.as_bytes())?;
        match &self.split_ranges {
            Some(split_ranges) => split_ranges.get(&idx).map(|ranges| {
                blob({
                    let ranges = Arc::clone(ranges);
                    move || encode_subnet_canister_ranges(Some(&ranges))
                })
            }),
            None => {
                // For subnets with no canister ranges we create a single entry at label CanisterId(0) encoding empty ranges.
                if idx == EMPTY_RANGES_LABEL {
                    Some(blob(move || encode_subnet_canister_ranges(None)))
                } else {
                    None
                }
            }
        }
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        match &self.split_ranges {
            Some(split_ranges) => Box::new(split_ranges.keys().map(|idx| idx.to_label())),
            None => Box::new(std::iter::once(EMPTY_RANGES_LABEL.to_label())),
        }
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        match &self.split_ranges {
            Some(split_ranges) => Box::new(split_ranges.iter().map(|(idx, ranges)| {
                let idx = idx.to_owned();
                let ranges = Arc::clone(ranges);
                (idx.to_label(), {
                    blob(move || encode_subnet_canister_ranges(Some(&ranges)))
                })
            })),
            None => Box::new(std::iter::once((
                EMPTY_RANGES_LABEL.to_label(),
                blob(move || encode_subnet_canister_ranges(None)),
            ))),
        }
    }

    fn len(&self) -> usize {
        self.split_ranges.as_ref().map_or(1, |r| r.len())
    }
}

fn invert_routing_table(
    routing_table: &RoutingTable,
) -> BTreeMap<SubnetId, Vec<(PrincipalId, PrincipalId)>> {
    let mut inverse_map: BTreeMap<SubnetId, Vec<_>> = BTreeMap::new();
    for (range, subnet_id) in routing_table.iter() {
        inverse_map
            .entry(*subnet_id)
            .or_default()
            .push((range.start.get(), range.end.get()));
    }
    inverse_map
}

/// The canister ranges of a single subnet, split into multiple chunks.
type SplitRanges = BTreeMap<CanisterId, Arc<Vec<(PrincipalId, PrincipalId)>>>;
/// The entire routing table in the format required for the /canister_ranges subtree.
type SplitRoutingTable = BTreeMap<SubnetId, Arc<SplitRanges>>;

/// Split the inverted routing table into multiple chunks such that no chunk is larger than `max_ranges_per_leaf` ranges.
fn split_inverted_routing_table(
    inverted_routing_table: &BTreeMap<SubnetId, Vec<(PrincipalId, PrincipalId)>>,
    max_ranges_per_leaf: usize,
) -> SplitRoutingTable {
    inverted_routing_table
        .iter()
        .map(|(k, v)| {
            let splits: BTreeMap<_, _> = v
                .chunks(max_ranges_per_leaf)
                .map(|v| {
                    (
                        CanisterId::unchecked_from_principal(v[0].0),
                        Arc::new(v.to_owned()),
                    )
                })
                .collect();
            (*k, Arc::new(splits))
        })
        .collect()
}

/// Converts replicated state into a lazy tree.
pub fn replicated_state_as_lazy_tree(state: &ReplicatedState) -> LazyTree<'_> {
    let certification_version = state.metadata.certification_version;
    assert!(
        MIN_SUPPORTED_CERTIFICATION_VERSION <= certification_version
            && certification_version <= MAX_SUPPORTED_CERTIFICATION_VERSION,
        "Unable to certify state with version {certification_version:?}. Supported certification versions are {MIN_SUPPORTED_CERTIFICATION_VERSION:?}..={MAX_SUPPORTED_CERTIFICATION_VERSION:?}",
    );
    let own_subnet_id = state.metadata.own_subnet_id;
    let inverted_routing_table = Arc::new(invert_routing_table(
        &state.metadata.network_topology.routing_table,
    ));
    let split_routing_table = Arc::new(split_inverted_routing_table(
        &inverted_routing_table,
        MAX_RANGES_PER_ROUTING_TABLE_LEAF,
    ));

    fork(
        FiniteMap::default()
            .with("api_boundary_nodes", move || {
                api_boundary_nodes_as_tree(
                    &state.metadata.api_boundary_nodes,
                    certification_version,
                )
            })
            .with("metadata", move || {
                system_metadata_as_tree(&state.metadata, certification_version)
            })
            .with("streams", move || {
                streams_as_tree(state.streams(), own_subnet_id, certification_version)
            })
            .with("canister", move || {
                canisters_as_tree(&state.canister_states, certification_version)
            })
            .with_tree(
                "request_status",
                fork(IngressHistoryFork(&state.metadata.ingress_history)),
            )
            .with("subnet", move || {
                subnets_as_tree(
                    &state.metadata.network_topology.subnets,
                    own_subnet_id,
                    &state.metadata.node_public_keys,
                    inverted_routing_table.clone(),
                    &state.metadata.subnet_metrics,
                    certification_version,
                )
            })
            .with_tree(
                "time",
                num(state.metadata.batch_time.as_nanos_since_unix_epoch()),
            )
            .with_if(
                certification_version >= CertificationVersion::V21,
                "canister_ranges",
                move || {
                    canister_ranges_as_tree(
                        &state.metadata.network_topology.subnets,
                        Arc::clone(&split_routing_table),
                        certification_version,
                    )
                },
            ),
    )
}

/// A filter for the streams map, to filter out the loopback stream.
struct StreamsFilter {
    own_subnet_id: SubnetId,
}

impl MapFilter<SubnetId, Stream> for StreamsFilter {
    #[inline]
    fn should_output(&self, k: &SubnetId) -> bool {
        *k != self.own_subnet_id
    }

    #[inline]
    fn filtered_len(&self, streams: &StreamMap) -> usize {
        if streams.contains_key(&self.own_subnet_id) {
            streams.len() - 1
        } else {
            streams.len()
        }
    }
}

fn streams_as_tree<'a>(
    streams: &'a StreamMap,
    own_subnet_id: SubnetId,
    certification_version: CertificationVersion,
) -> LazyTree<'a> {
    let mk_tree = |_subnet_id, stream: &'a Stream, certification_version| {
        fork(
            FiniteMap::default()
                .with_tree(
                    "header",
                    blob(move || {
                        let stream_header: StreamHeader = stream.header();
                        encode_stream_header(&stream_header, certification_version)
                    }),
                )
                .with_tree(
                    "messages",
                    fork(StreamQueueFork {
                        queue: stream.messages(),
                        certification_version,
                        mk_tree: |_idx, msg, certification_version| {
                            blob(move || encode_message(msg, certification_version))
                        },
                    }),
                ),
        )
    };

    if certification_version >= CertificationVersion::V20 {
        // Starting with `V20`, filter out the loopback stream.
        fork(MapTransformFork {
            map: streams,
            map_filter: StreamsFilter { own_subnet_id },
            certification_version,
            mk_tree,
        })
    } else {
        // Before `V20`, output all streams.
        fork(MapTransformFork {
            map: streams,
            map_filter: NoFilter,
            certification_version,
            mk_tree,
        })
    }
}

fn system_metadata_as_tree(
    m: &SystemMetadata,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    blob(move || encode_metadata(m, certification_version))
}

struct IngressHistoryFork<'a>(&'a IngressHistoryState);

impl<'a> LazyFork<'a> for IngressHistoryFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let byte_array: [u8; EXPECTED_MESSAGE_ID_LENGTH] = label.as_bytes().try_into().ok()?;
        let id = MessageId::from(byte_array);
        self.0.get(&id).map(|status| status_to_tree(status))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.0.statuses().map(|(id, _)| Label::from(id.as_bytes())))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        Box::new(
            self.0
                .statuses()
                .map(|(id, status)| (Label::from(id.as_bytes()), status_to_tree(status))),
        )
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

const ERROR_CODE_LABEL: &[u8] = b"error_code";
const REJECT_CODE_LABEL: &[u8] = b"reject_code";
const REJECT_MESSAGE_LABEL: &[u8] = b"reject_message";
const REPLY_LABEL: &[u8] = b"reply";
const STATUS_LABEL: &[u8] = b"status";

struct OnlyStatus<'a>(&'a str);

impl<'a> LazyFork<'a> for OnlyStatus<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        (label.as_bytes() == STATUS_LABEL).then_some(string(self.0))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        Box::new(once(Label::from(STATUS_LABEL)))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        Box::new(once((Label::from(STATUS_LABEL), string(self.0))))
    }

    fn len(&self) -> usize {
        1
    }
}

const REPLY_STATUS_LABELS: [&[u8]; 2] = [REPLY_LABEL, STATUS_LABEL];

#[derive(Clone)]
struct ReplyStatus<'a>(&'a [u8]);

impl<'a> LazyFork<'a> for ReplyStatus<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        match label.as_bytes() {
            STATUS_LABEL => Some(string("replied")),
            REPLY_LABEL => Some(Blob(self.0, None)),
            _ => None,
        }
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        Box::new(REPLY_STATUS_LABELS.iter().map(Label::from))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        let status = self.clone();
        Box::new(REPLY_STATUS_LABELS.iter().filter_map(move |label| {
            let label = Label::from(label);
            let fork = status.edge(&label)?;
            Some((label, fork))
        }))
    }

    fn len(&self) -> usize {
        REPLY_STATUS_LABELS.len()
    }
}

const REJECT_STATUS_LABELS: [&[u8]; 4] = [
    ERROR_CODE_LABEL,
    REJECT_CODE_LABEL,
    REJECT_MESSAGE_LABEL,
    STATUS_LABEL,
];

#[derive(Clone)]
struct RejectStatus<'a> {
    reject_code: u64,
    error_code: Option<ErrorCode>,
    message: &'a str,
}

impl<'a> LazyFork<'a> for RejectStatus<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        match label.as_bytes() {
            ERROR_CODE_LABEL => self
                .error_code
                .map(|code| blob(move || code.to_string().into_bytes())),
            REJECT_CODE_LABEL => Some(num::<'a>(self.reject_code)),
            REJECT_MESSAGE_LABEL => Some(string(self.message)),
            STATUS_LABEL => Some(string("rejected")),
            _ => None,
        }
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        Box::new(REJECT_STATUS_LABELS.iter().map(From::from))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        let status = self.clone();
        Box::new(REJECT_STATUS_LABELS.iter().filter_map(move |label| {
            let label = Label::from(label);
            let fork = status.edge(&label)?;
            Some((label, fork))
        }))
    }

    fn len(&self) -> usize {
        REJECT_STATUS_LABELS.len()
    }
}

fn status_to_tree(status: &IngressStatus) -> LazyTree<'_> {
    match status {
        IngressStatus::Known { state, .. } => match state {
            IngressState::Completed(WasmResult::Reply(b)) => fork(ReplyStatus(b)),
            IngressState::Completed(WasmResult::Reject(s)) => fork(RejectStatus {
                reject_code: RejectCode::CanisterReject as u64,
                error_code: Some(ErrorCode::CanisterRejectedMessage),
                message: s,
            }),
            IngressState::Failed(error) => fork(RejectStatus {
                reject_code: error.reject_code() as u64,
                error_code: Some(error.code()),
                message: error.description(),
            }),
            IngressState::Processing | IngressState::Received | IngressState::Done => {
                fork(OnlyStatus(status.as_str()))
            }
        },
        IngressStatus::Unknown => fork(OnlyStatus(status.as_str())),
    }
}

const CERTIFIED_DATA_LABEL: &[u8] = b"certified_data";
const CONTROLLER_LABEL: &[u8] = b"controller";
const CONTROLLERS_LABEL: &[u8] = b"controllers";
const METADATA_LABEL: &[u8] = b"metadata";
const MODULE_HASH_LABEL: &[u8] = b"module_hash";

const CANISTER_LABELS: [&[u8]; 4] = [
    CERTIFIED_DATA_LABEL,
    CONTROLLERS_LABEL,
    METADATA_LABEL,
    MODULE_HASH_LABEL,
];

const CANISTER_NO_MODULE_LABELS: [&[u8]; 1] = [CONTROLLERS_LABEL];

#[derive(Clone)]
struct CanisterFork<'a> {
    canister: &'a CanisterState,
    version: CertificationVersion,
}

impl<'a> CanisterFork<'a> {
    /// Like `edge`, but skips the version check on every call.
    fn edge_no_checks(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        let canister = self.canister;
        match canister.execution_state.as_ref() {
            Some(execution_state) => match label {
                CERTIFIED_DATA_LABEL => Some(Blob(&canister.system_state.certified_data[..], None)),
                CONTROLLER_LABEL => Some(Blob(canister.system_state.controller().as_slice(), None)),
                CONTROLLERS_LABEL => Some(blob(move || {
                    encode_controllers(&canister.system_state.controllers)
                })),
                METADATA_LABEL => Some(canister_metadata_as_tree(execution_state, self.version)),
                MODULE_HASH_LABEL => Some(blob(move || {
                    execution_state.wasm_binary.binary.module_hash().to_vec()
                })),
                _ => None,
            },
            None => match label {
                CONTROLLER_LABEL => Some(Blob(canister.system_state.controller().as_slice(), None)),
                CONTROLLERS_LABEL => Some(blob(move || {
                    encode_controllers(&canister.system_state.controllers)
                })),
                _ => None,
            },
        }
    }
}

impl<'a> LazyFork<'a> for CanisterFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        CANISTER_LABELS.iter().find(|l| *l == &label.as_bytes())?;
        self.edge_no_checks(label.as_bytes())
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        match self.canister.execution_state {
            Some(_) => Box::new(CANISTER_LABELS.iter().map(From::from)),
            None => Box::new(CANISTER_NO_MODULE_LABELS.iter().map(From::from)),
        }
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        let canister = self.clone();
        Box::new(
            CANISTER_LABELS.iter().filter_map(move |label| {
                Some((Label::from(label), canister.edge_no_checks(label)?))
            }),
        )
    }

    fn len(&self) -> usize {
        match self.canister.execution_state {
            Some(_) => CANISTER_LABELS.len(),
            None => CANISTER_NO_MODULE_LABELS.len(),
        }
    }
}

fn api_boundary_nodes_as_tree(
    api_boundary_nodes: &BTreeMap<NodeId, ApiBoundaryNodeEntry>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: api_boundary_nodes,
        map_filter: NoFilter,
        certification_version,
        mk_tree: |_api_boundary_node_id, api_boundary_node, _certification_version| {
            fork(
                FiniteMap::default()
                    .with_tree("domain", string(&api_boundary_node.domain))
                    .with_optional_tree(
                        api_boundary_node.ipv4_address.as_ref(),
                        "ipv4_address",
                        |ipv4_address| string(ipv4_address),
                    )
                    .with_tree("ipv6_address", string(&api_boundary_node.ipv6_address)),
            )
        },
    })
}

fn canisters_as_tree(
    canisters: &BTreeMap<CanisterId, CanisterState>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: canisters,
        map_filter: NoFilter,
        certification_version,
        mk_tree: |_canister_id, canister, certification_version| {
            fork(CanisterFork {
                canister,
                version: certification_version,
            })
        },
    })
}

fn subnets_as_tree<'a>(
    subnets: &'a BTreeMap<SubnetId, SubnetTopology>,
    own_subnet_id: SubnetId,
    own_subnet_node_public_keys: &'a BTreeMap<NodeId, Vec<u8>>,
    inverted_routing_table: Arc<BTreeMap<SubnetId, Vec<(PrincipalId, PrincipalId)>>>,
    metrics: &'a SubnetMetrics,
    certification_version: CertificationVersion,
) -> LazyTree<'a> {
    fork(MapTransformFork {
        map: subnets,
        map_filter: NoFilter,
        certification_version,
        mk_tree: move |subnet_id, subnet_topology, certification_version| {
            fork(
                FiniteMap::default()
                    .with_tree("public_key", Blob(&subnet_topology.public_key[..], None))
                    .with_tree(
                        "canister_ranges",
                        blob({
                            let inverted_routing_table = Arc::clone(&inverted_routing_table);
                            move || {
                                encode_subnet_canister_ranges(
                                    inverted_routing_table.get(&subnet_id),
                                )
                            }
                        }),
                    )
                    .with_if(subnet_id == own_subnet_id, "node", move || {
                        nodes_as_tree(own_subnet_node_public_keys, certification_version)
                    })
                    .with_tree_if(
                        subnet_id == own_subnet_id,
                        "metrics",
                        blob(move || encode_subnet_metrics(metrics, certification_version)),
                    ),
            )
        },
    })
}

fn canister_ranges_as_tree(
    subnets: &BTreeMap<SubnetId, SubnetTopology>,
    split_routing_table: Arc<SplitRoutingTable>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    let split_routing_table = Arc::clone(&split_routing_table);
    fork(MapTransformFork {
        map: subnets,
        map_filter: NoFilter,
        certification_version,
        mk_tree: move |subnet_id, _subnet_topology, _certification_version| {
            let split_ranges = split_routing_table.get(&subnet_id).map(Arc::clone);
            fork(CanisterRangesFork {
                split_ranges,
                phantom: PhantomData,
            })
        },
    })
}

fn nodes_as_tree(
    own_subnet_node_public_keys: &BTreeMap<NodeId, Vec<u8>>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: own_subnet_node_public_keys,
        map_filter: NoFilter,
        certification_version,
        mk_tree: |_node_id, public_key, _version| {
            fork(FiniteMap::default().with_tree("public_key", Blob(&public_key[..], None)))
        },
    })
}

fn canister_metadata_as_tree(
    execution_state: &ExecutionState,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: execution_state.metadata.custom_sections(),
        map_filter: NoFilter,
        certification_version,
        mk_tree: |_name, section, _version| Blob(section.content(), Some(section.hash())),
    })
}
