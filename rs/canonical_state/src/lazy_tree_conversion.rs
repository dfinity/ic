//! Conversion from `ReplicatedState` to `LazyTree`.

use crate::{
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION, MIN_SUPPORTED_CERTIFICATION_VERSION,
    encoding::{
        encode_controllers, encode_message, encode_metadata, encode_stream_header,
        encode_subnet_canister_ranges, encode_subnet_metrics,
    },
};
use LazyTree::Blob;
use ic_canonical_state_tree_hash::{
    hash_tree::{HashTree, HashTreeError, hash_lazy_tree},
    lazy_tree::{
        Lazy, LazyFork, LazyTree, SubtreeExpander, SubtreeSource, blob, fork,
        materialize::materialize_partial, num, string,
    },
};
use ic_crypto_tree_hash::{Label, Witness, sparse_labeled_tree_from_paths};
use ic_error_types::ErrorCode;
use ic_error_types::RejectCode;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterStates, ExecutionState, ReplicatedState, Stream,
    canister_state::CanisterState,
    metadata_state::{
        ApiBoundaryNodeEntry, IngressHistoryState, StreamMap, SubnetMetrics, SubnetTopology,
        SystemMetadata,
    },
    replicated_state::ReplicatedStateMessageRouting,
};
use ic_types::{
    CanisterId, Height, NodeId, PrincipalId, SubnetId,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{EXPECTED_MESSAGE_ID_LENGTH, MessageId, Refund, Request, Response, StreamMessage},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue},
};
use ic_types_cycles::NominalCycles;
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
    F: Fn(&'a K, &'a V, CertificationVersion) -> LazyTree<'a>,
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
    F: Fn(&'a K, &'a V, CertificationVersion) -> LazyTree<'a> + Send + Sync,
{
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let k = K::from_label(label.as_bytes())?;
        if !self.map_filter.should_output(&k) {
            return None;
        }
        self.map
            .get_key_value(&k)
            .map(|(k, v)| (self.mk_tree)(k, v, self.certification_version))
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
                        (self.mk_tree)(k, v, self.certification_version),
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
    /// Produces a [`SubtreeSource`] for a child, to be used to create a reusable
    /// [stub](`NodeKind::Stub`). Stream messages' contents are immutable once
    /// enqueued, so the digest of any index present in a baseline can be reused.
    mk_source: fn(&'a T, CertificationVersion) -> SubtreeSource,
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

    fn stub_sources(&self) -> Option<Box<dyn Iterator<Item = (Label, SubtreeSource)> + '_>> {
        let mk_source = self.mk_source;
        let version = self.certification_version;
        Some(Box::new(self.queue.iter().map(move |(idx, v)| {
            (idx.to_label(), mk_source(v, version))
        })))
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
pub fn replicated_state_as_lazy_tree(state: &ReplicatedState, height: Height) -> LazyTree<'_> {
    let certification_version = state.metadata.certification_version;
    assert!(
        MIN_SUPPORTED_CERTIFICATION_VERSION <= certification_version
            && certification_version <= MAX_SUPPORTED_CERTIFICATION_VERSION,
        "Unable to certify state with version {certification_version:?}. Supported certification versions are {MIN_SUPPORTED_CERTIFICATION_VERSION:?}..={MAX_SUPPORTED_CERTIFICATION_VERSION:?}",
    );
    let own_subnet_id = state.metadata.own_subnet_id;
    let inverted_routing_table = Arc::new(invert_routing_table(
        state
            .metadata
            .network_topology
            .routing_table_for_certification(),
    ));
    let split_routing_table = Arc::new(split_inverted_routing_table(
        &inverted_routing_table,
        MAX_RANGES_PER_ROUTING_TABLE_LEAF,
    ));

    fork(
        FiniteMap::default()
            .with("api_boundary_nodes", move || {
                api_boundary_nodes_as_tree(
                    &state.metadata.network_topology.api_boundary_nodes,
                    certification_version,
                )
            })
            .with("metadata", move || {
                system_metadata_as_tree(&state.metadata, height, certification_version)
            })
            .with("streams", move || {
                streams_as_tree(state.streams(), own_subnet_id, certification_version)
            })
            .with("canister", move || {
                canisters_as_tree(state.canister_states(), certification_version)
            })
            .with_tree(
                "request_status",
                fork(IngressHistoryFork(&state.metadata.ingress_history)),
            )
            .with("subnet", move || {
                subnets_as_tree(
                    state.metadata.network_topology.subnets_for_certification(),
                    own_subnet_id,
                    &state.metadata.own_subnet_info.node_public_keys,
                    inverted_routing_table.clone(),
                    &state.metadata.subnet_metrics,
                    state.canister_states(),
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
                        state.metadata.network_topology.subnets_for_certification(),
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
                        mk_source: message_source,
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

/// Expands `$ty`/`$variant` to a 1-leaf [`HashTree`] (re-encoding the message
/// under the const certification version `V`), and a `select_*` helper that
/// picks the `V`-specific monomorphization — so the stored function pointer
/// alone fully determines the expansion. See [`message_source`].
macro_rules! message_expander {
    ($expand:ident, $select:ident, $ty:ty, $variant:path) => {
        fn $expand<const V: u32>(source: &SubtreeSource) -> Result<HashTree, HashTreeError> {
            let inner = source.downcast_arc::<$ty>();
            let version = CertificationVersion::try_from(V)
                .expect("const version parameter is a valid certification version");
            let msg = $variant(inner);
            hash_lazy_tree(&blob(move || encode_message(&msg, version)), None)
        }

        fn $select(version: CertificationVersion) -> SubtreeExpander {
            match version {
                CertificationVersion::V19 => $expand::<{ CertificationVersion::V19 as u32 }>,
                CertificationVersion::V20 => $expand::<{ CertificationVersion::V20 as u32 }>,
                CertificationVersion::V21 => $expand::<{ CertificationVersion::V21 as u32 }>,
                CertificationVersion::V22 => $expand::<{ CertificationVersion::V22 as u32 }>,
                CertificationVersion::V23 => $expand::<{ CertificationVersion::V23 as u32 }>,
                CertificationVersion::V24 => $expand::<{ CertificationVersion::V24 as u32 }>,
                CertificationVersion::V25 => $expand::<{ CertificationVersion::V25 as u32 }>,
                CertificationVersion::V26 => $expand::<{ CertificationVersion::V26 as u32 }>,
                CertificationVersion::V27 => $expand::<{ CertificationVersion::V27 as u32 }>,
                CertificationVersion::V28 => $expand::<{ CertificationVersion::V28 as u32 }>,
                CertificationVersion::V29 => $expand::<{ CertificationVersion::V29 as u32 }>,
            }
        }
    };
}

message_expander!(
    expand_request,
    select_request_expander,
    Request,
    StreamMessage::Request
);
message_expander!(
    expand_response,
    select_response_expander,
    Response,
    StreamMessage::Response
);
message_expander!(
    expand_refund,
    select_refund_expander,
    Refund,
    StreamMessage::Refund
);

/// Produces a [`SubtreeSource`] for a stream message, identified by its backing
/// `Arc<Request|Response|Refund>`, used to create a reusable
/// [stub](`NodeKind::Stub`).
///
/// A message's contents never change once enqueued, so any index present in a
/// baseline keeps the same `Arc` and its precomputed digest can be reused; only
/// newly enqueued messages must be encoded and hashed.
fn message_source(msg: &StreamMessage, version: CertificationVersion) -> SubtreeSource {
    match msg {
        StreamMessage::Request(req) => SubtreeSource::new(req, select_request_expander(version)),
        StreamMessage::Response(resp) => {
            SubtreeSource::new(resp, select_response_expander(version))
        }
        StreamMessage::Refund(refund) => {
            SubtreeSource::new(refund, select_refund_expander(version))
        }
    }
}

const HEIGHT_LABEL: &[u8] = b"height";
const PREV_STATE_HASH_LABEL: &[u8] = b"prev_state_hash";

const METADATA_LABELS: [&[u8]; 2] = [HEIGHT_LABEL, PREV_STATE_HASH_LABEL];

#[derive(Clone)]
struct MetadataFork<'a> {
    height: Height,
    metadata: &'a SystemMetadata,
}

impl<'a> LazyFork<'a> for MetadataFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        match label.as_bytes() {
            HEIGHT_LABEL => Some(num(self.height.get())),
            PREV_STATE_HASH_LABEL => self
                .metadata
                .prev_state_hash
                .as_ref()
                .map(|hash| Blob(hash.as_ref().0.as_slice(), None)),
            _ => None,
        }
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        let fork = self.clone();
        Box::new(
            METADATA_LABELS
                .iter()
                .filter(move |label| fork.edge(&Label::from(label)).is_some())
                .map(From::from),
        )
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        let fork = self.clone();
        Box::new(METADATA_LABELS.iter().filter_map(move |label| {
            let label = Label::from(label);
            let edge = fork.edge(&label)?;
            Some((label, edge))
        }))
    }

    fn len(&self) -> usize {
        self.labels().count()
    }
}

fn system_metadata_as_tree(
    metadata: &SystemMetadata,
    height: Height,
    version: CertificationVersion,
) -> LazyTree<'_> {
    if version >= CertificationVersion::V24 {
        fork(MetadataFork { height, metadata })
    } else {
        blob(move || encode_metadata(metadata, version))
    }
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

    /// Collapse ingress messages into reusable stubs identified by their respective
    /// `Arc<IngressStatus>`.
    fn stub_sources(&self) -> Option<Box<dyn Iterator<Item = (Label, SubtreeSource)> + '_>> {
        Some(Box::new(self.0.statuses_arc().map(|(id, status)| {
            (
                Label::from(id.as_bytes()),
                SubtreeSource::new(status, expand_ingress_status),
            )
        })))
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
    error_code: ErrorCode,
    message: &'a str,
}

impl<'a> LazyFork<'a> for RejectStatus<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        match label.as_bytes() {
            ERROR_CODE_LABEL => {
                let error_code = self.error_code;
                Some(blob(move || error_code.to_string().into_bytes()))
            }
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

/// Produces one of a few small, focused [`LazyFork`] shapes (reply / reject /
/// status-only) for the given [`IngressStatus`].
fn status_to_tree(status: &IngressStatus) -> LazyTree<'_> {
    match status {
        IngressStatus::Known { state, .. } => match state {
            IngressState::Completed(WasmResult::Reply(b)) => fork(ReplyStatus(b)),
            IngressState::Completed(WasmResult::Reject(s)) => fork(RejectStatus {
                reject_code: RejectCode::CanisterReject as u64,
                error_code: ErrorCode::CanisterRejectedMessage,
                message: s,
            }),
            IngressState::Failed(error) => fork(RejectStatus {
                reject_code: error.reject_code() as u64,
                error_code: error.code(),
                message: error.description(),
            }),
            IngressState::Processing | IngressState::Received | IngressState::Done => {
                fork(OnlyStatus(status.as_str()))
            }
        },
        IngressStatus::Unknown => fork(OnlyStatus(status.as_str())),
    }
}

/// Materializes a stubbed ingress message's [`HashTree`], by recovering the
/// `&IngressStatus` from the stub's [`SubtreeSource`].
fn expand_ingress_status(source: &SubtreeSource) -> Result<HashTree, HashTreeError> {
    let status = source.downcast::<IngressStatus>();
    hash_lazy_tree(&status_to_tree(status), None)
}

const CERTIFIED_DATA_LABEL: &[u8] = b"certified_data";
const CONTROLLERS_LABEL: &[u8] = b"controllers";
const METADATA_LABEL: &[u8] = b"metadata";
const MODULE_HASH_LABEL: &[u8] = b"module_hash";
const LAST_INSTALL_TIMESTAMP_LABEL: &[u8] = b"last_install_timestamp";
const CANISTER_CREATION_TIMESTAMP_LABEL: &[u8] = b"canister_creation_timestamp";

#[derive(Clone)]
struct CanisterFork<'a> {
    canister: &'a CanisterState,
    version: CertificationVersion,
}

impl<'a> CanisterFork<'a> {
    /// Like `edge`, but assumes valid labels only.
    fn edge_no_checks(&self, label: &[u8]) -> LazyTree<'a> {
        let canister = self.canister;
        // The `canister_creation_timestamp` leaf is exposed for every canister
        // (with or without installed code); it lives on the system state.
        if label == CANISTER_CREATION_TIMESTAMP_LABEL {
            let timestamp = canister
                .system_state
                .canister_creation_timestamp
                .expect("canister_creation_timestamp leaf present without a value");
            return num(timestamp.as_nanos_since_unix_epoch());
        }
        match canister.execution_state.as_ref() {
            Some(execution_state) => match label {
                CERTIFIED_DATA_LABEL => Blob(canister.system_state.certified_data.as_slice(), None),
                CONTROLLERS_LABEL => {
                    blob(move || encode_controllers(&canister.system_state.controllers))
                }
                METADATA_LABEL => canister_metadata_as_tree(execution_state, self.version),
                MODULE_HASH_LABEL => {
                    Blob(execution_state.wasm_binary.binary.module_hash_ref(), None)
                }
                LAST_INSTALL_TIMESTAMP_LABEL => {
                    let timestamp = execution_state
                        .last_install_timestamp
                        .expect("last_install_timestamp leaf present without a value");
                    num(timestamp.as_nanos_since_unix_epoch())
                }
                _ => unreachable!(),
            },
            None => match label {
                CONTROLLERS_LABEL => {
                    blob(move || encode_controllers(&canister.system_state.controllers))
                }
                _ => unreachable!(),
            },
        }
    }

    /// Returns the labels applicable to this canister, in sorted order.
    fn valid_labels(&self) -> Vec<&'static [u8]> {
        let mut labels: Vec<&'static [u8]> = if self.canister.execution_state.is_some() {
            vec![
                CERTIFIED_DATA_LABEL,
                CONTROLLERS_LABEL,
                METADATA_LABEL,
                MODULE_HASH_LABEL,
            ]
        } else {
            vec![CONTROLLERS_LABEL]
        };
        // The `last_install_timestamp` leaf is only exposed from certification
        // version `V27` onwards, and only when the execution state has a recorded
        // install timestamp. It is therefore omitted for canisters with no
        // installed code and for code installed before the field existed.
        if self.version >= CertificationVersion::V27
            && self
                .canister
                .execution_state
                .as_ref()
                .is_some_and(|execution_state| execution_state.last_install_timestamp.is_some())
        {
            labels.push(LAST_INSTALL_TIMESTAMP_LABEL);
        }
        // The `canister_creation_timestamp` leaf is exposed from certification
        // version `V28` onwards for every canister (with or without installed
        // code) that has a recorded creation timestamp. It is omitted for
        // canisters created before the field existed.
        if self.version >= CertificationVersion::V28
            && self
                .canister
                .system_state
                .canister_creation_timestamp
                .is_some()
        {
            labels.push(CANISTER_CREATION_TIMESTAMP_LABEL);
        }
        labels.sort_unstable();
        labels
    }
}

impl<'a> LazyFork<'a> for CanisterFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        self.valid_labels()
            .iter()
            .find(|l| *l == &label.as_bytes())?;
        Some(self.edge_no_checks(label.as_bytes()))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + 'a> {
        Box::new(self.valid_labels().into_iter().map(Label::from))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + 'a> {
        let canister = self.clone();
        Box::new(
            self.valid_labels()
                .into_iter()
                .map(move |label| (Label::from(label), canister.edge_no_checks(label))),
        )
    }

    fn len(&self) -> usize {
        self.valid_labels().len()
    }
}

/// Rebuilds a canister's stubbed [subtree](`NodeKind::Stub`) for witness
/// generation, by recovering the `&CanisterState` from the stub's
/// [`SubtreeSource`] and traversing its [`CanisterFork`].
///
/// The certification version (which the canonical encoding depends on) is baked
/// in as the const parameter `V`, so the stored function pointer alone fully
/// determines the expansion — see [`select_canister_expander`].
fn expand_canister<const V: u32>(source: &SubtreeSource) -> Result<HashTree, HashTreeError> {
    let canister = source.downcast::<CanisterState>();
    let version = CertificationVersion::try_from(V)
        .expect("const version parameter is a valid certification version");
    hash_lazy_tree(&fork(CanisterFork { canister, version }), None)
}

/// Selects the [`expand_canister`] monomorphization for `version`, so the
/// resulting [`SubtreeExpander`] function pointer carries the version with it
/// (rather than replicating it in every stub).
fn select_canister_expander(version: CertificationVersion) -> SubtreeExpander {
    match version {
        CertificationVersion::V19 => expand_canister::<{ CertificationVersion::V19 as u32 }>,
        CertificationVersion::V20 => expand_canister::<{ CertificationVersion::V20 as u32 }>,
        CertificationVersion::V21 => expand_canister::<{ CertificationVersion::V21 as u32 }>,
        CertificationVersion::V22 => expand_canister::<{ CertificationVersion::V22 as u32 }>,
        CertificationVersion::V23 => expand_canister::<{ CertificationVersion::V23 as u32 }>,
        CertificationVersion::V24 => expand_canister::<{ CertificationVersion::V24 as u32 }>,
        CertificationVersion::V25 => expand_canister::<{ CertificationVersion::V25 as u32 }>,
        CertificationVersion::V26 => expand_canister::<{ CertificationVersion::V26 as u32 }>,
        CertificationVersion::V27 => expand_canister::<{ CertificationVersion::V27 as u32 }>,
        CertificationVersion::V28 => expand_canister::<{ CertificationVersion::V28 as u32 }>,
        CertificationVersion::V29 => expand_canister::<{ CertificationVersion::V29 as u32 }>,
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
    canisters: &CanisterStates,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(CanisterStatesFork {
        canisters,
        certification_version,
    })
}

/// A `LazyFork` view of a [`CanisterStates`].
///
/// Iterates over the merged hot+cold pools in `CanisterId` order, producing the
/// same `LazyTree` shape that a plain `BTreeMap` + `MapTransformFork` would.
#[derive(Clone)]
struct CanisterStatesFork<'a> {
    canisters: &'a CanisterStates,
    certification_version: CertificationVersion,
}

impl<'a> LazyFork<'a> for CanisterStatesFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let k = CanisterId::from_label(label.as_bytes())?;
        self.canisters.get(&k).map(|canister| {
            fork(CanisterFork {
                canister,
                version: self.certification_version,
            })
        })
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.canisters.all_keys().map(|k| k.to_label()))
    }

    fn children(&self) -> Box<dyn Iterator<Item = (Label, LazyTree<'a>)> + '_> {
        let version = self.certification_version;
        Box::new(
            self.canisters
                .all_iter()
                .map(move |(k, canister)| (k.to_label(), fork(CanisterFork { canister, version }))),
        )
    }

    fn len(&self) -> usize {
        self.canisters.len()
    }

    /// Every canister's certified subtree is stored as a reusable stub identified
    /// by the backing `Arc<CanisterState>` and the version-specific expander. An
    /// unchanged canister keeps the same `Arc` (copy-on-write) and the same
    /// expander, so its precomputed digest is reused from the baseline; any
    /// mutation or version change yields a mismatched [`SubtreeSource`] and a
    /// rebuild.
    fn stub_sources(&self) -> Option<Box<dyn Iterator<Item = (Label, SubtreeSource)> + '_>> {
        let expander = select_canister_expander(self.certification_version);
        Some(Box::new(self.canisters.all_iter().map(
            move |(k, canister)| (k.to_label(), SubtreeSource::new(canister, expander)),
        )))
    }
}

fn subnets_as_tree<'a>(
    subnets: &'a BTreeMap<SubnetId, SubnetTopology>,
    own_subnet_id: SubnetId,
    own_subnet_node_public_keys: &'a BTreeMap<NodeId, Vec<u8>>,
    inverted_routing_table: Arc<BTreeMap<SubnetId, Vec<(PrincipalId, PrincipalId)>>>,
    metrics: &'a SubnetMetrics,
    canisters: &'a CanisterStates,
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
                                encode_subnet_canister_ranges(inverted_routing_table.get(subnet_id))
                            }
                        }),
                    )
                    .with_if(subnet_id == &own_subnet_id, "node", move || {
                        nodes_as_tree(own_subnet_node_public_keys, certification_version)
                    })
                    .with_tree_if(
                        subnet_id == &own_subnet_id,
                        "metrics",
                        blob(move || {
                            // Starting with `V29`, the reported total also
                            // includes the cycles consumed by all non-deleted
                            // canisters. `total_consumed_cycles` is
                            // `O(|hot canisters|)` thanks to the precomputed
                            // cold-pool aggregate; only compute it when needed.
                            let consumed_cycles_by_canisters =
                                if certification_version >= CertificationVersion::V29 {
                                    canisters.total_consumed_cycles()
                                } else {
                                    NominalCycles::zero()
                                };
                            encode_subnet_metrics(
                                metrics,
                                consumed_cycles_by_canisters,
                                certification_version,
                            )
                        }),
                    )
                    .with_tree_if(
                        certification_version >= CertificationVersion::V25,
                        "type",
                        string(subnet_type_as_string(subnet_topology.subnet_type)),
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
            let split_ranges = split_routing_table.get(subnet_id).map(Arc::clone);
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

/// Helper function to turn a subnet type into a string.
/// This is intentionally explicitly implemented here, so that the state tree representation cannot be changed outside this crate, as opposed
/// to calling something like `subnet_type.to_string()`.
pub fn subnet_type_as_string(subnet_type: SubnetType) -> &'static str {
    match subnet_type {
        SubnetType::Application => "application",
        SubnetType::System => "system",
        SubnetType::VerifiedApplication => "verified_application",
        SubnetType::CloudEngine => "cloud_engine",
    }
}

pub fn state_height_as_tree(height: &Height) -> LazyTree<'_> {
    let metadata_lazy_tree = fork(FiniteMap::default().with_tree(HEIGHT_LABEL, num(height.get())));
    fork(FiniteMap::default().with_tree(METADATA_LABEL, metadata_lazy_tree))
}

pub fn compute_state_height_witness(lazy_tree: &LazyTree, hash_tree: &HashTree) -> Witness {
    let paths = vec![vec![METADATA_LABEL.into(), HEIGHT_LABEL.into()].into()];
    let labeled_tree =
        sparse_labeled_tree_from_paths(&paths).expect("Failed to compute labeled tree for height");
    let partial_tree = materialize_partial(lazy_tree, &labeled_tree, None);
    hash_tree
        .witness::<Witness>(&partial_tree)
        .expect("Failed to compute witness for state height")
}
