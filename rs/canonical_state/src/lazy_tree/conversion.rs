//! Conversion from `ReplicatedState` to `LazyTree`.

use super::{blob, fork, num, string, Lazy, LazyFork, LazyTree};
use crate::{
    encoding::{
        encode_controllers, encode_message, encode_metadata, encode_stream_header,
        encode_subnet_canister_ranges,
    },
    CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION,
};
use ic_crypto_tree_hash::Label;
use ic_error_types::RejectCode;
use ic_registry_routing_table::RoutingTable;
use ic_replicated_state::{
    canister_state::CanisterState,
    metadata_state::{IngressHistoryState, StreamMap, SubnetTopology, SystemMetadata},
    replicated_state::ReplicatedStateMessageRouting,
    ExecutionState, ReplicatedState,
};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{MessageId, EXPECTED_MESSAGE_ID_LENGTH},
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue},
    CanisterId, PrincipalId, SubnetId,
};
use std::collections::BTreeMap;
use std::convert::{AsRef, TryFrom, TryInto};
use std::sync::Arc;
use LazyTree::Blob;

/// A simple map from a label to a tree. It should be mostly used for static
/// subtrees where all the labels are known in advance.
#[derive(Default)]
struct FiniteMap<'a>(BTreeMap<Label, Lazy<'a, LazyTree<'a>>>);

impl<'a> FiniteMap<'a> {
    pub fn with<B, T>(mut self, blob: B, func: T) -> Self
    where
        B: AsRef<[u8]>,
        T: Fn() -> LazyTree<'a> + 'a,
    {
        self.0.insert(Label::from(blob), Lazy::Func(Arc::new(func)));
        self
    }

    /// Adds a subtree with the specified label to this map.
    pub fn with_tree<B: AsRef<[u8]>>(mut self, label: B, tree: LazyTree<'a>) -> Self {
        self.0.insert(Label::from(label), Lazy::Value(tree));
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
}

impl<'a> LazyFork<'a> for FiniteMap<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        self.0.get(label).map(|lazy| lazy.force())
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.0.keys().cloned())
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
        PrincipalId::from_label(label).map(|principal| Self::new(principal).unwrap())
    }
}

/// A type of fork that constructs a lazy tree view of a typed Map without
/// copying the underlying data.
#[derive(Clone)]
struct MapTransformFork<'a, K, V, F>
where
    F: Fn(K, &'a V, CertificationVersion) -> LazyTree<'a>,
{
    map: &'a BTreeMap<K, V>,
    certification_version: CertificationVersion,
    mk_tree: F,
}

impl<'a, K, V, F> LazyFork<'a> for MapTransformFork<'a, K, V, F>
where
    K: Ord + LabelLike,
    F: Fn(K, &'a V, CertificationVersion) -> LazyTree<'a>,
{
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let k = K::from_label(label.as_bytes())?;
        self.map
            .get(&k)
            .map(move |v| (self.mk_tree)(k, v, self.certification_version))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.map.keys().map(|l| l.to_label()))
    }
}

/// A special type of fork that describes a stream-indexed queue.
#[derive(Clone)]
struct StreamQueueFork<'a, T> {
    queue: &'a StreamIndexedQueue<T>,
    certification_version: CertificationVersion,
    mk_tree: fn(StreamIndex, &'a T, CertificationVersion) -> LazyTree<'a>,
}

impl<'a, T> LazyFork<'a> for StreamQueueFork<'a, T> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let idx = StreamIndex::from_label(label.as_bytes())?;
        self.queue
            .get(idx)
            .map(move |v| (self.mk_tree)(idx, v, self.certification_version))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new((self.queue.begin().get()..self.queue.end().get()).map(|i| i.to_label()))
    }
}

impl<'a> From<&'a ReplicatedState> for LazyTree<'a> {
    fn from(state: &'a ReplicatedState) -> LazyTree<'a> {
        state_as_tree(state)
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

/// Converts replicated state into a lazy tree.
fn state_as_tree(state: &ReplicatedState) -> LazyTree<'_> {
    let certification_version =
        CertificationVersion::try_from(state.metadata.certification_version).unwrap_or_else(|e| {
            panic!(
                "bug: this replica does not understand the current certification version: {}",
                e
            )
        });

    assert!(
        certification_version <= MAX_SUPPORTED_CERTIFICATION_VERSION,
        "Unable to certify state with version {:?}. Maximum supported certification version is {:?}",
        certification_version,
        MAX_SUPPORTED_CERTIFICATION_VERSION
    );

    fork(
        FiniteMap::default()
            .with("metadata", move || system_metadata_as_tree(&state.metadata))
            .with("streams", move || {
                streams_as_tree(state.streams(), certification_version)
            })
            .with("canister", move || {
                canisters_as_tree(&state.canister_states, certification_version)
            })
            .with_tree(
                "request_status",
                fork(IngressHistoryFork(&state.metadata.ingress_history)),
            )
            .with("subnet", move || {
                let inverted_routing_table = Arc::new(invert_routing_table(
                    &state.metadata.network_topology.routing_table,
                ));
                subnets_as_tree(
                    &state.metadata.network_topology.subnets,
                    inverted_routing_table,
                    certification_version,
                )
            })
            .with_tree(
                "time",
                num(state.metadata.batch_time.as_nanos_since_unix_epoch()),
            ),
    )
}

fn streams_as_tree(
    streams: &StreamMap,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: streams,
        certification_version,
        mk_tree: |_subnet_id, stream, certification_version| {
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
        },
    })
}

fn system_metadata_as_tree(m: &SystemMetadata) -> LazyTree<'_> {
    blob(move || encode_metadata(m))
}

struct IngressHistoryFork<'a>(&'a IngressHistoryState);

impl<'a> LazyFork<'a> for IngressHistoryFork<'a> {
    fn edge(&self, label: &Label) -> Option<LazyTree<'a>> {
        let byte_array: [u8; EXPECTED_MESSAGE_ID_LENGTH] = label.as_bytes().try_into().ok()?;
        let id = MessageId::from(byte_array);
        self.0.get(&id).map(status_to_tree)
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Label> + '_> {
        Box::new(self.0.statuses().map(|(id, _)| Label::from(id.as_bytes())))
    }
}

fn status_to_tree<'a>(status: &'a IngressStatus) -> LazyTree<'a> {
    let t = FiniteMap::default().with_tree("status", string(status.as_str()));

    let t = match status {
        IngressStatus::Known { state, .. } => match state {
            IngressState::Completed(WasmResult::Reply(b)) => t.with_tree("reply", Blob(&b[..])),
            IngressState::Completed(WasmResult::Reject(s)) => t
                .with_tree("reject_code", num::<'a>(RejectCode::CanisterReject as u64))
                .with_tree("reject_message", string(&s[..])),
            IngressState::Failed(error) => t
                .with_tree("reject_code", num::<'a>(error.reject_code() as u64))
                .with_tree("reject_message", string(error.description())),
            IngressState::Processing | IngressState::Received | IngressState::Done => t,
        },
        IngressStatus::Unknown => t,
    };
    fork(t)
}

fn canisters_as_tree(
    canisters: &BTreeMap<CanisterId, CanisterState>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: canisters,
        certification_version,
        mk_tree: |_canister_id, canister, certification_version| match &canister.execution_state {
            Some(execution_state) => fork(
                FiniteMap::default()
                    .with_tree(
                        "certified_data",
                        Blob(&canister.system_state.certified_data[..]),
                    )
                    .with_tree_if(
                        certification_version > CertificationVersion::V0,
                        "controller",
                        Blob(canister.system_state.controller().as_slice()),
                    )
                    .with_tree_if(
                        certification_version > CertificationVersion::V0,
                        "module_hash",
                        blob(move || execution_state.wasm_binary.binary.module_hash().to_vec()),
                    )
                    .with_tree_if(
                        certification_version > CertificationVersion::V1,
                        "controllers",
                        blob(move || encode_controllers(&canister.system_state.controllers)),
                    )
                    .with_tree_if(
                        certification_version > CertificationVersion::V5,
                        "metadata",
                        canister_metadata_as_tree(execution_state, certification_version),
                    ),
            ),
            None => fork(
                FiniteMap::default()
                    .with_tree_if(
                        certification_version > CertificationVersion::V0,
                        "controller",
                        Blob(canister.system_state.controller().as_slice()),
                    )
                    .with_tree_if(
                        certification_version > CertificationVersion::V1,
                        "controllers",
                        blob(move || encode_controllers(&canister.system_state.controllers)),
                    ),
            ),
        },
    })
}

fn subnets_as_tree(
    subnets: &BTreeMap<SubnetId, SubnetTopology>,
    inverted_routing_table: Arc<BTreeMap<SubnetId, Vec<(PrincipalId, PrincipalId)>>>,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: subnets,
        certification_version,
        mk_tree: move |subnet_id, subnet_topology, certification_version| {
            fork(
                FiniteMap::default()
                    .with_tree("public_key", Blob(&subnet_topology.public_key[..]))
                    .with_tree_if(
                        certification_version > CertificationVersion::V2,
                        "canister_ranges",
                        blob({
                            let inverted_routing_table = Arc::clone(&inverted_routing_table);
                            move || {
                                encode_subnet_canister_ranges(
                                    inverted_routing_table.get(&subnet_id),
                                )
                            }
                        }),
                    ),
            )
        },
    })
}

fn canister_metadata_as_tree(
    execution_state: &ExecutionState,
    certification_version: CertificationVersion,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: execution_state.metadata.custom_sections(),
        certification_version,
        mk_tree: |_name, section, _version| Blob(section.content.as_slice()),
    })
}
