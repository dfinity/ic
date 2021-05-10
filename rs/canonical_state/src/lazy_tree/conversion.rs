//! Conversion from `ReplicatedState` to `LazyTree`.

use super::{blob, fork, num, string, Lazy, LazyFork, LazyTree};
use crate::encoding::{encode_message, encode_metadata, encode_stream_header};
use ic_replicated_state::{
    canister_state::{CanisterState, Global},
    metadata_state::{IngressHistoryState, Streams, SubnetTopology, SystemMetadata},
    page_map::{PageIndex, PageMap},
    ReplicatedState,
};
use ic_types::{
    ingress::{IngressStatus, WasmResult},
    messages::{MessageId, EXPECTED_MESSAGE_ID_LENGTH},
    user_error::RejectCode,
    xnet::{StreamHeader, StreamIndex, StreamIndexedQueue},
    CanisterId, PrincipalId, SubnetId,
};
use std::collections::BTreeMap;
use std::convert::{AsRef, TryInto};
use std::sync::Arc;
use LazyTree::Blob;

/// Converts a value into a byte vector.
fn to_blob<B: AsRef<[u8]>>(b: B) -> Vec<u8> {
    b.as_ref().to_vec()
}

/// A simple map from a label to a tree. It should be mostly used for static
/// subtrees where all the labels are known in advance.
#[derive(Default)]
struct FiniteMap<'a>(BTreeMap<Vec<u8>, Lazy<'a, LazyTree<'a>>>);

impl<'a> FiniteMap<'a> {
    pub fn with<B, T>(mut self, blob: B, func: T) -> Self
    where
        B: AsRef<[u8]>,
        T: Fn() -> LazyTree<'a> + 'a,
    {
        self.0.insert(to_blob(blob), Lazy::Func(Arc::new(func)));
        self
    }

    pub fn with_tree<B: AsRef<[u8]>>(mut self, blob: B, tree: LazyTree<'a>) -> Self {
        self.0.insert(to_blob(blob), Lazy::Value(tree));
        self
    }
}

impl<'a> LazyFork<'a> for FiniteMap<'a> {
    fn edge(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        self.0.get(label).map(|lazy| lazy.force())
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new(self.0.keys().map(|l| l.to_vec()))
    }
}

/// A special type of fork that doesn't have any children.
struct EmptyFork;
impl<'a> LazyFork<'a> for EmptyFork {
    fn edge(&self, _label: &[u8]) -> Option<LazyTree<'a>> {
        None
    }
    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new(std::iter::empty::<Vec<u8>>())
    }
}

/// LabelLike defines a (partial) conversion between a type and a label.
pub trait LabelLike: Sized {
    fn to_label(&self) -> Vec<u8>;
    fn from_label(label: &[u8]) -> Option<Self>;
}

impl LabelLike for u64 {
    fn to_label(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        if label.len() != 8 {
            return None;
        }
        let be_bytes: [u8; 8] = label.try_into().ok()?;
        Some(u64::from_be_bytes(be_bytes))
    }
}

impl<T: LabelLike, Tag> LabelLike for phantom_newtype::Id<Tag, T> {
    fn to_label(&self) -> Vec<u8> {
        self.get_ref().to_label()
    }
    fn from_label(label: &[u8]) -> Option<Self> {
        T::from_label(label).map(Self::new)
    }
}

impl<T: LabelLike + Copy, Tag> LabelLike for phantom_newtype::AmountOf<Tag, T> {
    fn to_label(&self) -> Vec<u8> {
        self.get().to_label()
    }
    fn from_label(label: &[u8]) -> Option<Self> {
        T::from_label(label).map(Self::new)
    }
}

impl LabelLike for PrincipalId {
    fn to_label(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        use std::convert::TryFrom;
        PrincipalId::try_from(label).ok()
    }
}

impl LabelLike for CanisterId {
    fn to_label(&self) -> Vec<u8> {
        self.get_ref().to_label()
    }

    fn from_label(label: &[u8]) -> Option<Self> {
        PrincipalId::from_label(label).map(|principal| Self::new(principal).unwrap())
    }
}

/// A type of fork that constructs a lazy tree view of a typed Map without
/// copying the underlying data.
#[derive(Clone)]
struct MapTransformFork<'a, K, V> {
    map: &'a BTreeMap<K, V>,
    certification_version: u32,
    mk_tree: fn(K, &'a V, u32) -> LazyTree<'a>,
}

impl<'a, K, V> LazyFork<'a> for MapTransformFork<'a, K, V>
where
    K: Ord + LabelLike,
{
    fn edge(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        let k = K::from_label(label)?;
        self.map
            .get(&k)
            .map(move |v| (self.mk_tree)(k, v, self.certification_version))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new(self.map.keys().map(|l| l.to_label()))
    }
}

/// A special type of fork that describes a stream-indexed queue.
#[derive(Clone)]
struct StreamQueueFork<'a, T> {
    queue: &'a StreamIndexedQueue<T>,
    mk_tree: fn(StreamIndex, &'a T) -> LazyTree<'a>,
}

impl<'a, T> LazyFork<'a> for StreamQueueFork<'a, T> {
    fn edge(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        let idx = StreamIndex::from_label(label)?;
        self.queue.get(idx).map(move |v| (self.mk_tree)(idx, v))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new((self.queue.begin().get()..self.queue.end().get()).map(|i| i.to_label()))
    }
}

/// A special type of fork that describes a page map, i.e. memory pages of a
/// canister.
struct PageMapFork<'a> {
    map: &'a PageMap,
}

impl<'a> LazyFork<'a> for PageMapFork<'a> {
    fn edge(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        let idx = u64::from_label(label)?;
        if self.map.num_host_pages() < idx as usize {
            return None;
        }
        Some(Blob(self.map.get_page(PageIndex::from(idx))))
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new((0..self.map.num_host_pages()).map(|n| (n as u64).to_label()))
    }
}

impl<'a> From<&'a ReplicatedState> for LazyTree<'a> {
    fn from(state: &'a ReplicatedState) -> LazyTree<'a> {
        state_as_tree(state)
    }
}

/// Converts replicated state into a lazy tree.
fn state_as_tree(state: &ReplicatedState) -> LazyTree<'_> {
    let certification_version = state.metadata.certification_version;
    fork(
        FiniteMap::default()
            .with("metadata", move || metadata_as_tree(&state.metadata))
            .with("streams", move || {
                streams_as_tree(&*state.metadata.streams, certification_version)
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
                    certification_version,
                )
            })
            .with_tree(
                "time",
                num(state.metadata.batch_time.as_nanos_since_unix_epoch()),
            ),
    )
}

fn streams_as_tree(streams: &Streams, certification_version: u32) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: &*streams,
        certification_version,
        mk_tree: |_subnet_id, stream, _certification_version| {
            fork(
                FiniteMap::default()
                    .with_tree(
                        "header",
                        blob(move || {
                            let stream_header: StreamHeader = stream.header();
                            encode_stream_header(&stream_header)
                        }),
                    )
                    .with_tree(
                        "messages",
                        fork(StreamQueueFork {
                            queue: &stream.messages,
                            mk_tree: |_idx, msg| blob(move || encode_message(msg)),
                        }),
                    ),
            )
        },
    })
}

fn metadata_as_tree(m: &SystemMetadata) -> LazyTree<'_> {
    blob(move || encode_metadata(m))
}

struct IngressHistoryFork<'a>(&'a IngressHistoryState);

impl<'a> LazyFork<'a> for IngressHistoryFork<'a> {
    fn edge(&self, label: &[u8]) -> Option<LazyTree<'a>> {
        let byte_array: [u8; EXPECTED_MESSAGE_ID_LENGTH] = label.try_into().ok()?;
        let id = MessageId::from(byte_array);
        self.0.get(&id).map(status_to_tree)
    }

    fn labels(&self) -> Box<dyn Iterator<Item = Vec<u8>> + '_> {
        Box::new(self.0.statuses().map(|(id, _)| id.as_bytes().to_vec()))
    }
}

fn status_to_tree<'a>(status: &'a IngressStatus) -> LazyTree<'a> {
    let t = FiniteMap::default().with_tree("status", string(status.as_str()));

    let t = match status {
        IngressStatus::Completed {
            result: WasmResult::Reply(b),
            ..
        } => t.with_tree("reply", Blob(&b[..])),
        IngressStatus::Completed {
            result: WasmResult::Reject(s),
            ..
        } => t
            .with_tree("reject_code", num::<'a>(RejectCode::CanisterReject as u64))
            .with_tree("reject_message", string(&s[..])),
        IngressStatus::Failed { error, .. } => t
            .with_tree("reject_code", num::<'a>(error.reject_code() as u64))
            .with_tree("reject_message", string(error.description())),
        IngressStatus::Processing { .. }
        | IngressStatus::Received { .. }
        | IngressStatus::Unknown => t,
    };

    fork(t)
}

fn canisters_as_tree(
    canisters: &BTreeMap<CanisterId, CanisterState>,
    certification_version: u32,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: canisters,
        certification_version,
        mk_tree: |_canister_id, canister, certification_version| match &canister.execution_state {
            Some(execution_state) => {
                let mut map = FiniteMap::default()
                    .with_tree(
                        "certified_data",
                        Blob(&canister.system_state.certified_data[..]),
                    )
                    .with_tree(
                        "wasm_state",
                        fork(
                            FiniteMap::default()
                                .with_tree(
                                    "globals",
                                    blob(move || {
                                        raw_globals(&execution_state.exported_globals[..])
                                    }),
                                )
                                .with_tree("module", Blob(execution_state.wasm_binary.as_slice()))
                                .with("memory", move || {
                                    fork(FiniteMap::default().with("0", move || {
                                        fork(
                                            FiniteMap::default()
                                                .with_tree(
                                                    "usage",
                                                    num(execution_state.heap_size.get() as u64),
                                                )
                                                .with_tree(
                                                    "pages",
                                                    fork(PageMapFork {
                                                        map: &execution_state.page_map,
                                                    }),
                                                ),
                                        )
                                    }))
                                }),
                        ),
                    );

                if certification_version > 0 {
                    map = map
                        .with_tree(
                            "controller",
                            Blob(canister.system_state.controller.as_slice()),
                        )
                        .with_tree(
                            "module_hash",
                            blob(move || execution_state.wasm_binary.hash_sha256().to_vec()),
                        );
                }

                fork(map)
            }
            None => {
                if certification_version > 0 {
                    fork(FiniteMap::default().with_tree(
                        "controller",
                        Blob(&canister.system_state.controller.as_slice()[..]),
                    ))
                } else {
                    fork(EmptyFork)
                }
            }
        },
    })
}

fn subnets_as_tree(
    subnets: &BTreeMap<SubnetId, SubnetTopology>,
    certification_version: u32,
) -> LazyTree<'_> {
    fork(MapTransformFork {
        map: subnets,
        certification_version,
        mk_tree: |_subnet_id, subnet_topology, _certification_version| {
            fork(
                FiniteMap::default().with_tree("public_key", Blob(&subnet_topology.public_key[..])),
            )
        },
    })
}

/// Serializes globals into a flat byte array.  All globals are
/// converted into u64 and encoded using Little-Endian encoding because
/// it's more natural for Wasm than Big-Endian.
fn raw_globals(typed_globals: &[Global]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(typed_globals.len() * std::mem::size_of::<u64>());
    for g in typed_globals.iter() {
        match g {
            Global::I32(n) => raw.extend_from_slice(&((*n as u64).to_le_bytes())[..]),
            Global::I64(n) => raw.extend_from_slice(&((*n as u64).to_le_bytes())[..]),
            Global::F32(n) => raw.extend_from_slice(&((*n as f64).to_le_bytes())[..]),
            Global::F64(n) => raw.extend_from_slice(&((*n as f64).to_le_bytes())[..]),
        }
    }
    raw
}
