use crate::lazy_tree::LazyTree;
use crate::visitor::{Control, Visitor};
use ic_replicated_state::ReplicatedState;

/// Traverses lazy tree using specified visitor.
fn traverse_lazy_tree<'a, V: Visitor>(t: &LazyTree<'a>, v: &mut V) -> Result<(), V::Output> {
    match t {
        LazyTree::Blob(b) => v.visit_blob(b),
        LazyTree::LazyBlob(thunk) => {
            let b = thunk();
            v.visit_blob(&b)
        }
        LazyTree::LazyFork(f) => {
            v.start_subtree()?;
            for l in f.labels() {
                match v.enter_edge(&l[..])? {
                    Control::Skip => continue,
                    Control::Continue => {
                        let t = f.edge(&l).expect("fork edge disappeared");
                        traverse_lazy_tree(&t, v)?;
                    }
                }
            }
            v.end_subtree()
        }
    }
}

/// Traverses `state` as if it was a state in canonical form using visitor `v`.
///
/// By supplying different visitors, one can use `traverse` to serialize the
/// `state` for transmitting it over the network to another replica, compute a
/// hash tree for certification or extract a specific value.
pub fn traverse<V: Visitor>(state: &ReplicatedState, mut v: V) -> V::Output {
    let t = LazyTree::from(state);
    match traverse_lazy_tree(&t, &mut v) {
        Err(output) => output,
        _ => v.finish(),
    }
}

/// Traverses `state` partially (Wasm state excluded).
/// It's used for quick certification that can be done every round.
pub fn traverse_partial<V: Visitor>(state: &ReplicatedState, v: V) -> V::Output {
    use crate::subtree_visitor::{Pattern as P, SubtreeVisitor};

    let pattern = P::match_any(
        vec![
            (
                "canister",
                P::any(P::match_any(
                    vec![
                        ("certified_data", P::all()),
                        ("controller", P::all()),
                        ("module_hash", P::all()),
                    ]
                    .into_iter(),
                )),
            ),
            ("metadata", P::all()),
            ("request_status", P::all()),
            ("subnet", P::all()),
            ("streams", P::all()),
            ("time", P::all()),
        ]
        .into_iter(),
    );
    let subtree_visitor = SubtreeVisitor::new(&pattern, v);
    traverse(state, subtree_visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::{encode_stream_header, types::SystemMetadata, CborProxyEncoder},
        test_visitors::{NoopVisitor, TraceEntry as E, TracingVisitor},
    };
    use ic_base_types::NumSeconds;
    use ic_cow_state::CowMemoryManagerImpl;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        canister_state::{ExecutionState, ExportedFunctions, Global, NumWasmPages},
        metadata_state::SubnetTopology,
        page_map::{PageDelta, PageIndex, PageMap, PAGE_SIZE},
    };
    use ic_test_utilities::{
        mock_time,
        state::new_canister_state,
        types::ids::{canister_test_id, subnet_test_id, user_test_id},
    };
    use ic_types::{Cycles, ExecutionRound};
    use ic_wasm_types::BinaryEncodedWasm;
    use maplit::btreemap;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    fn edge<L: AsRef<[u8]>>(label: L) -> E {
        E::EnterEdge(label.as_ref().to_vec())
    }

    fn leb_num(n: u64) -> E {
        let mut buf = Vec::new();
        leb128::write::unsigned(&mut buf, n).unwrap();
        E::VisitBlob(buf)
    }

    fn encode_metadata(metadata: SystemMetadata) -> Vec<u8> {
        SystemMetadata::proxy_encode(metadata).unwrap()
    }

    #[test]
    fn test_traverse_empty_state() {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_canister_empty_execution_state() {
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        state.put_canister_state(canister_state);

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree, // global
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );

        // Test new certification version.
        state.metadata.certification_version = 1;
        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree, // global
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("controller"),
                E::VisitBlob(controller.get().to_vec()),
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_canister_with_pages() {
        let page0 = vec![0u8; *PAGE_SIZE];
        let page1 = vec![1u8; *PAGE_SIZE];
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let mut canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let mut page_map = PageMap::default();
        page_map.update(PageDelta::from(&[(PageIndex::from(1), &page1[..])][..]));
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let wasm_binary = BinaryEncodedWasm::new(vec![]);
        let wasm_binary_hash = wasm_binary.hash_sha256();
        let execution_state = ExecutionState {
            canister_root: "NOT_USED".into(),
            session_nonce: None,
            wasm_binary,
            page_map,
            exported_globals: vec![Global::I32(1)],
            heap_size: NumWasmPages::from(2),
            exports: ExportedFunctions::new(BTreeSet::new()),
            embedder_cache: None,
            last_executed_round: ExecutionRound::from(0),
            cow_mem_mgr: Arc::new(CowMemoryManagerImpl::open_readwrite(tmpdir.path().into())),
            mapped_state: None,
        };
        canister_state.execution_state = Some(execution_state);

        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        state.put_canister_state(canister_state);

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("certified_data"),
                E::VisitBlob(vec![]),
                edge("wasm_state"),
                E::StartSubtree,
                edge("globals"),
                E::VisitBlob(vec![1, 0, 0, 0, 0, 0, 0, 0]),
                edge("memory"),
                E::StartSubtree,
                edge("0"),
                E::StartSubtree,
                edge("pages"),
                E::StartSubtree,
                edge(&[0, 0, 0, 0, 0, 0, 0, 0]),
                E::VisitBlob(page0.clone()),
                edge(&[0, 0, 0, 0, 0, 0, 0, 1]),
                E::VisitBlob(page1.clone()),
                E::EndSubtree, // pages
                edge("usage"),
                leb_num(2),
                E::EndSubtree, // 0
                E::EndSubtree, // memory
                edge("module"),
                E::VisitBlob(vec![]),
                E::EndSubtree, // wasm_state
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, //global
            ],
            traverse(&state, visitor).0
        );

        // Test new certification version
        state.metadata.certification_version = 1;
        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("certified_data"),
                E::VisitBlob(vec![]),
                edge("controller"),
                E::VisitBlob(controller.get().to_vec()),
                edge("module_hash"),
                E::VisitBlob(wasm_binary_hash.to_vec()),
                edge("wasm_state"),
                E::StartSubtree,
                edge("globals"),
                E::VisitBlob(vec![1, 0, 0, 0, 0, 0, 0, 0]),
                edge("memory"),
                E::StartSubtree,
                edge("0"),
                E::StartSubtree,
                edge("pages"),
                E::StartSubtree,
                edge(&[0, 0, 0, 0, 0, 0, 0, 0]),
                E::VisitBlob(page0),
                edge(&[0, 0, 0, 0, 0, 0, 0, 1]),
                E::VisitBlob(page1),
                E::EndSubtree, // pages
                edge("usage"),
                leb_num(2),
                E::EndSubtree, // 0
                E::EndSubtree, // memory
                edge("module"),
                E::VisitBlob(vec![]),
                E::EndSubtree, // wasm_state
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, //global
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_partial_canister_empty_execution_state() {
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        state.put_canister_state(canister_state);

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree, // global
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse_partial(&state, visitor).0
        );

        // Test new certification version.
        state.metadata.certification_version = 1;
        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree, // global
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("controller"),
                E::VisitBlob(controller.get().to_vec()),
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse_partial(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_partial_canister_with_execution_state() {
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let mut canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let wasm_binary = BinaryEncodedWasm::new(vec![]);
        let wasm_binary_hash = wasm_binary.hash_sha256();
        let execution_state = ExecutionState {
            canister_root: "NOT_USED".into(),
            session_nonce: None,
            wasm_binary,
            page_map: PageMap::default(),
            exported_globals: vec![Global::I32(1)],
            heap_size: NumWasmPages::from(2),
            exports: ExportedFunctions::new(BTreeSet::new()),
            embedder_cache: None,
            last_executed_round: ExecutionRound::from(0),
            cow_mem_mgr: Arc::new(CowMemoryManagerImpl::open_readwrite(tmpdir.path().into())),
            mapped_state: None,
        };
        canister_state.execution_state = Some(execution_state);

        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        state.put_canister_state(canister_state);

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("certified_data"),
                E::VisitBlob(vec![]),
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, //global
            ],
            traverse_partial(&state, visitor).0
        );

        // Test new certification version.
        state.metadata.certification_version = 1;
        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EnterEdge(canister_id.get().into_vec()),
                E::StartSubtree,
                edge("certified_data"),
                E::VisitBlob(vec![]),
                edge("controller"),
                E::VisitBlob(controller.get().to_vec()),
                edge("module_hash"),
                E::VisitBlob(wasm_binary_hash.to_vec()),
                E::EndSubtree, // canister
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, //global
            ],
            traverse_partial(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_xnet_stream_header() {
        use ic_replicated_state::metadata_state::Stream;
        use ic_types::xnet::{StreamHeader, StreamIndex, StreamIndexedQueue};

        let header = StreamHeader {
            begin: StreamIndex::from(4),
            end: StreamIndex::from(4),
            signals_end: StreamIndex::new(11),
        };

        let stream = Stream {
            messages: StreamIndexedQueue::with_begin(StreamIndex::from(4)),
            signals_end: StreamIndex::new(11),
        };

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );
        state.modify_streams(move |streams| {
            streams.insert(subnet_test_id(5), stream);
        });

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                edge(subnet_test_id(5).get_ref().to_vec()),
                E::StartSubtree,
                edge("header"),
                E::VisitBlob(encode_stream_header(&header)),
                edge("messages"),
                E::StartSubtree,
                E::EndSubtree, // messages
                E::EndSubtree, // stream
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_ingress_history() {
        use crate::subtree_visitor::{Pattern, SubtreeVisitor};
        use ic_test_utilities::types::ids::{message_test_id, subnet_test_id, user_test_id};
        use ic_types::{
            ingress::{IngressStatus, WasmResult},
            user_error::{ErrorCode, UserError},
        };

        let user_id = user_test_id(1);
        let canister_id = canister_test_id(1);
        let time = mock_time();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "/test".into(),
        );
        state.set_ingress_status(message_test_id(1), IngressStatus::Unknown);
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Processing {
                receiver: canister_id.get(),
                user_id,
                time,
            },
        );
        state.set_ingress_status(
            message_test_id(3),
            IngressStatus::Received {
                receiver: canister_id.get(),
                user_id,
                time,
            },
        );
        state.set_ingress_status(
            message_test_id(4),
            IngressStatus::Failed {
                receiver: canister_id.get(),
                user_id,
                error: UserError::new(ErrorCode::SubnetOversubscribed, "subnet oversubscribed"),
                time,
            },
        );
        state.set_ingress_status(
            message_test_id(5),
            IngressStatus::Completed {
                receiver: canister_id.get(),
                user_id,
                result: WasmResult::Reply(b"reply".to_vec()),
                time,
            },
        );
        state.set_ingress_status(
            message_test_id(6),
            IngressStatus::Completed {
                receiver: canister_id.get(),
                user_id,
                result: WasmResult::Reject("reject".to_string()),
                time,
            },
        );

        let pattern = Pattern::match_only("request_status", Pattern::all());
        let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("request_status"),
                E::StartSubtree,
                //
                edge(message_test_id(1)),
                E::StartSubtree,
                edge("status"),
                E::VisitBlob(b"unknown".to_vec()),
                E::EndSubtree,
                //
                edge(message_test_id(2)),
                E::StartSubtree,
                edge("status"),
                E::VisitBlob(b"processing".to_vec()),
                E::EndSubtree,
                //
                edge(message_test_id(3)),
                E::StartSubtree,
                edge("status"),
                E::VisitBlob(b"received".to_vec()),
                E::EndSubtree,
                //
                edge(message_test_id(4)),
                E::StartSubtree,
                edge("reject_code"),
                leb_num(1),
                edge("reject_message"),
                E::VisitBlob(b"subnet oversubscribed".to_vec()),
                edge("status"),
                E::VisitBlob(b"rejected".to_vec()),
                E::EndSubtree,
                //
                edge(message_test_id(5)),
                E::StartSubtree,
                edge("reply"),
                E::VisitBlob(b"reply".to_vec()),
                edge("status"),
                E::VisitBlob(b"replied".to_vec()),
                E::EndSubtree,
                //
                edge(message_test_id(6)),
                E::StartSubtree,
                edge("reject_code"),
                leb_num(4),
                edge("reject_message"),
                E::VisitBlob(b"reject".to_vec()),
                edge("status"),
                E::VisitBlob(b"rejected".to_vec()),
                E::EndSubtree,
                //
                E::EndSubtree,
                E::EndSubtree,
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_time() {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );

        state.metadata.batch_time += Duration::new(1, 123456789);

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(1123456789),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );
    }

    #[test]
    fn test_traverse_subnet() {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            tmpdir.path().into(),
        );

        state.metadata.network_topology.subnets = btreemap! {
            subnet_test_id(0) => SubnetTopology {
                public_key: vec![1, 2, 3, 4],
                nodes: btreemap!{},
                subnet_type: SubnetType::Application,
            },
            subnet_test_id(1) => SubnetTopology {
                public_key: vec![5, 6, 7, 8],
                nodes: btreemap!{},
                subnet_type: SubnetType::Application,
            }
        };

        let visitor = TracingVisitor::new(NoopVisitor);
        assert_eq!(
            vec![
                E::StartSubtree,
                edge("canister"),
                E::StartSubtree,
                E::EndSubtree, // canisters
                edge("metadata"),
                E::VisitBlob(encode_metadata(SystemMetadata {
                    id_counter: 0,
                    prev_state_hash: None
                })),
                edge("request_status"),
                E::StartSubtree,
                E::EndSubtree, // request_status
                edge("streams"),
                E::StartSubtree,
                E::EndSubtree, // streams
                edge("subnet"),
                E::StartSubtree,
                E::EnterEdge(subnet_test_id(0).get().into_vec()),
                E::StartSubtree,
                edge("public_key"),
                E::VisitBlob(vec![1, 2, 3, 4]),
                E::EndSubtree, // subnet
                E::EnterEdge(subnet_test_id(1).get().into_vec()),
                E::StartSubtree,
                edge("public_key"),
                E::VisitBlob(vec![5, 6, 7, 8]),
                E::EndSubtree, // subnet
                E::EndSubtree, // subnets
                edge("time"),
                leb_num(0),
                E::EndSubtree, // global
            ],
            traverse(&state, visitor).0
        );
    }
}
