use crate::lazy_tree_conversion::replicated_state_as_lazy_tree;
use crate::visitor::{Control, Visitor};
use ic_canonical_state_tree_hash::lazy_tree::LazyTree;
use ic_replicated_state::ReplicatedState;

/// Traverses lazy tree using specified visitor.
fn traverse_lazy_tree<V: Visitor>(t: &LazyTree<'_>, v: &mut V) -> Result<(), V::Output> {
    match t {
        LazyTree::Blob(b, _) => v.visit_blob(b),
        LazyTree::LazyBlob(thunk) => {
            let b = thunk();
            v.visit_blob(&b)
        }
        LazyTree::LazyFork(f) => {
            v.start_subtree()?;
            for (l, t) in f.children() {
                match v.enter_edge(l.as_bytes())? {
                    Control::Skip => continue,
                    Control::Continue => {
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
    let t = replicated_state_as_lazy_tree(state);
    match traverse_lazy_tree(&t, &mut v) {
        Err(output) => output,
        _ => v.finish(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::{CborProxyEncoder, encode_stream_header, types::SystemMetadata},
        test_visitors::{NoopVisitor, TraceEntry as E, TracingVisitor},
    };
    use ic_base_types::{NumBytes, NumSeconds};
    use ic_certification_version::{
        CertificationVersion::{self, *},
        all_supported_versions,
    };
    use ic_management_canister_types_private::Global;
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_registry_subnet_features::SubnetFeatures;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        Memory,
        canister_state::{
            ExecutionState, ExportedFunctions, NumWasmPages,
            execution_state::{CustomSection, CustomSectionType, WasmBinary, WasmMetadata},
        },
        metadata_state::{ApiBoundaryNodeEntry, SubnetTopology},
        page_map::PageMap,
        testing::ReplicatedStateTesting,
    };
    use ic_test_utilities_state::new_canister_state;
    use ic_test_utilities_types::ids::{
        canister_test_id, node_test_id, subnet_test_id, user_test_id,
    };
    use ic_types::{
        CanisterId, Cycles,
        batch::CanisterCyclesCostSchedule,
        xnet::{StreamFlags, StreamHeader},
    };
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;
    use std::collections::{BTreeSet, VecDeque};
    use std::convert::TryFrom;
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

    /// Helper function for most tests where the /cansiter_ranges subtree should be missing before V21, and empty afterwards.
    fn expected_empty_canister_ranges(
        certification_version: CertificationVersion,
    ) -> Option<Vec<crate::test_visitors::TraceEntry>> {
        (certification_version >= V21).then_some(vec![
            edge("canister_ranges"),
            E::StartSubtree,
            E::EndSubtree, // canister_ranges
        ])
    }

    #[test]
    fn test_traverse_empty_state() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_canister_empty_execution_state() {
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let controllers_cbor = {
            let mut cbor = vec![217, 217, 247, 129, 74];
            cbor.extend(controller.get().to_vec());
            cbor
        };
        let canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.put_canister_state(canister_state);

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EnterEdge(canister_id.get().into_vec()),
                    E::StartSubtree,
                ]),
                Some(vec![
                    edge("controllers"),
                    E::VisitBlob(controllers_cbor.clone()),
                ]),
                Some(vec![
                    E::EndSubtree, // canister
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_canister_with_execution_state() {
        let canister_id = canister_test_id(2);
        let controller = user_test_id(24);
        let controllers_cbor = {
            let mut cbor = vec![217, 217, 247, 129, 74];
            cbor.extend(controller.get().to_vec());
            cbor
        };
        let mut canister_state = new_canister_state(
            canister_id,
            controller.get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let wasm_binary = WasmBinary::new(CanisterModule::new(vec![]));
        let wasm_binary_hash = wasm_binary.binary.module_hash();
        let wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::from(2));

        let metadata = btreemap! {
            String::from("dummy1") => CustomSection::new(CustomSectionType::Private, vec![0, 2]),
            String::from("dummy2") => CustomSection::new(CustomSectionType::Public, vec![2, 1]),
            String::from("dummy3") => CustomSection::new(CustomSectionType::Public, vec![8, 9]),
        };

        let execution_state = ExecutionState::new(
            "NOT_USED".into(),
            wasm_binary,
            ExportedFunctions::new(BTreeSet::new()),
            wasm_memory,
            Memory::new_for_testing(),
            vec![Global::I32(1)],
            WasmMetadata::new(metadata),
        );

        canister_state.execution_state = Some(execution_state);

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.put_canister_state(canister_state);

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EnterEdge(canister_id.get().into_vec()),
                    E::StartSubtree,
                    edge("certified_data"),
                    E::VisitBlob(vec![]),
                ]),
                Some(vec![
                    edge("controllers"),
                    E::VisitBlob(controllers_cbor.clone()),
                ]),
                Some(vec![
                    edge("metadata"),
                    E::StartSubtree,
                    edge("dummy1"),
                    E::VisitBlob(vec![0, 2]),
                    edge("dummy2"),
                    E::VisitBlob(vec![2, 1]),
                    edge("dummy3"),
                    E::VisitBlob(vec![8, 9]),
                    E::EndSubtree,
                ]),
                Some(vec![
                    edge("module_hash"),
                    E::VisitBlob(wasm_binary_hash.to_vec()),
                ]),
                Some(vec![
                    E::EndSubtree, // canister
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_streams() {
        use ic_replicated_state::metadata_state::Stream;
        use ic_types::xnet::{StreamIndex, StreamIndexedQueue};

        let header = StreamHeader::new(
            4.into(),
            4.into(),
            11.into(),
            VecDeque::default(),
            StreamFlags::default(),
        );

        let stream = Stream::new(
            StreamIndexedQueue::with_begin(StreamIndex::from(4)),
            StreamIndex::new(11),
        );

        let own_subnet_id = subnet_test_id(1);
        let other_subnet_id = subnet_test_id(5);
        let mut state = ReplicatedState::new(own_subnet_id, SubnetType::Application);

        // Loopback stream and remote stream. Loopback stream is not output for versions
        // V20 and greater.
        state.modify_streams(move |streams| {
            streams.insert(own_subnet_id, stream.clone());
            streams.insert(other_subnet_id, stream);
        });

        // Test all certification versions.
        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
                    })),
                    edge("request_status"),
                    E::StartSubtree,
                    E::EndSubtree, // request_status
                    edge("streams"),
                    E::StartSubtree,
                ]),
                // For versions before V20, the loopback stream is also encoded.
                (certification_version < V20).then_some(vec![
                    edge(own_subnet_id.get_ref().to_vec()),
                    E::StartSubtree,
                    edge("header"),
                    E::VisitBlob(encode_stream_header(&header, certification_version)),
                    edge("messages"),
                    E::StartSubtree,
                    E::EndSubtree, // messages
                    E::EndSubtree, // stream
                ]),
                Some(vec![
                    edge(other_subnet_id.get_ref().to_vec()),
                    E::StartSubtree,
                    edge("header"),
                    E::VisitBlob(encode_stream_header(&header, certification_version)),
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_ingress_history() {
        use crate::subtree_visitor::{Pattern, SubtreeVisitor};
        use ic_error_types::{ErrorCode, UserError};
        use ic_test_utilities_types::ids::{message_test_id, subnet_test_id, user_test_id};
        use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
        use ic_types::time::UNIX_EPOCH;

        let user_id = user_test_id(1);
        let canister_id = canister_test_id(1);
        let time = UNIX_EPOCH;
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Unknown,
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(3),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Received,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(4),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Failed(UserError::new(
                    ErrorCode::SubnetOversubscribed,
                    "subnet oversubscribed",
                )),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(5),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reply(b"reply".to_vec())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(6),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Completed(WasmResult::Reject("reject".to_string())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(7),
            IngressStatus::Known {
                receiver: canister_id.get(),
                user_id,
                time,
                state: IngressState::Done,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let pattern = Pattern::match_only("request_status", Pattern::all());
            let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));

            let expected_traversal = vec![
                Some(vec![
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
                ]),
                Some(vec![edge("error_code"), E::VisitBlob(b"IC0101".to_vec())]),
                Some(vec![
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
                ]),
                Some(vec![edge("error_code"), E::VisitBlob(b"IC0406".to_vec())]),
                Some(vec![
                    edge("reject_code"),
                    leb_num(4),
                    edge("reject_message"),
                    E::VisitBlob(b"reject".to_vec()),
                    edge("status"),
                    E::VisitBlob(b"rejected".to_vec()),
                    E::EndSubtree,
                    //
                    edge(message_test_id(7)),
                    E::StartSubtree,
                    edge("status"),
                    E::VisitBlob(b"done".to_vec()),
                    E::EndSubtree,
                    //
                    E::EndSubtree,
                    E::EndSubtree,
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_time() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.metadata.batch_time += Duration::new(1, 123456789);

        // Test all supported certification versions.
        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    fn id_range(from: u64, to: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: CanisterId::from_u64(from),
            end: CanisterId::from_u64(to),
        }
    }

    #[test]
    fn test_traverse_subnet() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        state.metadata.network_topology.subnets = btreemap! {
            subnet_test_id(0) => SubnetTopology {
                public_key: vec![1, 2, 3, 4],
                nodes: BTreeSet::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            },
            subnet_test_id(1) => SubnetTopology {
                public_key: vec![5, 6, 7, 8],
                nodes: BTreeSet::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            }
        };
        state.metadata.network_topology.routing_table = Arc::new(
            RoutingTable::try_from(btreemap! {
                id_range(0, 10) => subnet_test_id(0),
                id_range(11, 20) => subnet_test_id(1),
                id_range(21, 30) => subnet_test_id(0),
            })
            .unwrap(),
        );
        state.metadata.node_public_keys = btreemap! {
            node_test_id(2) => vec![9, 10, 11, 12],
        };

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                    ]),
                    (certification_version >= V21).then_some(
                        vec![
                            edge("canister_ranges"),
                            E::StartSubtree,
                            E::EnterEdge(subnet_test_id(0).get().into_vec()),
                            E::StartSubtree,
                            E::EnterEdge(CanisterId::from_u64(0).get().into_vec()),
                            E::VisitBlob(hex::decode("d9d9f782824a000000000000000001014a000000000000000a0101824a000000000000001501014a000000000000001e0101").unwrap()),
                            E::EndSubtree, // subnet_test_id(0)
                            E::EnterEdge(subnet_test_id(1).get().into_vec()),
                            E::StartSubtree,
                            E::EnterEdge(CanisterId::from_u64(11).get().into_vec()),
                            E::VisitBlob(hex::decode("d9d9f781824a000000000000000b01014a00000000000000140101").unwrap()),
                            E::EndSubtree, // subnet_test_id(1)
                            E::EndSubtree, // canister_ranges
                        ]
                    ),
                    Some(vec![edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
                Some(vec![
                    edge("canister_ranges"),
                    //D9 D9F7                          # tag(55799)
                    //   82                            # array(2)
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000000101 # "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000000A0101 # "\x00\x00\x00\x00\x00\x00\x00\x0A\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000150101 # "\x00\x00\x00\x00\x00\x00\x00\x15\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000001E0101 # "\x00\x00\x00\x00\x00\x00\x00\x1E\x01\x01"
                    E::VisitBlob(hex::decode("d9d9f782824a000000000000000001014a000000000000000a0101824a000000000000001501014a000000000000001e0101").unwrap()),
                ]),
                Some(vec![
                    edge("public_key"),
                    E::VisitBlob(vec![1, 2, 3, 4]),
                    E::EndSubtree, // subnet
                    E::EnterEdge(subnet_test_id(1).get().into_vec()),
                    E::StartSubtree,
                ]),
                Some(vec![
                    edge("canister_ranges"),
                    // D9 D9F7                          # tag(55799)
                    //    81                            # array(1)
                    //       82                         # array(2)
                    //          4A                      # bytes(10)
                    //             000000000000000B0101 # "\x00\x00\x00\x00\x00\x00\x00\x0B\x01\x01"
                    //          4A                      # bytes(10)
                    //             00000000000000140101 # "\x00\x00\x00\x00\x00\x00\x00\x14\x01\x01"
                    E::VisitBlob(hex::decode("d9d9f781824a000000000000000b01014a00000000000000140101").unwrap()),
                ]),
                Some(vec![
                    edge("metrics"),
                    // A4       # map(4)
                    //    00    # unsigned(0)
                    //    00    # unsigned(0)
                    //    01    # unsigned(1)
                    //    00    # unsigned(0)
                    //    02    # unsigned(2)
                    //    A2    # map(2)
                    //       00 # unsigned(0)
                    //       00 # unsigned(0)
                    //       01 # unsigned(1)
                    //       00 # unsigned(0)
                    //    03    # unsigned(3)
                    //    00    # unsigned(0)
                    E::VisitBlob(hex::decode("a40000010002a2000001000300").unwrap()),
                ]),
                Some(vec![
                    edge("node"),
                    E::StartSubtree,
                    E::EnterEdge(node_test_id(2).get().into_vec()),
                    E::StartSubtree,
                    edge("public_key"), // node public key
                    E::VisitBlob(vec![9, 10, 11, 12]),
                    E::EndSubtree, // node
                    E::EndSubtree, // nodes
                ]),
                Some(vec![
                    edge("public_key"),
                    E::VisitBlob(vec![5, 6, 7, 8]),
                    E::EndSubtree, // subnet
                    E::EndSubtree, // subnets
                    edge("time"),
                    leb_num(0),
                    E::EndSubtree, // global
                ])
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_large_or_empty_routing_table() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        state.metadata.network_topology.subnets = btreemap! {
            subnet_test_id(0) => SubnetTopology {
                public_key: vec![1, 2, 3, 4],
                nodes: BTreeSet::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            },
            subnet_test_id(1) => SubnetTopology {
                public_key: vec![5, 6, 7, 8],
                nodes: BTreeSet::new(),
                subnet_type: SubnetType::Application,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            }
        };
        state.metadata.network_topology.routing_table = Arc::new(
            RoutingTable::try_from(btreemap! {
                id_range(0, 10) => subnet_test_id(0),
                id_range(21, 30) => subnet_test_id(0),
                id_range(36, 40) => subnet_test_id(0),
                id_range(51, 51) => subnet_test_id(0),
                id_range(61, 70) => subnet_test_id(0),
                id_range(81, 90) => subnet_test_id(0),
                id_range(105, 110) => subnet_test_id(0),
            })
            .unwrap(),
        );

        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                    ]),
                    (certification_version >= V21).then_some(
                        vec![
                            edge("canister_ranges"),
                            E::StartSubtree,
                            E::EnterEdge(subnet_test_id(0).get().into_vec()),
                            E::StartSubtree,
                            E::EnterEdge(CanisterId::from_u64(0).get().into_vec()),
                            //D9 D9F7                          # tag(55799)
                            //   87                            # array(5)
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000000101 # "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
                            //         4A                      # bytes(10)
                            //            000000000000000A0101 # "\x00\x00\x00\x00\x00\x00\x00\x0A\x01\x01"
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000150101 # "\x00\x00\x00\x00\x00\x00\x00\x15\x01\x01"
                            //         4A                      # bytes(10)
                            //            000000000000001E0101 # "\x00\x00\x00\x00\x00\x00\x00\x1E\x01\x01"
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000240101 # "\x00\x00\x00\x00\x00\x00\x00\x24\x01\x01"
                            //         4A                      # bytes(10)
                            //            00000000000000280101 # "\x00\x00\x00\x00\x00\x00\x00\x28\x01\x01"
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000330101 # "\x00\x00\x00\x00\x00\x00\x00\x33\x01\x01"
                            //         4A                      # bytes(10)
                            //            00000000000000330101 # "\x00\x00\x00\x00\x00\x00\x00\x33\x01\x01"
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            000000000000003D0101 # "\x00\x00\x00\x00\x00\x00\x00\x3D\x01\x01"
                            //         4A                      # bytes(10)
                            //            00000000000000460101 # "\x00\x00\x00\x00\x00\x00\x00\x46\x01\x01"
                            E::VisitBlob(hex::decode("d9d9f785824a000000000000000001014a000000000000000a0101824a000000000000001501014a000000000000001e0101824a000000000000002401014a00000000000000280101824a000000000000003301014a00000000000000330101\
                                                      824a000000000000003d01014a00000000000000460101").unwrap()),
                            E::EnterEdge(CanisterId::from_u64(81).get().into_vec()),
                            //D9 D9F7                          # tag(55799)
                            //   87                            # array(2)
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000510101 # "\x00\x00\x00\x00\x00\x00\x00\x51\x01\x01"
                            //         4A                      # bytes(10)
                            //            000000000000005A0101 # "\x00\x00\x00\x00\x00\x00\x00\x5A\x01\x01"
                            //      82                         # array(2)
                            //         4A                      # bytes(10)
                            //            00000000000000690101 # "\x00\x00\x00\x00\x00\x00\x00\x69\x01\x01"
                            //         4A                      # bytes(10)
                            //            000000000000006E0101 # "\x00\x00\x00\x00\x00\x00\x00\x6E\x01\x01"
                            E::VisitBlob(hex::decode("d9d9f782824a000000000000005101014a000000000000005a0101824a000000000000006901014a000000000000006e0101").unwrap()),
                            E::EndSubtree, // subnet_test_id(0)
                            E::EnterEdge(subnet_test_id(1).get().into_vec()),
                            E::StartSubtree,
                            E::EnterEdge(CanisterId::from_u64(0).get().into_vec()),
                            // D9 D9F7                          # tag(55799)
                            //    80                            # array(0)
                            E::VisitBlob(hex::decode("d9d9f780").unwrap()),
                            E::EndSubtree, // subnet_test_id(1)
                            E::EndSubtree, // canister_ranges
                        ]
                    ),
                    Some(vec![edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
                Some(vec![
                    edge("canister_ranges"),
                    //D9 D9F7                          # tag(55799)
                    //   87                            # array(7)
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000000101 # "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000000A0101 # "\x00\x00\x00\x00\x00\x00\x00\x0A\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000150101 # "\x00\x00\x00\x00\x00\x00\x00\x15\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000001E0101 # "\x00\x00\x00\x00\x00\x00\x00\x1E\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000240101 # "\x00\x00\x00\x00\x00\x00\x00\x24\x01\x01"
                    //         4A                      # bytes(10)
                    //            00000000000000280101 # "\x00\x00\x00\x00\x00\x00\x00\x28\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000330101 # "\x00\x00\x00\x00\x00\x00\x00\x33\x01\x01"
                    //         4A                      # bytes(10)
                    //            00000000000000330101 # "\x00\x00\x00\x00\x00\x00\x00\x33\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            000000000000003D0101 # "\x00\x00\x00\x00\x00\x00\x00\x3D\x01\x01"
                    //         4A                      # bytes(10)
                    //            00000000000000460101 # "\x00\x00\x00\x00\x00\x00\x00\x46\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000510101 # "\x00\x00\x00\x00\x00\x00\x00\x51\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000005A0101 # "\x00\x00\x00\x00\x00\x00\x00\x5A\x01\x01"
                    //      82                         # array(2)
                    //         4A                      # bytes(10)
                    //            00000000000000690101 # "\x00\x00\x00\x00\x00\x00\x00\x69\x01\x01"
                    //         4A                      # bytes(10)
                    //            000000000000006E0101 # "\x00\x00\x00\x00\x00\x00\x00\x6E\x01\x01"
                    E::VisitBlob(hex::decode("d9d9f787824a000000000000000001014a000000000000000a0101824a000000000000001501014a000000000000001e0101824a000000000000002401014a00000000000000280101824a000000000000003301014a00000000000000330101\
                                              824a000000000000003d01014a00000000000000460101824a000000000000005101014a000000000000005a0101824a000000000000006901014a000000000000006e0101").unwrap()),
                ]),
                Some(vec![
                    edge("public_key"),
                    E::VisitBlob(vec![1, 2, 3, 4]),
                    E::EndSubtree, // subnet
                    E::EnterEdge(subnet_test_id(1).get().into_vec()),
                    E::StartSubtree,
                ]),
                Some(vec![
                    edge("canister_ranges"),
                    // D9 D9F7                          # tag(55799)
                    //    80                            # array(0)
                    E::VisitBlob(hex::decode("d9d9f780").unwrap()),
                ]),
                Some(vec![
                    edge("metrics"),
                    // A4       # map(4)
                    //    00    # unsigned(0)
                    //    00    # unsigned(0)
                    //    01    # unsigned(1)
                    //    00    # unsigned(0)
                    //    02    # unsigned(2)
                    //    A2    # map(2)
                    //       00 # unsigned(0)
                    //       00 # unsigned(0)
                    //       01 # unsigned(1)
                    //       00 # unsigned(0)
                    //    03    # unsigned(3)
                    //    00    # unsigned(0)
                    E::VisitBlob(hex::decode("a40000010002a2000001000300").unwrap()),
                ]),
                Some(vec![
                    edge("node"),
                    E::StartSubtree,
                    E::EndSubtree, // nodes
                ]),
                Some(vec![
                    edge("public_key"),
                    E::VisitBlob(vec![5, 6, 7, 8]),
                    E::EndSubtree, // subnet
                    E::EndSubtree, // subnets
                    edge("time"),
                    leb_num(0),
                    E::EndSubtree, // global
                ])
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }

    #[test]
    fn test_traverse_api_boundary_nodes() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.metadata.api_boundary_nodes = btreemap! {
            node_test_id(11) => ApiBoundaryNodeEntry {
                domain: "api-bn11-example.com".to_string(),
                ipv4_address: Some("127.0.0.1".to_string()),
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
                pubkey: None,
            },
            node_test_id(12) => ApiBoundaryNodeEntry {
                domain: "api-bn12-example.com".to_string(),
                ipv4_address: None,
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7335".to_string(),
                pubkey: None,
            },
        };

        // Test all supported certification versions.
        for certification_version in all_supported_versions() {
            state.metadata.certification_version = certification_version;
            let visitor = TracingVisitor::new(NoopVisitor);

            let expected_traversal = vec![
                Some(vec![E::StartSubtree]), // global
                Some(vec![
                    edge("api_boundary_nodes"),
                    E::StartSubtree,
                    E::EnterEdge(node_test_id(11).get().into_vec()),
                    E::StartSubtree,
                    edge("domain"),
                    E::VisitBlob("api-bn11-example.com".to_string().into_bytes()),
                    edge("ipv4_address"),
                    E::VisitBlob("127.0.0.1".to_string().into_bytes()),
                    edge("ipv6_address"),
                    E::VisitBlob(
                        "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                            .to_string()
                            .into_bytes(),
                    ),
                    E::EndSubtree, // api boundary node 11
                    E::EnterEdge(node_test_id(12).get().into_vec()),
                    E::StartSubtree,
                    edge("domain"),
                    E::VisitBlob("api-bn12-example.com".to_string().into_bytes()),
                    edge("ipv6_address"),
                    E::VisitBlob(
                        "2001:0db8:85a3:0000:0000:8a2e:0370:7335"
                            .to_string()
                            .into_bytes(),
                    ),
                    E::EndSubtree, // api boundary node 12
                    E::EndSubtree, // api_boundary_nodes
                ]),
                Some(vec![
                    edge("canister"),
                    E::StartSubtree,
                    E::EndSubtree, // canisters
                ]),
                expected_empty_canister_ranges(certification_version),
                Some(vec![
                    edge("metadata"),
                    E::VisitBlob(encode_metadata(SystemMetadata {
                        deprecated_id_counter: None,
                        prev_state_hash: None,
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
                ]),
            ]
            .into_iter()
            .flat_map(Option::unwrap_or_default)
            .collect::<Vec<_>>();

            assert_eq!(
                expected_traversal,
                traverse(&state, visitor).0,
                "unexpected traversal for certification_version: {certification_version:?}"
            );
        }
    }
}
