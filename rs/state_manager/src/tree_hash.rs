use ic_canonical_state::{Control, Visitor};
use ic_crypto_tree_hash::{HashTree, HashTreeBuilder, HashTreeBuilderImpl, Label};
use ic_replicated_state::ReplicatedState;

/// A visitor that constructs a hash tree by traversing a replicated
/// state.
#[derive(Default)]
pub struct HashingVisitor<T> {
    tree_hasher: T,
}

impl<T> Visitor for HashingVisitor<T>
where
    T: HashTreeBuilder,
{
    type Output = T;

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        self.tree_hasher.start_subtree();
        Ok(())
    }

    fn enter_edge(&mut self, label: &[u8]) -> Result<Control, Self::Output> {
        self.tree_hasher.new_edge(Label::from(label));
        Ok(Control::Continue)
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        self.tree_hasher.finish_subtree();
        Ok(())
    }

    fn visit_num(&mut self, num: u64) -> Result<(), Self::Output> {
        self.tree_hasher.start_leaf();
        self.tree_hasher.write_leaf(&num.to_le_bytes()[..]);
        self.tree_hasher.finish_leaf();
        Ok(())
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output> {
        self.tree_hasher.start_leaf();
        self.tree_hasher.write_leaf(blob);
        self.tree_hasher.finish_leaf();
        Ok(())
    }

    fn finish(self) -> Self::Output {
        self.tree_hasher
    }
}

/// Compute the hash tree corresponding to the full replicated state.
pub fn hash_state(state: &ReplicatedState) -> HashTree {
    ic_canonical_state::traverse(state, HashingVisitor::<HashTreeBuilderImpl>::default())
        .into_hash_tree()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use ic_base_types::{NumBytes, NumSeconds};
    use ic_canonical_state::{CertificationVersion, all_supported_versions};
    use ic_crypto_tree_hash::Digest;
    use ic_error_types::{ErrorCode, UserError};
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, Global, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
    };
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        ExecutionState, ExportedFunctions, Memory, NumWasmPages, PageMap, ReplicatedState,
        canister_state::{
            execution_state::{CustomSection, CustomSectionType, WasmBinary, WasmMetadata},
            system_state::CyclesUseCase,
        },
        metadata_state::{ApiBoundaryNodeEntry, Stream, SubnetMetrics},
        page_map::{PAGE_SIZE, PageIndex},
        testing::ReplicatedStateTesting,
    };
    use ic_test_utilities_state::new_canister_state;
    use ic_test_utilities_types::ids::{
        canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id,
    };
    use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
    use ic_types::{
        CanisterId, CryptoHashOfPartialState, Cycles, Time,
        crypto::CryptoHash,
        ingress::{IngressState, IngressStatus},
        messages::{NO_DEADLINE, Refund, RequestMetadata},
        nominal_cycles::NominalCycles,
        time::CoarseTime,
        xnet::{RejectReason, StreamFlags, StreamIndex, StreamIndexedQueue},
    };
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    #[test]
    fn partial_hash_reflects_streams() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        let hash_of_empty_state = hash_state(&state);

        state.modify_streams(|streams| {
            streams.insert(
                subnet_test_id(5),
                Stream::new(
                    StreamIndexedQueue::with_begin(StreamIndex::new(4)),
                    StreamIndex::new(10),
                ),
            );
        });

        let hash_of_state_with_streams = hash_state(&state);

        assert!(
            hash_of_empty_state != hash_of_state_with_streams,
            "Expected the hash tree of the empty state {hash_of_empty_state:?} to different from the hash tree with streams {hash_of_state_with_streams:?}"
        );
    }

    #[test]
    fn partial_hash_detects_changes_in_streams() {
        use ic_replicated_state::metadata_state::Stream;
        use ic_types::xnet::{StreamIndex, StreamIndexedQueue};

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        let stream = Stream::new(
            StreamIndexedQueue::with_begin(StreamIndex::from(4)),
            StreamIndex::new(10),
        );

        state.modify_streams(|streams| {
            streams.insert(subnet_test_id(5), stream);
        });

        let hash_of_state_one = hash_state(&state);

        let stream = Stream::new(
            StreamIndexedQueue::with_begin(StreamIndex::from(14)),
            StreamIndex::new(11),
        );
        state.modify_streams(|streams| {
            streams.insert(subnet_test_id(6), stream);
        });

        let hash_of_state_two = hash_state(&state);

        assert!(
            hash_of_state_one != hash_of_state_two,
            "Expected the hash tree of one stream {hash_of_state_one:?} to different from the hash tree with two streams {hash_of_state_two:?}"
        );
    }

    #[test]
    fn test_backward_compatibility() {
        fn state_fixture(certification_version: CertificationVersion) -> ReplicatedState {
            let own_subnet_id = subnet_test_id(1);
            let other_subnet_id = subnet_test_id(5);
            let mut state = ReplicatedState::new(own_subnet_id, SubnetType::Application);

            let canister_id = canister_test_id(2);
            let controller = user_test_id(24);
            let mut canister_state = new_canister_state(
                canister_id,
                controller.get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let mut wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::from(2));
            wasm_memory
                .page_map
                .update(&[(PageIndex::from(1), &[0u8; PAGE_SIZE])]);
            let wasm_binary = WasmBinary::new(CanisterModule::new(vec![]));
            let metadata = WasmMetadata::new(btreemap! {
                String::from("dummy1") => CustomSection::new(CustomSectionType::Private, vec![0, 2]),
            });
            let execution_state = ExecutionState::new(
                "NOT_USED".into(),
                wasm_binary,
                ExportedFunctions::new(BTreeSet::new()),
                wasm_memory,
                Memory::new_for_testing(),
                vec![Global::I32(1)],
                metadata,
            );
            canister_state.execution_state = Some(execution_state);

            state.put_canister_state(canister_state);

            let mut stream = Stream::new(
                StreamIndexedQueue::with_begin(StreamIndex::from(4)),
                StreamIndex::new(10),
            );
            let maybe_deadline = |i: u64| {
                if !i.is_multiple_of(2) {
                    CoarseTime::from_secs_since_unix_epoch(i as u32)
                } else {
                    NO_DEADLINE
                }
            };
            for i in 1..6 {
                stream.push(
                    ResponseBuilder::new()
                        .deadline(maybe_deadline(i))
                        .build()
                        .into(),
                );
            }
            for i in 1..6 {
                stream.push(
                    RequestBuilder::new()
                        .metadata(RequestMetadata::new(
                            i % 3,
                            Time::from_nanos_since_unix_epoch(i % 2),
                        ))
                        .deadline(maybe_deadline(i))
                        .build()
                        .into(),
                );
            }
            // Enqueue some refund messages for certification versions >= V22.
            if certification_version >= CertificationVersion::V22 {
                for i in 1..6 {
                    stream.push(Refund::anonymous(canister_id, Cycles::new(i)).into());
                }
            }
            stream.push_reject_signal(RejectReason::CanisterMigrating);
            stream.set_reverse_stream_flags(StreamFlags {
                deprecated_responses_only: true,
            });
            stream.push_reject_signal(RejectReason::CanisterNotFound);
            stream.push_reject_signal(RejectReason::QueueFull);
            stream.push_reject_signal(RejectReason::CanisterStopped);
            stream.push_reject_signal(RejectReason::OutOfMemory);
            stream.push_reject_signal(RejectReason::Unknown);
            stream.push_reject_signal(RejectReason::CanisterStopping);

            let loopback_stream = Stream::new(
                StreamIndexedQueue::with_begin(StreamIndex::from(13)),
                StreamIndex::new(13),
            );
            state.modify_streams(|streams| {
                streams.insert(own_subnet_id, loopback_stream.clone());
                streams.insert(other_subnet_id, stream);
            });

            for i in 1..6 {
                state.set_ingress_status(
                    message_test_id(i),
                    IngressStatus::Unknown,
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
            }

            state.set_ingress_status(
                message_test_id(7),
                IngressStatus::Known {
                    state: IngressState::Failed(UserError::new(
                        ErrorCode::CanisterNotFound,
                        "canister not found",
                    )),
                    receiver: canister_id.into(),
                    user_id: user_test_id(1),
                    time: Time::from_nanos_since_unix_epoch(12345),
                },
                NumBytes::from(u64::MAX),
                |_| {},
            );

            state.metadata.node_public_keys = btreemap! {
                node_test_id(1) => vec![1; 44],
                node_test_id(2) => vec![2; 44],
            };

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

            fn id_range(from: u64, to: u64) -> CanisterIdRange {
                CanisterIdRange {
                    start: CanisterId::from_u64(from),
                    end: CanisterId::from_u64(to),
                }
            }

            // More than 5 ranges for the same subnet to capture sharding of the routing table.
            let routing_table = RoutingTable::try_from(btreemap! {
                CanisterIdRange {start: canister_id, end: canister_id} => own_subnet_id,
                id_range(1000, 2000) => own_subnet_id,
                id_range(3000, 3001) => own_subnet_id,
                id_range(4000, 4010) => own_subnet_id,
                id_range(4100, 5000) => own_subnet_id,
                id_range(5002, 5002) => other_subnet_id,
                id_range(6000, 7000) => own_subnet_id,
            })
            .unwrap();

            state.metadata.network_topology.subnets = btreemap! {
                own_subnet_id => Default::default(),
                other_subnet_id => Default::default(),
            };
            state.metadata.network_topology.routing_table = Arc::new(routing_table);
            state.metadata.prev_state_hash =
                Some(CryptoHashOfPartialState::new(CryptoHash(vec![3, 2, 1])));

            state.metadata.certification_version = certification_version;

            let mut subnet_metrics = SubnetMetrics::default();

            subnet_metrics.consumed_cycles_by_deleted_canisters = NominalCycles::from(0);
            subnet_metrics.consumed_cycles_http_outcalls = NominalCycles::from(50_000_000_000);
            subnet_metrics.consumed_cycles_ecdsa_outcalls = NominalCycles::from(100_000_000_000);
            subnet_metrics.num_canisters = 5;
            subnet_metrics.canister_state_bytes = NumBytes::from(5 * 1024 * 1024);
            subnet_metrics.update_transactions_total = 4200;
            subnet_metrics.observe_consumed_cycles_with_use_case(
                CyclesUseCase::Instructions,
                NominalCycles::from(80_000_000_000),
            );
            subnet_metrics.observe_consumed_cycles_with_use_case(
                CyclesUseCase::RequestAndResponseTransmission,
                NominalCycles::from(20_000_000_000),
            );
            let schnorr_key_id = MasterPublicKeyId::Schnorr(SchnorrKeyId {
                algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                name: "schnorr_key_id".into(),
            });
            let ecdsa_key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "ecdsa_key_id".into(),
            });
            subnet_metrics.threshold_signature_agreements =
                BTreeMap::from([(schnorr_key_id, 15), (ecdsa_key_id, 16)]);

            state.metadata.subnet_metrics = subnet_metrics;

            state
        }

        fn assert_partial_state_hash_matches(
            certification_version: CertificationVersion,
            expected_hash: &str,
        ) {
            let state = state_fixture(certification_version);

            assert_eq!(
                hash_state(&state).digest(),
                &Digest::from(<[u8; 32]>::from_hex(expected_hash,).unwrap()),
                "Mismatched partial state hash computed according to certification version {certification_version:?}. \
                Perhaps you made a change that requires writing backward compatibility code?"
            );
        }

        // WARNING: IF THIS TEST FAILS IT IS LIKELY BECAUSE OF A CHANGE THAT BREAKS
        // BACKWARD COMPATIBILITY OF PARTIAL STATE HASHING. IF THAT IS THE CASE
        // PLEASE INCREMENT THE CERTIFICATION VERSION AND PROVIDE APPROPRIATE
        // BACKWARD COMPATIBILITY CODE FOR OLD CERTIFICATION VERSIONS THAT
        // NEED TO BE SUPPORTED.
        let expected_hashes = [
            "47C3A071B293B4723FCACB17F2FD2FD75F68C010E333007ACC0EF425D92765FB",
            "3F9441CBAC0A00718BA6CB2D4D1B6FF7FF96F42051567365B670ACFC08AB96EA",
            "9D9C8D991198BCD0BCAA627F409181D08ADD8CA442730393D5A27FA1042D2477",
            "7FA3E764326968A311F7FE760CE7B6D29978BC9165DCDA332B4350EBEEC6D90C",
        ];
        assert_eq!(expected_hashes.len(), all_supported_versions().count());

        for (certification_version, expected_hash) in
            all_supported_versions().zip(expected_hashes.iter())
        {
            assert_partial_state_hash_matches(certification_version, expected_hash);
        }
    }
}
