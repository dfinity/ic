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
    use ic_canonical_state::CertificationVersion;
    use ic_crypto_tree_hash::Digest;
    use ic_error_types::{ErrorCode, UserError};
    use ic_management_canister_types::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
    };
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        canister_state::{
            execution_state::{
                CustomSection, CustomSectionType, NextScheduledMethod, WasmBinary, WasmMetadata,
            },
            system_state::CyclesUseCase,
        },
        metadata_state::{ApiBoundaryNodeEntry, Stream, SubnetMetrics},
        page_map::{PageIndex, PAGE_SIZE},
        testing::ReplicatedStateTesting,
        ExecutionState, ExportedFunctions, Global, Memory, NumWasmPages, PageMap, ReplicatedState,
    };
    use ic_test_utilities_state::new_canister_state;
    use ic_test_utilities_types::ids::{
        canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id,
    };
    use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
    use ic_types::{
        crypto::CryptoHash,
        ingress::{IngressState, IngressStatus},
        messages::{RequestMetadata, NO_DEADLINE},
        nominal_cycles::NominalCycles,
        time::CoarseTime,
        xnet::{RejectReason, StreamFlags, StreamIndex, StreamIndexedQueue},
        CryptoHashOfPartialState, Cycles, ExecutionRound, Time,
    };
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };
    use strum::{EnumCount, IntoEnumIterator};

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
            "Expected the hash tree of the empty state {:?} to different from the hash tree with streams {:?}",
            hash_of_empty_state, hash_of_state_with_streams
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
            "Expected the hash tree of one stream {:?} to different from the hash tree with two streams {:?}",
            hash_of_state_one, hash_of_state_two
        );
    }

    #[test]
    fn test_backward_compatibility() {
        fn state_fixture(certification_version: CertificationVersion) -> ReplicatedState {
            let subnet_id = subnet_test_id(1);
            let mut state = ReplicatedState::new(subnet_id, SubnetType::Application);

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
            let execution_state = ExecutionState {
                canister_root: "NOT_USED".into(),
                session_nonce: None,
                wasm_binary,
                wasm_memory,
                stable_memory: Memory::new_for_testing(),
                exported_globals: vec![Global::I32(1)],
                exports: ExportedFunctions::new(BTreeSet::new()),
                metadata,
                last_executed_round: ExecutionRound::from(0),
                next_scheduled_method: NextScheduledMethod::default(),
            };
            canister_state.execution_state = Some(execution_state);

            state.put_canister_state(canister_state);

            let mut stream = Stream::new(
                StreamIndexedQueue::with_begin(StreamIndex::from(4)),
                StreamIndex::new(10),
            );
            let maybe_deadline = |i: u64| {
                if certification_version >= CertificationVersion::V18 && i % 2 != 0 {
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
                        .metadata(
                            (certification_version >= CertificationVersion::V14 && i % 5 != 0)
                                .then_some(RequestMetadata::new(
                                    i % 3,
                                    Time::from_nanos_since_unix_epoch(i % 2),
                                )),
                        )
                        .deadline(maybe_deadline(i))
                        .build()
                        .into(),
                );
            }
            if certification_version >= CertificationVersion::V8 {
                stream.push_reject_signal(RejectReason::CanisterMigrating);
            }
            if certification_version >= CertificationVersion::V17 {
                stream.set_reverse_stream_flags(StreamFlags {
                    deprecated_responses_only: true,
                });
            }
            if certification_version >= CertificationVersion::V19 {
                stream.push_reject_signal(RejectReason::CanisterNotFound);
                stream.push_reject_signal(RejectReason::QueueFull);
                stream.push_reject_signal(RejectReason::CanisterStopped);
                stream.push_reject_signal(RejectReason::OutOfMemory);
                stream.push_reject_signal(RejectReason::Unknown);
                stream.push_reject_signal(RejectReason::CanisterStopping);
            }
            state.modify_streams(|streams| {
                streams.insert(subnet_test_id(5), stream);
            });

            for i in 1..6 {
                state.set_ingress_status(
                    message_test_id(i),
                    IngressStatus::Unknown,
                    NumBytes::from(u64::MAX),
                );
            }

            if certification_version >= CertificationVersion::V11 {
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
                );
            }

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

            let mut routing_table = RoutingTable::new();
            routing_table
                .insert(
                    CanisterIdRange {
                        start: canister_id,
                        end: canister_id,
                    },
                    subnet_id,
                )
                .unwrap();
            state.metadata.network_topology.subnets = btreemap! {
                subnet_id => Default::default(),
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
                "Mismatched partial state hash computed according to certification version {:?}. \
                Perhaps you made a change that requires writing backward compatibility code?",
                certification_version
            );
        }

        // WARNING: IF THIS TEST FAILS IT IS LIKELY BECAUSE OF A CHANGE THAT BREAKS
        // BACKWARD COMPATIBILITY OF PARTIAL STATE HASHING. IF THAT IS THE CASE
        // PLEASE INCREMENT THE CERTIFICATION VERSION AND PROVIDE APPROPRIATE
        // BACKWARD COMPATIBILITY CODE FOR OLD CERTIFICATION VERSIONS THAT
        // NEED TO BE SUPPORTED.
        let expected_hashes: [&str; CertificationVersion::COUNT] = [
            "1B931426F36191153996B82CE305BE659AAE65D8AE75B4839736176C0453BDF3",
            "3B3F058CD6BAF16A990585223CDD9ED98BC5507B51403707E486B764F1FF5DAE",
            "5F17DC054CBE03F1887400247E4255764AAF3CDBFBA0AD4F414CB7ABAA4782C2",
            "2A615692EF107355C38439DC5AABDF85BAE4979C4135F761213485C655B6F196",
            "2A615692EF107355C38439DC5AABDF85BAE4979C4135F761213485C655B6F196",
            "2A615692EF107355C38439DC5AABDF85BAE4979C4135F761213485C655B6F196",
            "F86FEBBF994627432621BE7DEBD9D59BECEBD922C9C8B4F7F37BD34A5709F16B",
            "F86FEBBF994627432621BE7DEBD9D59BECEBD922C9C8B4F7F37BD34A5709F16B",
            "410BD1929B6884DE65DDBACC54749FDCC2A5FA3585898B9B2644147DE2760678",
            "410BD1929B6884DE65DDBACC54749FDCC2A5FA3585898B9B2644147DE2760678",
            "4BAB4FD35605188FDDCA534204C8E8852C9E450CEB6BE53129FB84DF109D8905",
            "1ED37E00D177681A4111B6D45F518DF3E414B0B614333BB6552EBC0D8492B687",
            "62B2E77DFCD17C7E0CE3E762FD37281776C4B0A38CE1B83A1316614C3F849E39",
            "80D4B528CC9E09C775273994261DD544D45EFFF90B655D90FC3A6E3F633ED718",
            "970BC5155AEB4B4F81E470CBF6748EFA7D8805B936998A54AE70B7DD21F5DDCC",
            "EA3B53B72150E3982CB0E6773F86634685EE7B153DCFE10D86D9927778409D97",
            "D13F75C42D3E2BDA2F742510029088A9ADB119E30241AC969DE24936489168B5",
            "D13F75C42D3E2BDA2F742510029088A9ADB119E30241AC969DE24936489168B5",
            "E739B8EA1585E9BB97988C80ED0C0CDFDF064D4BC5A2B6B06EB414BFF6139CCE",
            "31F4593CC82CDB0B858F190E00112AF4599B5333F7AED9403EEAE88B656738D5",
        ];

        for certification_version in CertificationVersion::iter() {
            assert_partial_state_hash_matches(
                certification_version,
                // expected_hash
                expected_hashes[certification_version as usize],
            );
        }
    }
}
