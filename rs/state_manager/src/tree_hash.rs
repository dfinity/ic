use ic_canonical_state::{Control, Visitor};
use ic_crypto_tree_hash::{HashTree, HashTreeBuilder, HashTreeBuilderImpl, Label};
use ic_replicated_state::ReplicatedState;
use ic_types::Height;

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
pub fn hash_state(state: &ReplicatedState, height: Height) -> HashTree {
    ic_canonical_state::traverse(
        state,
        height,
        HashingVisitor::<HashTreeBuilderImpl>::default(),
    )
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
        canister_state::execution_state::{
            CustomSection, CustomSectionType, WasmBinary, WasmMetadata,
        },
        metadata_state::{
            ApiBoundaryNodeEntry, Stream, SubnetMetrics,
            testing::{NetworkTopologyTesting, SystemMetadataTesting},
        },
        page_map::{PAGE_SIZE, PageIndex},
        testing::{ReplicatedStateTesting, StreamTesting},
    };
    use ic_test_utilities_state::new_canister_state;
    use ic_test_utilities_types::ids::{
        canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id,
    };
    use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
    use ic_types::{
        CanisterId, CryptoHashOfPartialState, Height, Time,
        crypto::CryptoHash,
        ingress::{IngressState, IngressStatus, WasmResult},
        messages::{NO_DEADLINE, Refund, RequestMetadata},
        time::CoarseTime,
        xnet::{RejectReason, StreamFlags, StreamIndex, StreamIndexedQueue},
    };
    use ic_types_cycles::{Cycles, CyclesUseCase, NominalCycles, NominalCyclesTesting};
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;
    use std::collections::{BTreeMap, BTreeSet};

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    #[test]
    fn partial_hash_reflects_streams() {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

        let hash_of_empty_state = hash_state(&state, Height::new(0));

        state.modify_streams(|streams| {
            streams.insert(
                subnet_test_id(5),
                Stream::new(
                    StreamIndexedQueue::with_begin(StreamIndex::new(4)),
                    StreamIndex::new(10),
                ),
            );
        });

        let hash_of_state_with_streams = hash_state(&state, Height::new(0));

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

        let hash_of_state_one = hash_state(&state, Height::new(0));

        let stream = Stream::new(
            StreamIndexedQueue::with_begin(StreamIndex::from(14)),
            StreamIndex::new(11),
        );
        state.modify_streams(|streams| {
            streams.insert(subnet_test_id(6), stream);
        });

        let hash_of_state_two = hash_state(&state, Height::new(0));

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
                .update(&[(PageIndex::from(1), &[0_u8; PAGE_SIZE])]);
            let wasm_binary = WasmBinary::new(CanisterModule::new(vec![]));
            let metadata = WasmMetadata::new(btreemap! {
                String::from("dummy1") => CustomSection::new(CustomSectionType::Private, vec![0, 2]),
            });
            // Exercise the `last_install_timestamp` leaf added in `V27`.
            let last_install_timestamp = (certification_version >= CertificationVersion::V27)
                .then(|| Time::from_nanos_since_unix_epoch(1234));
            let execution_state = ExecutionState::new(
                wasm_binary,
                last_install_timestamp,
                ExportedFunctions::new(BTreeSet::new()),
                wasm_memory,
                Memory::new_for_testing(),
                vec![Global::I32(1)],
                metadata,
            );
            canister_state.execution_state = Some(execution_state);
            // Exercise the `canister_creation_timestamp` leaf added in `V28`.
            if certification_version >= CertificationVersion::V28 {
                canister_state.system_state.canister_creation_timestamp =
                    Some(Time::from_nanos_since_unix_epoch(1234));
            }

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
            if certification_version >= CertificationVersion::V26 {
                stream.push_reject_signal(RejectReason::EngineNotAllowed);
            }

            let loopback_stream = Stream::new(
                StreamIndexedQueue::with_begin(StreamIndex::from(13)),
                StreamIndex::new(13),
            );
            state.modify_streams(|streams| {
                streams.insert(own_subnet_id, loopback_stream.clone());
                streams.insert(other_subnet_id, stream);
            });

            // Exercise every ingress state. (`IngressStatus::Unknown` stands for the
            // absence of an ingress history entry, so it is never recorded.)
            let ingress_states = [
                IngressState::Received,
                IngressState::Processing,
                IngressState::Completed(WasmResult::Reply(vec![1, 2, 3])),
                IngressState::Completed(WasmResult::Reject("rejected".into())),
                IngressState::Done,
                IngressState::Failed(UserError::new(
                    ErrorCode::CanisterNotFound,
                    "canister not found",
                )),
            ];
            for (i, ingress_state) in ingress_states.into_iter().enumerate() {
                state.set_ingress_status(
                    message_test_id(i as u64 + 1),
                    IngressStatus::Known {
                        state: ingress_state,
                        receiver: canister_id.into(),
                        user_id: user_test_id(1),
                        time: Time::from_nanos_since_unix_epoch(12345),
                    },
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
            }

            std::sync::Arc::make_mut(&mut state.metadata.own_subnet_info).node_public_keys = btreemap! {
                node_test_id(1) => vec![1; 44],
                node_test_id(2) => vec![2; 44],
            };

            std::sync::Arc::make_mut(&mut state.metadata.network_topology).api_boundary_nodes = btreemap! {
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

            state.metadata.modify_network_topology(|network_topology| {
                network_topology.set_subnets(btreemap! {
                    own_subnet_id => Default::default(),
                    other_subnet_id => Default::default(),
                });
                network_topology.set_routing_table(routing_table);
            });
            state.metadata.prev_state_hash =
                Some(CryptoHashOfPartialState::new(CryptoHash(vec![3, 2, 1])));

            state.metadata.certification_version = certification_version;

            let mut subnet_metrics = SubnetMetrics::default();

            subnet_metrics.observe_consumed_cycles_by_deleted_canisters(NominalCycles::zero());
            subnet_metrics
                .observe_consumed_cycles_http_outcalls(NominalCycles::new(50_000_000_000));
            subnet_metrics
                .observe_consumed_cycles_ecdsa_outcalls(NominalCycles::new(100_000_000_000));
            subnet_metrics.num_canisters = 5;
            subnet_metrics.canister_state_bytes = NumBytes::from(5 * 1024 * 1024);
            subnet_metrics.update_transactions_total = 4200;
            subnet_metrics.observe_consumed_cycles_with_use_case(
                CyclesUseCase::Instructions,
                NominalCycles::new(80_000_000_000),
            );
            subnet_metrics.observe_consumed_cycles_with_use_case(
                CyclesUseCase::RequestAndResponseTransmission,
                NominalCycles::new(20_000_000_000),
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
            subnet_metrics.refresh_consumed_cycles(NominalCycles::zero());

            state.metadata.subnet_metrics = subnet_metrics;

            state
        }

        fn assert_partial_state_hash_matches(
            certification_version: CertificationVersion,
            expected_hash: &str,
        ) {
            let state = state_fixture(certification_version);

            assert_eq!(
                hash_state(&state, Height::new(0)).digest(),
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
            "A58A2CE65A1EF1F32AA1B46E884B52FDBF14C4A8A01100C78401F958F5BE04E4",
            "D23410333D985C91C2BE540D7282BCB28C356D6B587F7ABCEFC8BE2C4D7DE454",
            "1090ACD6B66270816569DD4AEC2B315EAFB0AF7F00D6C4801BE88979765C67C5",
            "5FB827932CC4FF419E47869F1AB37473311B81DFD10A7090FABB90E55B6495BE",
            "3FFC2919D08408B3C9D582AE2BEE4D806707179B1D110E113EFEF3D709A62E24",
            "BCD87ECE333D4F1C132EDE0F820EA717A6BD63F14544526FBBAF5BAA69A45C5A",
            "DB79E2779240264D24194A0FA3609F1369F6C98800DEC23DEF69D2B395C0D2E1",
            "0EC99B2AA159C259010B02E8568077959506C4153594338E9A69450F326CEE38",
            "3EE82452CD7712A87BC313F6AD0BBEEC7F264A4699BEBD324A961080D96F5FD1",
            "512D8886C4E68D75AA1EE4AFC26A67F2BA00E56FB75FE5C9FB7E69DDA25026EB",
            "A15A37BD9A0454C39D6B9A4234001D19B02433D8F0CD790664027145790B06B3",
        ];
        assert_eq!(expected_hashes.len(), all_supported_versions().count());

        for (certification_version, expected_hash) in
            all_supported_versions().zip(expected_hashes.iter())
        {
            assert_partial_state_hash_matches(certification_version, expected_hash);
        }
    }
}
