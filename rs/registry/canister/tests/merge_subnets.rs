use candid::Encode;
use ic_nns_test_utils::{
    itest_helpers::{
        set_up_registry_canister, set_up_universal_canister, state_machine_test_on_nns_subnet,
        try_call_via_universal_canister,
    },
    registry::{initial_routing_table_mutations, prepare_registry_with_two_node_sets},
};
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, ChainKeyInitialization, EcdsaInitialization, RecoveryArgs,
    catch_up_package_contents::CupType,
};
use ic_registry_keys::make_catch_up_package_contents_key;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_types::CanisterId;
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::merge_subnets::MergeSubnetsPayload,
};

mod common;
use common::test_helpers::{
    check_error_message, check_subnet_for_canisters, get_cup_contents, get_subnet_record,
};

/// The recovery CUP the merge creates for the destination subnet. The values are
/// arbitrary: this test does not run a subnet from the resulting CUP, it only
/// checks that the endpoint accepts them and records them.
const MERGE_HEIGHT: u64 = 100;
const MERGE_TIME_NS: u64 = 1_234_567_890;
const MERGED_STATE_HASH: &[u8] = &[42; 32];

/// Exercises the `merge_subnets` endpoint end to end. The payload validation
/// itself is covered by the unit tests of `Registry::merge_subnets`, so this test
/// only covers what those cannot: that the endpoint is reachable with a Candid
/// encoded payload, that only governance may call it, that the canisters of the
/// source subnet end up routed to the destination subnet, and that the recovery
/// CUP of the destination subnet -- whose DKG transcripts come from the
/// `setup_initial_dkg` call the endpoint makes half way through -- is recorded
/// and the destination subnet is brought back online.
#[test]
fn test_merge_subnets() {
    state_machine_test_on_nns_subnet(|runtime| {
        async move {
            // Step 1: Prepare the world: two subnets where subnet 2 hosts the canister
            // ID range [0, 255] and subnet 1 hosts [256, 511].
            let (subnet_1_mutation, subnet_id_1, subnet_id_2_option, _, _) =
                prepare_registry_with_two_node_sets(
                    /* num_nodes_in_subnet = */ 4, /* num_unassigned_nodes = */ 4, true,
                );
            let subnet_id_2 = subnet_id_2_option.unwrap();
            // Give the destination subnet a CUP holding chain key initializations, as it
            // would if it had once been recovered while holding chain keys. Merging must
            // not carry them over into the recovery CUP it creates.
            let subnet_1_mutation = {
                let mut subnet_1_mutation = subnet_1_mutation;
                let cup_contents_key = make_catch_up_package_contents_key(subnet_id_2).into_bytes();
                let cup_contents_mutation = subnet_1_mutation
                    .mutations
                    .iter_mut()
                    .find(|mutation| mutation.key == cup_contents_key)
                    .expect("the destination subnet should have CUP contents");
                let mut cup_contents =
                    CatchUpPackageContents::decode(&cup_contents_mutation.value[..])
                        .expect("failed to decode the CUP contents");
                cup_contents.ecdsa_initializations = vec![EcdsaInitialization::default()];
                cup_contents.chain_key_initializations = vec![ChainKeyInitialization::default()];
                cup_contents_mutation.value = cup_contents.encode_to_vec();
                subnet_1_mutation
            };
            let rt_mutation = {
                fn range(start: u64, end: u64) -> CanisterIdRange {
                    CanisterIdRange {
                        start: CanisterId::from(start),
                        end: CanisterId::from(end),
                    }
                }

                let mut rt = RoutingTable::new();
                rt.insert(range(0, 255), subnet_id_2)
                    .expect("failed to update the routing table");
                rt.insert(range(256, 511), subnet_id_1)
                    .expect("failed to update the routing table");

                RegistryAtomicMutateRequest {
                    mutations: initial_routing_table_mutations(&rt),
                    preconditions: vec![],
                }
            };

            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(subnet_1_mutation)
                    .push_init_mutate_request(rt_mutation)
                    .build(),
            )
            .await;

            let governance_fake = set_up_universal_canister(&runtime).await;
            assert_eq!(
                governance_fake.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            // Step 2: A caller other than governance may not merge subnets.
            check_error_message(
                registry
                    .update_(
                        "merge_subnets",
                        dfn_candid::candid_one,
                        MergeSubnetsPayload {
                            source_subnet: subnet_id_1,
                            destination_subnet: subnet_id_2,
                            height: MERGE_HEIGHT,
                            time_ns: MERGE_TIME_NS,
                            state_hash: MERGED_STATE_HASH.to_vec(),
                            initial_dkg_subnet_id: None,
                        },
                    )
                    .await as Result<(), String>,
                "not authorized",
            );

            // Step 3: Run the code under test: merge subnet 1 into subnet 2.
            try_call_via_universal_canister(
                &governance_fake,
                &registry,
                "merge_subnets",
                Encode!(&MergeSubnetsPayload {
                    source_subnet: subnet_id_1,
                    destination_subnet: subnet_id_2,
                    height: MERGE_HEIGHT,
                    time_ns: MERGE_TIME_NS,
                    state_hash: MERGED_STATE_HASH.to_vec(),
                    initial_dkg_subnet_id: None,
                })
                .unwrap(),
            )
            .await
            .unwrap();

            // Step 4: Verify results: the canisters formerly hosted by subnet 1 are now
            // hosted by subnet 2, and the canisters of subnet 2 stay put.
            check_subnet_for_canisters(
                &registry,
                vec![
                    (CanisterId::from(0), subnet_id_2),
                    (CanisterId::from(255), subnet_id_2),
                    (CanisterId::from(256), subnet_id_2),
                    (CanisterId::from(511), subnet_id_2),
                ],
            )
            .await;

            // Step 5: Verify results: the destination subnet got a recovery CUP at the
            // height, time and state hash of the merged state, with fresh DKG
            // transcripts, and is no longer halted.
            let cup_contents = get_cup_contents(&registry, subnet_id_2).await;
            assert_eq!(cup_contents.height, MERGE_HEIGHT);
            assert_eq!(cup_contents.time, MERGE_TIME_NS);
            assert_eq!(cup_contents.state_hash, MERGED_STATE_HASH);
            assert_eq!(
                cup_contents.cup_type,
                Some(CupType::Recovery(RecoveryArgs {
                    height: MERGE_HEIGHT,
                    time: MERGE_TIME_NS,
                    state_hash: MERGED_STATE_HASH.to_vec(),
                })),
            );
            assert!(
                cup_contents
                    .initial_ni_dkg_transcript_low_threshold
                    .is_some(),
                "the recovery CUP should hold a low threshold DKG transcript",
            );
            assert!(
                cup_contents
                    .initial_ni_dkg_transcript_high_threshold
                    .is_some(),
                "the recovery CUP should hold a high threshold DKG transcript",
            );
            // Chain key initializations in a CUP take precedence over the chain key
            // configuration of the subnet record, so the stale ones seeded above must be
            // gone: merging reshares no chain key.
            assert_eq!(cup_contents.ecdsa_initializations, vec![]);
            assert_eq!(cup_contents.chain_key_initializations, vec![]);

            let subnet_record = get_subnet_record(&registry, subnet_id_2).await;
            assert!(
                !subnet_record.is_halted,
                "the destination subnet should have been brought back online",
            );
            assert!(!subnet_record.halt_at_cup_height);

            Ok(())
        }
    });
}
