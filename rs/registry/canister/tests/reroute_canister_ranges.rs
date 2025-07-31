use candid::Encode;
use ic_nns_test_utils::{
    itest_helpers::{
        local_test_on_nns_subnet, set_up_registry_canister, set_up_universal_canister,
        try_call_via_universal_canister,
    },
    registry::{initial_routing_table_mutations, prepare_registry_with_two_node_sets},
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::CanisterId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        prepare_canister_migration::PrepareCanisterMigrationPayload,
        reroute_canister_ranges::RerouteCanisterRangesPayload,
    },
};

mod common;
use common::test_helpers::{check_error_message, check_subnet_for_canisters};

#[test]
fn test_reroute_canister_ranges() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let (subnet_1_mutation, subnet_id_1, subnet_id_2_option, _, _) =
                prepare_registry_with_two_node_sets(
                    /* num_nodes_in_subnet = */ 4, /* num_unassigned_nodes = */ 4, true,
                );
            let subnet_id_2 = subnet_id_2_option.unwrap();
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

            // Add canister migrations entries.
            let payload = PrepareCanisterMigrationPayload {
                canister_id_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(10),
                    end: CanisterId::from(11),
                }],
                source_subnet: subnet_id_2,
                destination_subnet: subnet_id_1,
            };

            try_call_via_universal_canister(
                &governance_fake,
                &registry,
                "prepare_canister_migration",
                Encode!(&payload).unwrap(),
            )
            .await
            .unwrap();

            let payload = RerouteCanisterRangesPayload {
                reassigned_canister_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(10),
                    end: CanisterId::from(11),
                }],
                source_subnet: subnet_id_2,
                destination_subnet: subnet_id_1,
            };

            try_call_via_universal_canister(
                &governance_fake,
                &registry,
                "reroute_canister_ranges",
                Encode!(&payload).unwrap(),
            )
            .await
            .unwrap();

            check_subnet_for_canisters(
                &registry,
                vec![
                    (CanisterId::from(9), subnet_id_2),
                    (CanisterId::from(10), subnet_id_1),
                    (CanisterId::from(11), subnet_id_1),
                    (CanisterId::from(12), subnet_id_2),
                ],
            )
            .await;

            check_error_message(
                registry
                    .update_(
                        "reroute_canister_ranges",
                        dfn_candid::candid_one,
                        RerouteCanisterRangesPayload {
                            reassigned_canister_ranges: vec![CanisterIdRange {
                                start: CanisterId::from(12),
                                end: CanisterId::from(15),
                            }],
                            source_subnet: subnet_id_2,
                            destination_subnet: subnet_id_1,
                        },
                    )
                    .await as Result<(), String>,
                "not authorized",
            );

            // Invalid request: canister ID ranges are not well formed
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "reroute_canister_ranges",
                    Encode!(&RerouteCanisterRangesPayload {
                        reassigned_canister_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(15),
                            end: CanisterId::from(10),
                        },],
                        source_subnet: subnet_id_2,
                        destination_subnet: subnet_id_1,
                    })
                    .unwrap(),
                )
                .await,
                "not well formed",
            );

            // Invalid request: non-existing subnet
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "reroute_canister_ranges",
                    Encode!(&RerouteCanisterRangesPayload {
                        reassigned_canister_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(12),
                            end: CanisterId::from(15),
                        },],
                        source_subnet: subnet_id_2,
                        destination_subnet: subnet_test_id(9999),
                    })
                    .unwrap(),
                )
                .await,
                "not a known subnet",
            );

            check_subnet_for_canisters(
                &registry,
                vec![
                    (CanisterId::from(9), subnet_id_2),
                    (CanisterId::from(10), subnet_id_1),
                    (CanisterId::from(11), subnet_id_1),
                    (CanisterId::from(12), subnet_id_2),
                ],
            )
            .await;

            Ok(())
        }
    });
}
