use crate::tests::reroute_canister_ranges::check_error_message;
use candid::Encode;
use ic_base_types::SubnetId;
use ic_nns_test_utils::{
    itest_helpers::{
        local_test_on_nns_subnet, set_up_registry_canister, set_up_universal_canister,
        try_call_via_universal_canister,
    },
    registry::{get_value, prepare_registry_with_two_node_sets, routing_table_mutation},
};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_test_utilities::types::ids::subnet_test_id;
use ic_types::CanisterId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        complete_canister_migration::CompleteCanisterMigrationPayload,
        prepare_canister_migration::PrepareCanisterMigrationPayload,
        reroute_canister_ranges::RerouteCanisterRangesPayload,
    },
};

async fn get_canister_migrations(canister: &canister_test::Canister<'_>) -> CanisterMigrations {
    use std::convert::TryFrom;
    let pb_canister_migrations: pb::CanisterMigrations =
        get_value(canister, b"canister_migrations").await;
    CanisterMigrations::try_from(pb_canister_migrations)
        .expect("failed to decode canister migrations")
}

#[test]
fn test_modify_canister_migrations() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let (subnet_1_mutation, subnet_id_1, subnet_id_2_option, _, _) =
                prepare_registry_with_two_node_sets(
                    /* num_nodes_in_subnet = */ 4, /* num_unassigned_nodes = */ 4, true,
                );
            let nns_subnet = subnet_test_id(999);
            let subnet_id_2 = subnet_id_2_option.expect("subnet 2 is not created.");
            let rt_mutation = {
                fn range(start: u64, end: u64) -> CanisterIdRange {
                    CanisterIdRange {
                        start: CanisterId::from(start),
                        end: CanisterId::from(end),
                    }
                }

                let mut rt = RoutingTable::new();
                rt.insert(range(0, 255), nns_subnet)
                    .expect("failed to update the routing table");
                rt.insert(range(256, 511), subnet_id_1)
                    .expect("failed to update the routing table");

                RegistryAtomicMutateRequest {
                    mutations: vec![routing_table_mutation(&rt)],
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
                canister_id_ranges: vec![
                    CanisterIdRange {
                        start: CanisterId::from(10),
                        end: CanisterId::from(11),
                    },
                    CanisterIdRange {
                        start: CanisterId::from(20),
                        end: CanisterId::from(30),
                    },
                ],
                source_subnet: nns_subnet,
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

            let canister_migrations = get_canister_migrations(&registry).await;
            let trace: Vec<SubnetId> = vec![nns_subnet, subnet_id_1];
            assert_eq!(canister_migrations.lookup(CanisterId::from(9)), None);
            for i in 10..=11 {
                assert_eq!(
                    canister_migrations.lookup(CanisterId::from(i)),
                    Some(trace.clone())
                );
            }
            assert_eq!(canister_migrations.lookup(CanisterId::from(12)), None);
            for i in 20..=30 {
                assert_eq!(
                    canister_migrations.lookup(CanisterId::from(i)),
                    Some(trace.clone())
                );
            }

            check_error_message(
                registry
                    .update_(
                        "prepare_canister_migration",
                        dfn_candid::candid_one,
                        payload,
                    )
                    .await as Result<(), String>,
                "not authorized",
            );

            // Invalid request: canister ID ranges are not well formed
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "prepare_canister_migration",
                    Encode!(&PrepareCanisterMigrationPayload {
                        canister_id_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(8),
                            end: CanisterId::from(7)
                        }],
                        source_subnet: nns_subnet,
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
                    "prepare_canister_migration",
                    Encode!(&PrepareCanisterMigrationPayload {
                        canister_id_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(7),
                            end: CanisterId::from(8)
                        }],
                        source_subnet: nns_subnet,
                        destination_subnet: subnet_test_id(9999),
                    })
                    .unwrap(),
                )
                .await,
                "not a known subnet",
            );

            // Invalid request: canisters are not from the source subnet
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "prepare_canister_migration",
                    Encode!(&PrepareCanisterMigrationPayload {
                        canister_id_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(255),
                            end: CanisterId::from(256)
                        }],
                        source_subnet: nns_subnet,
                        destination_subnet: subnet_id_1,
                    })
                    .unwrap(),
                )
                .await,
                "not all canisters to be migrated are hosted by the provided source subnet",
            );

            // Invalid request: some ranges already exist in canister migrations
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "prepare_canister_migration",
                    Encode!(&PrepareCanisterMigrationPayload {
                        canister_id_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(11),
                            end: CanisterId::from(12)
                        }],
                        source_subnet: nns_subnet,
                        destination_subnet: subnet_id_1,
                    })
                    .unwrap(),
                )
                .await,
                "are already being migrated",
            );

            assert_eq!(
                get_canister_migrations(&registry).await,
                canister_migrations
            );

            // Try to reassign the range in the routing table in a conflicting way.
            // Invalid request: routing table mutations do not exactly match canister migrations.
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "reroute_canister_ranges",
                    Encode!(&RerouteCanisterRangesPayload {
                        reassigned_canister_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(10),
                            end: CanisterId::from(10),
                        },],
                        source_subnet: nns_subnet,
                        destination_subnet: subnet_id_1,
                    })
                    .unwrap(),
                )
                .await,
                "not covered by any existing canister migrations",
            );

            // Test removing canister migrations entries.
            let canister_id_ranges = vec![
                CanisterIdRange {
                    start: CanisterId::from(10),
                    end: CanisterId::from(11),
                },
                CanisterIdRange {
                    start: CanisterId::from(20),
                    end: CanisterId::from(30),
                },
            ];

            let payload = CompleteCanisterMigrationPayload {
                canister_id_ranges: canister_id_ranges.clone(),
                migration_trace: vec![nns_subnet, subnet_id_2],
            };

            // Try to reassign the range in the routing table in a conflicting way.
            // Invalid request: routing table mutations do not match canister migrations.
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "complete_canister_migration",
                    Encode!(&payload).unwrap(),
                )
                .await,
                "do not match the provided trace",
            );

            // Check that nothing is removed if there is any inconsistency.
            assert_eq!(
                get_canister_migrations(&registry).await,
                canister_migrations
            );

            let payload = CompleteCanisterMigrationPayload {
                canister_id_ranges,
                migration_trace: vec![nns_subnet, subnet_id_1],
            };

            try_call_via_universal_canister(
                &governance_fake,
                &registry,
                "complete_canister_migration",
                Encode!(&payload).unwrap(),
            )
            .await
            .unwrap();

            let canister_migrations = get_canister_migrations(&registry).await;

            for i in 10..=11 {
                assert_eq!(canister_migrations.lookup(CanisterId::from(i)), None);
            }
            for i in 20..=30 {
                assert_eq!(canister_migrations.lookup(CanisterId::from(i)), None);
            }

            Ok(())
        }
    });
}
