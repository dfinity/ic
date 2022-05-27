use candid::Encode;
use ic_nns_test_utils::{
    itest_helpers::{
        local_test_on_nns_subnet, set_up_registry_canister, set_up_universal_canister,
        try_call_via_universal_canister,
    },
    registry::{get_value, prepare_registry, routing_table_mutation},
};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_test_utilities::types::ids::subnet_test_id;
use ic_types::CanisterId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        prepare_canister_migration::PrepareCanisterMigrationPayload,
        reroute_canister_ranges::RerouteCanisterRangesPayload,
    },
};

pub(crate) async fn get_routing_table(canister: &canister_test::Canister<'_>) -> RoutingTable {
    use std::convert::TryFrom;
    let pb_routing_table: pb::RoutingTable = get_value(canister, b"routing_table").await;
    RoutingTable::try_from(pb_routing_table).expect("failed to decode routing table")
}

pub(crate) fn check_error_message<T: std::fmt::Debug>(
    result: Result<T, String>,
    expected_substring: &str,
) {
    match result {
        Ok(value) => panic!(
            "expected the call to fail with message '{}', got Ok({:?})",
            expected_substring, value
        ),
        Err(e) => assert!(
            e.contains(expected_substring),
            "expected the call to fail with message '{}', got:  {}",
            expected_substring,
            e
        ),
    }
}

#[test]
fn test_reroute_canister_ranges() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let (subnet_1_mutation, subnet_id_1, _, _) = prepare_registry(
                /* num_nodes_in_subnet = */ 4, /* num_unassigned_nodes = */ 0,
            );
            let nns_subnet = subnet_test_id(999);
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
                canister_id_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(10),
                    end: CanisterId::from(11),
                }],
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

            let payload = RerouteCanisterRangesPayload {
                reassigned_canister_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(10),
                    end: CanisterId::from(11),
                }],
                source_subnet: nns_subnet,
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

            let routing_table = get_routing_table(&registry).await;

            assert_eq!(
                routing_table.route(CanisterId::from(9).into()),
                Some(nns_subnet)
            );
            assert_eq!(
                routing_table.route(CanisterId::from(10).into()),
                Some(subnet_id_1)
            );
            assert_eq!(
                routing_table.route(CanisterId::from(11).into()),
                Some(subnet_id_1)
            );
            assert_eq!(
                routing_table.route(CanisterId::from(12).into()),
                Some(nns_subnet)
            );

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
                            source_subnet: nns_subnet,
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
                    "reroute_canister_ranges",
                    Encode!(&RerouteCanisterRangesPayload {
                        reassigned_canister_ranges: vec![CanisterIdRange {
                            start: CanisterId::from(12),
                            end: CanisterId::from(15),
                        },],
                        source_subnet: nns_subnet,
                        destination_subnet: subnet_test_id(9999),
                    })
                    .unwrap(),
                )
                .await,
                "not a known subnet",
            );

            assert_eq!(get_routing_table(&registry).await, routing_table);

            Ok(())
        }
    });
}
