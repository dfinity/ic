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
    mutations::reroute_canister_range::RerouteCanisterRangePayload,
};

async fn get_routing_table(canister: &canister_test::Canister<'_>) -> RoutingTable {
    use std::convert::TryFrom;
    let pb_routing_table: pb::RoutingTable = get_value(canister, b"routing_table").await;
    RoutingTable::try_from(pb_routing_table).expect("failed to decode routing table")
}

fn check_error_message<T: std::fmt::Debug>(result: Result<T, String>, expected_substring: &str) {
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
fn test_reroute_canister_range() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let (subnet_1_mutation, subnet_id_1, _, _) = prepare_registry(
                /* num_nodes_in_subnet = */ 4, /* num_anassigned_nodes = */ 0,
            );
            let nns_subnet = subnet_test_id(1);

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

            let payload = RerouteCanisterRangePayload {
                range_start_inclusive: CanisterId::from(10).into(),
                range_end_inclusive: CanisterId::from(11).into(),
                destination_subnet: subnet_id_1.get(),
            };

            try_call_via_universal_canister(
                &governance_fake,
                &registry,
                "reroute_canister_range",
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
                        "reroute_canister_range",
                        dfn_candid::candid_one,
                        RerouteCanisterRangePayload {
                            range_start_inclusive: CanisterId::from(12).into(),
                            range_end_inclusive: CanisterId::from(15).into(),
                            destination_subnet: subnet_id_1.get(),
                        },
                    )
                    .await as Result<(), String>,
                "not authorized",
            );

            // Invalid request: start > end
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "reroute_canister_range",
                    Encode!(&RerouteCanisterRangePayload {
                        range_start_inclusive: CanisterId::from(15).into(),
                        range_end_inclusive: CanisterId::from(10).into(),
                        destination_subnet: subnet_id_1.get(),
                    })
                    .unwrap(),
                )
                .await,
                "start > end",
            );

            // Invalid request: non-existing subnet
            check_error_message(
                try_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "reroute_canister_range",
                    Encode!(&RerouteCanisterRangePayload {
                        range_start_inclusive: CanisterId::from(12).into(),
                        range_end_inclusive: CanisterId::from(15).into(),
                        destination_subnet: subnet_test_id(9999).get(),
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
