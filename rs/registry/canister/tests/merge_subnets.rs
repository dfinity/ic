use candid::Encode;
use ic_nns_test_utils::{
    itest_helpers::{
        set_up_registry_canister, set_up_universal_canister, state_machine_test_on_nns_subnet,
        try_call_via_universal_canister,
    },
    registry::{initial_routing_table_mutations, prepare_registry_with_two_node_sets},
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_types::CanisterId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::merge_subnets::MergeSubnetsPayload,
};

mod common;
use common::test_helpers::{check_error_message, check_subnet_for_canisters};

/// Exercises the `merge_subnets` endpoint end to end. The payload validation
/// itself is covered by the unit tests of `Registry::merge_subnets`, so this test
/// only covers what those cannot: that the endpoint is reachable with a Candid
/// encoded payload, that only governance may call it, and that the resulting
/// routing table is visible through the canister's query API.
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

            Ok(())
        }
    });
}
