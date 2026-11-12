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
use ic_types::{CanisterId, SubnetId};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::merge_subnets::MergeSubnetsPayload,
    pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister},
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
                    4,    // num_nodes_in_subnet1
                    4,    // num_nodes_in_subnet2
                    true, // assign_nodes_to_subnet2
                );
            let subnet_id_2 = subnet_id_2_option.unwrap();
            let routing_table_mutation = {
                fn range(start: u64, end: u64) -> CanisterIdRange {
                    CanisterIdRange {
                        start: CanisterId::from(start),
                        end: CanisterId::from(end),
                    }
                }

                let mut routing_table = RoutingTable::new();
                routing_table
                    .insert(range(0, 255), subnet_id_2)
                    .expect("failed to update the routing table");
                routing_table
                    .insert(range(256, 511), subnet_id_1)
                    .expect("failed to update the routing table");

                RegistryAtomicMutateRequest {
                    mutations: initial_routing_table_mutations(&routing_table),
                    preconditions: vec![],
                }
            };

            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(subnet_1_mutation)
                    .push_init_mutate_request(routing_table_mutation)
                    .build(),
            )
            .await;

            let governance_fake = set_up_universal_canister(&runtime).await;
            assert_eq!(
                governance_fake.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            // Step 2: Run the code under test.

            // Step 2.1: The sad case: caller is not the Governance canister.
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

            // Step 2.2: The happy case: merging subnet 1 into subnet 2 succeeds,
            // because Governance is the caller.
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

            // Step 3: Verify results.

            // Step 3.1: The canisters formerly hosted by subnet 1 are now hosted by
            // subnet 2, and the canisters of subnet 2 stay put.
            check_subnet_for_canisters(
                &registry,
                (0..=511_u64)
                    .map(|canister_id| (CanisterId::from(canister_id), subnet_id_2))
                    .collect::<Vec<(CanisterId, SubnetId)>>(),
            )
            .await;

            // Step 3.2: Canister IDs outside the merged ranges are still not routed
            // to any subnet.
            let subnet_for_canister: Result<SubnetForCanister, String> = registry
                .query_(
                    "get_subnet_for_canister",
                    dfn_candid::candid_one,
                    GetSubnetForCanisterRequest {
                        principal: Some(CanisterId::from(512).get()),
                    },
                )
                .await
                .unwrap();
            check_error_message(subnet_for_canister, "not assigned to any subnet");

            Ok(())
        }
    });
}
