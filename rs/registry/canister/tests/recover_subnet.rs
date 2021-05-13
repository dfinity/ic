use candid::Encode;
use ic_nns_common::registry::SUBNET_LIST_KEY;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet_with_mutations,
        set_up_registry_canister, set_up_universal_canister,
    },
    registry::{get_value, prepare_registry},
};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_catch_up_package_contents_key, make_subnet_record_key};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_recover_subnet::RecoverSubnetPayload,
};

/// Test that calling "recover_subnet" produces the expected Registry mutations,
/// namely that a subnet's `CatchUpPackageContents` and node membership are
/// updated as expected.
///
/// A note on the use of local_test_on_nns_subnet_with_mutations:
///
/// During this test, we stand-up an IC (the NNS subnet), install the Registry
/// canister and Subnet Handler, and call the "recover_subnet" Subnet Handler
/// method. Any instance of the IC needs a Registry to run, and because when we
/// create a new IC there doesn't exist a Registry Canister yet (because there
/// is no IC to run it on), the new IC uses a fake/static Registry. Once we
/// start this IC, we then deploy the Registry _canister_ onto it, because the
/// Subnet Handler needs the Registry _canister_ to function. However, this puts
/// us into an awkward position where there are 2 registries: the fake/static
/// one used by the underlying IC, and the Registry canister installed on top of
/// this IC.
///
/// During this test, we want to assert that nodes can be replaced in a subnet,
/// and that new DKG material is generated for these nodes/subnet. The required
/// set-up for this is to create some node records and node cypto info and store
/// it in the Registry canister. These are the replacement nodes we want to
/// replace the subnet's old nodes. With everything set-up, we call
/// "recover_subnet", which calls ic00's "setup_initial_dkg" to generate the DKG
/// info for these nodes.
///
/// "setup_initial_dkg" is an async call that takes a list of node IDs and
/// eventually delivers these nodes to the Consensus component of the underlying
/// IC. To generate DKG material, Consensus looks up the node records and node
/// crypto info for these nodes in the Registry. HOWEVER, these nodes are not in
/// the IC's fake/static Registry! These nodes were only added to the Registry
/// _canister_, not the IC's fake/static Registry. In order to ensure that
/// Consensus has access to these node records, we use
/// `common::prepare_registry` to get the list of node mutations used by this
/// test. We then use `local_test_on_nns_subnet_with_mutations` to apply these
/// mutations to the fake/static Registry used by the underlying IC, and then in
/// this test, we also apply these same mutations to the Registry _canister_.
/// This ensures that both the fake/static Registry and Registry _canister_ are
/// sync'd on the same node records.
#[test]
fn test_recover_subnet_with_replacement_nodes() {
    let num_nodes_in_subnet = 4 as usize;
    let num_unassigned_nodes = 5 as usize;
    let (init_mutate, subnet_id, unassigned_node_ids, node_mutations) =
        prepare_registry(num_nodes_in_subnet, num_unassigned_nodes);

    local_test_on_nns_subnet_with_mutations(node_mutations, move |runtime| {
        async move {
            // In order to correctly allow the subnet handler to call atomic_mutate, we
            // must first create canisters to get their IDs, and only then install them.
            // This way, we pass the initial payload to the registry so it would allow
            // mutation by the subnet handler.
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            // Install the universal canister in place of the governance canister
            let fake_governance_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the governance canister, it can
            // impersonate it
            assert_eq!(
                fake_governance_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            let cup_contents_key = make_catch_up_package_contents_key(subnet_id).into_bytes();
            let initial_cup_contents: CatchUpPackageContents =
                get_value(&registry, &cup_contents_key).await;

            // Ensure that the subnet record is there
            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, SUBNET_LIST_KEY.as_bytes()).await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, &make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet as usize);

            let payload = RecoverSubnetPayload {
                subnet_id: subnet_id.get(),
                height: 10,
                time_ns: 1200,
                state_hash: vec![10, 20, 30],
                replacement_nodes: Some(unassigned_node_ids.clone()),
                registry_store_uri: None,
            };

            assert!(
                forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "recover_subnet",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, SUBNET_LIST_KEY.as_bytes()).await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, &make_subnet_record_key(subnet_id).as_bytes())
                    .await;

            // Assert that `membership` has been replaced by `unassigned_node_ids`
            assert_eq!(subnet_record.membership.len(), num_unassigned_nodes);
            for node_id in unassigned_node_ids {
                let node_id = node_id.get().to_vec();
                assert!(subnet_record.membership.iter().any(|x| *x == node_id));
            }

            let updated_cup_contents: CatchUpPackageContents =
                get_value(&registry, &cup_contents_key).await;

            // Assert that the CatchUpPackageContents was updated as expected
            assert_eq!(payload.height, updated_cup_contents.height);
            assert_eq!(payload.time_ns, updated_cup_contents.time);
            assert_eq!(payload.state_hash, updated_cup_contents.state_hash);

            // DKG should have been changed
            assert_ne!(
                initial_cup_contents.initial_ni_dkg_transcript_low_threshold,
                updated_cup_contents.initial_ni_dkg_transcript_low_threshold
            );
            assert_ne!(
                initial_cup_contents.initial_ni_dkg_transcript_high_threshold,
                updated_cup_contents.initial_ni_dkg_transcript_high_threshold
            );

            Ok(())
        }
    });
}
