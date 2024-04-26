// TODO(NNS1-2986) remove this file once it's published
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    install_nns_canisters, upgrade_nns_canister_to_tip_of_master_or_panic,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::registry::invariant_compliant_mutation_with_subnet_id;
use ic_protobuf::registry::{crypto::v1::EcdsaKeyId, subnet::v1::EcdsaConfig};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use pocket_ic::PocketIcBuilder;

#[test]
fn test_registry_ecdsa_to_chain_key_migration() {
    // We don't actually need an *SNS* subnet; we expect two subnet records in the Registry.
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let subnet_id = pocket_ic.topology().get_sns().unwrap();
    let subnet_id = PrincipalId::from(subnet_id);
    let subnet_id = SubnetId::from(subnet_id);

    let ecdsa_config = Some(EcdsaConfig {
        quadruples_to_create_in_advance: 456,
        key_ids: vec![EcdsaKeyId {
            curve: 1,
            name: "test_curve".to_string(),
        }],
        max_queue_size: 100,
        signature_request_timeout_ns: Some(10_000),
        idkg_key_rotation_period_ms: Some(20_000),
    });

    let mutations = invariant_compliant_mutation_with_subnet_id(0, subnet_id, ecdsa_config);

    let initial_mutation_requests = vec![RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    }];

    let with_mainnet_nns_canisters = true;

    install_nns_canisters(
        &pocket_ic,
        vec![],
        with_mainnet_nns_canisters,
        Some(initial_mutation_requests),
    );

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, REGISTRY_CANISTER_ID);

    // The test passes if and only if the upgrade succeeded.
}
