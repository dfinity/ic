use candid::Encode;
use ic_nervous_system_agent::{CallCanisters, pocketic_impl::PocketIcAgent};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_get_value_handles_chunked_records() {
    // Step 1: Prepare the world.

    // Step 1.1: Create a simulated ICP (to wit, PocketIc).
    let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    // Step 1.2: Install Registry canister on PocketIc.
    let mut nns_configuration = NnsInitPayloadsBuilder::new();
    let registry_init_args = nns_configuration
        .with_initial_invariant_compliant_mutations()
        .build()
        .registry;
    install_canister(
        &pocket_ic,
        "Registry",
        REGISTRY_CANISTER_ID,
        Encode!(&registry_init_args).unwrap(),
        build_test_registry_wasm(),
        Some(REGISTRY_CANISTER_ID.get()),
    )
    .await;

    // Step 1.3: Add some (chunked) test data to the Registry canister.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
            },
        )
        .await
        .unwrap();

    // Step 1.4: Make pocket_ic callable by RegistryCanister.
    let endpoint = pocket_ic.make_live(None).await; // Make PocketIc callable by ic-admin.

    // Step 2: Call the code under test.
    let root_key = pocket_ic.root_key().await.unwrap();
    let registry_canister = RegistryCanister::new_with_agent_transformer(vec![endpoint], |agent| {
        agent.set_root_key(root_key.clone());
        agent
    });
    let query_result = registry_canister
        .get_value(b"daniel_wong_42".to_vec(), None)
        .await
        .unwrap();
    let update_result = registry_canister
        .get_value_with_update(b"daniel_wong_42".to_vec(), None)
        .await
        .unwrap();

    // Step 3: Verify result(s).

    let (content, version) = query_result;
    // assert_eq is intentionally not used here, because it would generate tons of spam.
    assert!(content == *MEGA_BLOB, "len={}", content.len());
    assert_eq!(version, 2);

    let (content, version) = update_result;
    // assert_eq is intentionally not used here, because it would generate tons of spam.
    assert!(content == *MEGA_BLOB, "len={}", content.len());
    assert_eq!(version, 2);
}
