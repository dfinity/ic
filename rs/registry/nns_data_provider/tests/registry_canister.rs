use candid::Encode;
use ic_certification_test_utils::generate_root_of_trust;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_nervous_system_agent::{CallCanisters, pocketic_impl::PocketIcAgent};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;

/// Creates a simulated ICP (to wit, PocketIc), and installs the Registry canister on it.
async fn new_pocket_ic_with_registry() -> PocketIc {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

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

    pocket_ic
}

#[tokio::test]
async fn test_get_value_handles_chunked_records() {
    // Step 1: Prepare the world.

    // Step 1.1: Create a simulated ICP (to wit, PocketIc), and install Registry canister on it.
    let mut pocket_ic = new_pocket_ic_with_registry().await;

    // Step 1.2: Add some (chunked) test data to the Registry canister.
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

    // Step 1.3: Make pocket_ic callable by RegistryCanister.
    let endpoint = pocket_ic.make_live(None).await; // Make PocketIc callable by ic-admin.

    // Step 2: Call the code under test.

    let registry_canister = RegistryCanister::new(vec![endpoint]);
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

/// Responses to update calls are certified. Given the NNS public key, `get_value_with_update`
/// verifies the certificate against it, and rejects responses that it does not sign.
#[tokio::test]
async fn test_get_value_with_update_verifies_certificate() {
    // Step 1: Prepare the world.

    // Step 1.1: Create a simulated ICP (to wit, PocketIc), and install Registry canister on it.
    let mut pocket_ic = new_pocket_ic_with_registry().await;

    // Step 1.2: Add some test data to the Registry canister.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::UpsertSmall,
            },
        )
        .await
        .unwrap();

    // Step 1.3: Make pocket_ic callable by RegistryCanister, once with the key that signs its
    // certificates, and once with an unrelated key.
    let endpoint = pocket_ic.make_live(None).await;
    let root_key_der = pocket_ic
        .root_key()
        .await
        .expect("PocketIc has no root key");
    let root_public_key = parse_threshold_sig_key_from_der(&root_key_der).unwrap();
    let (unrelated_public_key, _unrelated_secret_key) =
        generate_root_of_trust(&mut rand::thread_rng());

    let registry_canister_with_root_key =
        RegistryCanister::new_with_agent_transformer(vec![endpoint.clone()], |agent| {
            agent.with_nns_public_key(root_public_key)
        });
    let registry_canister_with_unrelated_key =
        RegistryCanister::new_with_agent_transformer(vec![endpoint], |agent| {
            agent.with_nns_public_key(unrelated_public_key)
        });

    // Step 2: Call the code under test.

    let result_with_root_key = registry_canister_with_root_key
        .get_value_with_update(b"daniel_wong_42".to_vec(), None)
        .await;
    let result_with_unrelated_key = registry_canister_with_unrelated_key
        .get_value_with_update(b"daniel_wong_42".to_vec(), None)
        .await;

    // Step 3: Verify result(s).

    let (content, _version) = result_with_root_key.unwrap();
    assert_eq!(content, b"small value".to_vec());

    let error = result_with_unrelated_key.unwrap_err();
    assert!(
        error.to_string().contains("verifying certificate failed"),
        "{error}"
    );
}
