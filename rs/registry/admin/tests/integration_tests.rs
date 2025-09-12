use candid::{Encode, Principal};
use ic_admin::initialize_registry_local_store;
use ic_base_types::RegistryVersion;
use ic_nervous_system_agent::{CallCanisters, pocketic_impl::PocketIcAgent};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{NnsInstaller, install_canister};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_registry_local_store::{KeyMutation, LocalStoreImpl, LocalStoreReader};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use std::{env, io::Write, process::Command};
use tempfile::{NamedTempFile, TempDir, tempdir};
use url::Url;

async fn setup() -> (PocketIc, Url) {
    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    let endpoint = pocket_ic.make_live(None).await;
    (pocket_ic, endpoint)
}

fn create_neuron_1_pem_file() -> NamedTempFile {
    let contents: String = TEST_NEURON_1_OWNER_KEYPAIR.to_pem();
    let mut pem_file = NamedTempFile::new().expect("Unable to create a temporary file");
    pem_file
        .write_all(contents.as_bytes())
        .expect("Unable to write to file");
    pem_file
}

#[tokio::test]
async fn test_propose_to_rent_subnet_can_read_pem_file() {
    let (_pocket_ic, url) = setup().await;

    let ic_admin_path = env::var("IC_ADMIN_BIN").expect("IC_ADMIN_BIN not set");
    let pem_file = create_neuron_1_pem_file();
    let pem_file_path = pem_file
        .path()
        .to_str()
        .expect("Failed to get pem file path");
    let neuron_id = TEST_NEURON_1_ID.to_string();

    let output = Command::new(ic_admin_path)
        .args([
            "--nns-url",
            url.as_ref(),
            "--secret-key-pem",
            pem_file_path,
            "propose-to-rent-subnet",
            "--proposer",
            &neuron_id,
            "--summary",
            "This is the summary.",
            "--rental-condition-id",
            "App13CH",
            "--user",
            &Principal::anonymous().to_string(), // Not related to the pem file, will be whitelisted on the subnet
        ])
        .output()
        .expect("Failed to run ic-admin");

    let stderr: String = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        output.status.code().unwrap(),
        0,
        "ic-admin's status code was not 0"
    );
    assert!(stderr.contains("response: Ok(proposal 1)"));
}

// The only WASM this needs is test Registry.
// This also needs ic-admin.
#[tokio::test]
async fn test_update_registry_local_store_handles_chunked_records() {
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

    // Step 1.4: Initialize registry local store.
    let root_key = pocket_ic.root_key().await.unwrap();
    let registry_local_store: TempDir = tempdir().unwrap();
    initialize_registry_local_store(registry_local_store.path(), root_key);

    // Step 2: Call code under test: `ic-admin update-registry-local-store`.
    let endpoint = pocket_ic.make_live(None).await; // Make PocketIc callable by ic-admin.
    let ic_admin_path = env::var("IC_ADMIN_BIN").expect("IC_ADMIN_BIN not set");
    let output = Command::new(ic_admin_path)
        .args([
            "--nns-urls",
            endpoint.as_ref(),
            "update-registry-local-store",
            registry_local_store.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:#?}");

    // Step 3: Verify result(s): Read registry local store. It should have the
    // data that was inserted into Registry canister during step 1.3.

    let local_store = LocalStoreImpl::new(registry_local_store.path());
    let composite_mutations: Vec<Vec<KeyMutation>> = local_store
        .get_changelog_since_version(RegistryVersion::from(0))
        .unwrap();
    assert_eq!(composite_mutations.len(), 2);
    assert!(
        composite_mutations.last().unwrap()
            == // assert_eq is not used, because that would generate tons of spam.
            &vec![
                KeyMutation {
                    key: "daniel_wong_42".to_string(),
                    value: Some(MEGA_BLOB.clone()),
                }
            ]
    );
}
