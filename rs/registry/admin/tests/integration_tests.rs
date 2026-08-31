use candid::{Encode, Principal};
use canister_test::Wasm;
use ic_admin::initialize_registry_local_store;
use ic_base_types::RegistryVersion;
use ic_nervous_system_agent::{CallCanisters, pocketic_impl::PocketIcAgent};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    NnsInstaller, install_canister, install_canister_on_subnet, nns,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_registry_local_store::{KeyMutation, LocalStoreImpl, LocalStoreReader};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use std::{env, io::Write, process::Command, time::Duration};
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

    let ic_admin_path = env::var("IC_ADMIN_PATH").expect("IC_ADMIN_PATH not set");
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
    let ic_admin_path = env::var("IC_ADMIN_PATH").expect("IC_ADMIN_PATH not set");
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

/// This exercises the skip_pre_upgrade and wasm_memory_persistence upgrade options.
#[tokio::test]
async fn test_upgrade_canister_with_options() {
    // Step 1: Prepare the world.

    let (pocket_ic, nns_url) = setup().await;
    let nns_subnet_id = pocket_ic.topology().await.get_nns().unwrap();

    // This module does a few key things:
    // 1. Writes to main memory when it is installed.
    // 2. Declares that it uses Enhanced Orthogonal Persistence, thereby
    //    requiring wasm_memory_persistence to be specified when it is next
    //    upgraded.
    // 3. Unconditionally panics in its pre_upgrade hook, so that any
    //    subsequent upgrade can only succeed if --skip-pre-upgrade is
    //    actually respected.
    let original_code = wat::parse_str(
        r#"
        (module
            (func $initialize
                (i32.store (i32.const 0) (i32.const 0xCAFE_BABE))
            )
            (start $initialize)
            (func $pre_upgrade
                unreachable
            )
            (export "canister_pre_upgrade" (func $pre_upgrade))
            (memory 1)
            (@custom "icp:private enhanced-orthogonal-persistence" "")
        )
        "#,
    )
    .unwrap();

    let canister_id = install_canister_on_subnet(
        &pocket_ic,
        nns_subnet_id,
        vec![],
        Some(Wasm::from_bytes(original_code)),
        vec![ROOT_CANISTER_ID.get()],
    )
    .await;

    // When this is installed, it checks whether the data written by
    // original_code survived the upgrade. If not, it panics.
    let new_code = wat::parse_str(
        r#"
        (module
            (func $check
                (if (i32.ne (i32.load (i32.const 0)) (i32.const 0xCAFE_BABE))
                    (then unreachable)
                )
            )
            (start $check)
            (memory 1)
            (@custom "icp:private enhanced-orthogonal-persistence" "")
        )
        "#,
    )
    .unwrap();
    let mut new_code_file = NamedTempFile::new().unwrap();
    new_code_file.write_all(&new_code).unwrap();
    let new_code_sha256 = hex::encode(Wasm::from_bytes(new_code.clone()).sha256_hash());

    // Step 2: Call code under test: Pass --skip-pre-upgrade and
    // --wasm-memory-persistence to ic-admin, in particular its
    // propose-to-change-nns-canister subcommand (which maps to the InstallCode
    // proposal type).

    let ic_admin_path = env::var("IC_ADMIN_PATH").expect("IC_ADMIN_PATH not set");
    let output = Command::new(ic_admin_path)
        .args([
            "--nns-url",
            nns_url.as_ref(),
            "propose-to-change-nns-canister",
            "--test-neuron-proposer",
            "--mode",
            "upgrade",
            "--canister-id",
            &canister_id.to_string(),
            "--wasm-module-path",
            new_code_file.path().to_str().unwrap(),
            "--wasm-module-sha256",
            &new_code_sha256,
            "--skip-pre-upgrade",
            "--wasm-memory-persistence",
            "keep",
            "--summary",
            "Upgrade the test canister, keeping its main memory.",
        ])
        .output()
        .expect("Failed to run ic-admin");
    assert!(
        output.status.success(),
        "ic-admin failed: {:#?}",
        String::from_utf8(output.stdout).unwrap()
    );

    // Step 3: Verify result(s). In particular, check that the canister has the
    // new code. This shows that the two flags work, as follows:
    //
    // 1. If --skip-pre-upgrade were not respsected, then, the upgrade would
    //    have been thwarted by the panic in pre-upgrade.
    //
    // 2. If --wasm-memory-persistence were not respected, then, the upgrade
    //    would fail during post-upgrade, because that explodes if it does not
    //    see the value written by original_code.

    // Extract the proposal ID from the output of ic-admin.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let proposal_id = stdout
        .lines()
        .last()
        // The last line looks like "proposal proposal 1".
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_else(|| panic!("Unexpected ic-admin stdout: {stdout:#?}"))
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("Unexpected ic-admin stdout: {stdout:#?}"));

    // The proposal is supposed to be executed before long.
    nns::governance::wait_for_proposal_execution(&pocket_ic, proposal_id)
        .await
        .unwrap();

    // There is an old bug where InstallCode proposals are marked as
    // successfully executed before the canister upgrade actually succeeds.
    // Therefore, to really verify, we must look at what's currently installed.
    // This could take some time, so we check in a loop.
    let mut last_seen_module_hash = None;
    let mut has_new_code = false;
    for attempt in 0..60 {
        // Request information about the canister that we tried to upgrade via
        // proposal.
        let status = pocket_ic
            .canister_status(canister_id.into(), Some(ROOT_CANISTER_ID.get().0))
            .await
            .unwrap();

        // Check whether the canister has the new code yet.
        last_seen_module_hash = status.module_hash.map(hex::encode);
        if last_seen_module_hash.as_deref() == Some(new_code_sha256.as_str()) {
            has_new_code = true;
            break;
        }

        // Wait before polling again. Because pocket_ic is live, to pass time in
        // the simulated ICP, we simply allow time to pass in real life.
        eprintln!(
            "Canister does not have the new code after {} attempts. Will \
             check again soon...",
            attempt + 1,
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        has_new_code,
        "Canister {canister_id} does not have the expected module hash after retrying. \
         last_seen_module_hash = {last_seen_module_hash:?}, expected = {new_code_sha256:?}"
    );
    eprintln!("Yay! Canister has new code! This means that no panic occurred during upgrade.");
}
