use candid::Principal;
use canister_test::Wasm;
use ic_nervous_system_agent::nns::registry::get_subnet_for_canister;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns::governance::{
    find_neuron_with_majority_voting_power, wait_for_proposal_execution,
};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    await_with_timeout, install_canister_on_subnet, nns, sns, NnsInstaller,
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::add_wasms_to_sns_wasm,
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_sns_cli::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use ic_sns_cli::upgrade_sns_controlled_canister::{
    self, UpgradeSnsControlledCanisterArgs, UpgradeSnsControlledCanisterInfo,
};
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use std::collections::BTreeSet;
use std::path::PathBuf;
use url::Url;

const MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 20;
const MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 5 * 60;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

fn very_large_wasm_path() -> PathBuf {
    let image_classification_canister_wasm_path =
        std::env::var("IMAGE_CLASSIFICATION_CANISTER_WASM_PATH")
            .expect("Please ensure that this Bazel test target correctly specifies env and data.");

    PathBuf::from(image_classification_canister_wasm_path)
}

fn very_large_wasm_bytes() -> Vec<u8> {
    let wasm_path = very_large_wasm_path();
    std::fs::read(&wasm_path).expect("Failed to read WASM file")
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Uploads `wasm` into the store canister, one [`CHUNK_SIZE`]-sized chunk at a time.
///
/// Returns the vector of uploaded chunk hashes.
async fn upload_wasm_as_chunks(
    pocket_ic: &PocketIc,
    store_controller_id: Principal,
    store_canister_id: Principal,
    wasm: Wasm,
    num_chunks_expected: usize,
) -> Vec<Vec<u8>> {
    let sender = Some(store_controller_id);

    let mut uploaded_chunk_hashes = Vec::new();

    for chunk in wasm.bytes().chunks(CHUNK_SIZE) {
        let uploaded_chunk_hash = pocket_ic
            .upload_chunk(store_canister_id, sender, chunk.to_vec())
            .await
            .unwrap();

        uploaded_chunk_hashes.push(uploaded_chunk_hash);
    }

    // Smoke test
    {
        let stored_chunk_hashes = pocket_ic
            .stored_chunks(store_canister_id, sender)
            .await
            .unwrap()
            .into_iter()
            .map(|hash| format_full_hash(&hash[..]))
            .collect::<Vec<_>>();

        let stored_chunk_hashes = BTreeSet::from_iter(stored_chunk_hashes.iter());

        let uploaded_chunk_hashes = uploaded_chunk_hashes
            .iter()
            .map(|hash| format_full_hash(&hash[..]))
            .collect::<Vec<_>>();
        let uploaded_chunk_hashes = BTreeSet::from_iter(uploaded_chunk_hashes.iter());

        assert!(uploaded_chunk_hashes.is_subset(&stored_chunk_hashes));
        assert_eq!(uploaded_chunk_hashes.len(), num_chunks_expected);
    }

    uploaded_chunk_hashes
}

#[tokio::test]
async fn test_store_different_from_target() {
    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Install the NNS canisters.
    {
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_tip_nns_canister_versions();
        nns_installer.with_cycles_ledger();
        nns_installer.install(&pocket_ic).await;
    }

    // Publish SNS Wasms to SNS-W.
    {
        let with_mainnet_sns_canisters = false;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
            .await
            .unwrap();
    };

    // Install a dapp canister.
    let original_wasm = {
        // Modify the Wasm upfront, as we then upgrade to the (unmodified) Wasm on the file system.
        let wasm_bytes = very_large_wasm_bytes();
        let wasm_bytes = modify_wasm_bytes(&wasm_bytes, 42);
        Wasm::from_bytes(&wasm_bytes[..])
    };
    let original_wasm_hash = original_wasm.sha256_hash();

    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let ii_subnet = pocket_ic.topology().await.get_ii().unwrap();
    assert_ne!(app_subnet, ii_subnet);

    let root_subnet = get_subnet_for_canister(&pocket_ic, ROOT_CANISTER_ID.into())
        .await
        .unwrap();

    println!("root_subnet = {}", root_subnet);
    panic!("boo");

    let target_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(original_wasm.clone()),
        vec![ROOT_CANISTER_ID.into()],
    )
    .await;

    let sns = {
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
            .with_dapp_canisters(vec![target_canister_id])
            .build();

        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .clone()
            .unwrap();

        let sns_instance_label = "1";
        let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
            &pocket_ic,
            create_service_nervous_system,
            sns_instance_label,
        )
        .await;

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
            .await
            .unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        )
        .await;

        sns
    };

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
    // neuron either holds the majority of the voting power or the follow graph is set up
    // s.t. when this neuron submits a proposal, that proposal gets through without the need
    // for any voting.
    let (sns_neuron_id, _) =
        find_neuron_with_majority_voting_power(&pocket_ic, sns.governance.canister_id)
            .await
            .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    let cli_arg = UpgradeSnsControlledCanisterArgs {
        sns_neuron_id: Some(ParsedSnsNeuron(sns_neuron_id)),
        target_canister_id,
        wasm_path: very_large_wasm_path().clone(),
        candid_arg: None,
        proposal_url: Url::try_from(
            "https://github.com/dfinity/examples/tree/master/rust/image-classification",
        )
        .unwrap(),
        summary: "Upgrade Image Classification canister.".to_string(),
    };

    // 2. Submit the upgrade proposal.
    let pocket_ic_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: sns.root.canister_id.into(),
    };
    let UpgradeSnsControlledCanisterInfo {
        wasm_module_hash,
        proposal_id,
    } = upgrade_sns_controlled_canister::exec(cli_arg, &pocket_ic_agent)
        .await
        .unwrap();

    let proposal_id = proposal_id.unwrap();

    // 3. Await proposal execution.
    wait_for_proposal_execution(&pocket_ic, sns.governance.canister_id, proposal_id)
        .await
        .unwrap();

    // 4. Inspect the resulting state.
    await_with_timeout(
        &pocket_ic,
        MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS..MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS,
        |pocket_ic| async {
            let status = pocket_ic
                .canister_status(target_canister_id.into(), Some(sns.root.canister_id.into()))
                .await;
            status
                .expect("canister status must be available")
                .module_hash
        },
        &Some(wasm_module_hash),
    )
    .await
    .unwrap();
}
