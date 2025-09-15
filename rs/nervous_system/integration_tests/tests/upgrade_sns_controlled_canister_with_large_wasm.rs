use assert_matches::assert_matches;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_agent::helpers::await_with_timeout;
use ic_nervous_system_agent::management_canister::canister_status;
use ic_nervous_system_agent::pocketic_impl::{PocketIcAgent, PocketIcCallError::PocketIc};
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns::governance::{
    find_neuron_with_majority_voting_power, wait_for_proposal_execution,
};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    NnsInstaller, cycles_ledger, install_canister_on_subnet, load_registry_mutations, nns, sns,
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::add_wasms_to_sns_wasm,
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_sns_cli::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use ic_sns_cli::upgrade_sns_controlled_canister::{
    self, RefundAfterSnsControlledCanisterUpgradeArgs, UpgradeSnsControlledCanisterArgs,
    UpgradeSnsControlledCanisterInfo,
};
use ic_sns_governance_api::pb::v1::{ChunkedCanisterWasm, UpgradeSnsControlledCanister, proposal};
use ic_sns_swap::pb::v1::Lifecycle;
use icp_ledger::Tokens;
use pocket_ic::ErrorCode::CanisterNotFound;
use pocket_ic::PocketIcBuilder;
use std::path::PathBuf;
use tempfile::TempDir;
use url::Url;

const MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 20;
const MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 5 * 60;

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

#[tokio::test]
async fn upgrade_sns_controlled_canister_with_large_wasm() {
    // 1. Prepare the world
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Install the NNS canisters.
    {
        let registry_proto_path = state_dir.join("registry.proto");
        let initial_mutations = load_registry_mutations(registry_proto_path);

        let mut nns_installer = NnsInstaller::default();
        nns_installer
            .with_current_nns_canister_versions()
            .with_cycles_minting_canister()
            .with_cycles_ledger()
            .with_custom_registry_mutations(vec![initial_mutations]);
        nns_installer.install(&pocket_ic).await;
    }

    // Publish SNS Wasms to SNS-W.
    let with_mainnet_sns_canisters = false;
    add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    // Install a dapp canister.
    let original_wasm = {
        // Modify the Wasm upfront, as we then upgrade to the (unmodified) Wasm on the file system.
        let wasm_bytes = very_large_wasm_bytes();
        let wasm_bytes = modify_wasm_bytes(&wasm_bytes, 42);
        Wasm::from_bytes(&wasm_bytes[..])
    };
    let original_wasm_hash = original_wasm.sha256_hash().to_vec();

    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
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
    let (sns_neuron_id, sender) =
        find_neuron_with_majority_voting_power(&pocket_ic, sns.governance.canister_id)
            .await
            .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    // Ensure the user controlling the SNS neuron can also create a canister with enough cycles
    // so that it can host the large Wasm. To that end, the GM grants this user 10 ICP, for
    // the sake of testing, out of thin air.
    let icp = Tokens::from_tokens(10).unwrap();
    cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

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
        sender: sender.into(),
    };
    let UpgradeSnsControlledCanisterInfo {
        wasm_module_hash,
        proposal_id,
    } = upgrade_sns_controlled_canister::exec(cli_arg, &pocket_ic_agent)
        .await
        .unwrap();

    // Smoke test.
    assert_ne!(wasm_module_hash, original_wasm_hash);

    let proposal_id = proposal_id.unwrap();

    // 3. Await proposal execution.
    let action = wait_for_proposal_execution(&pocket_ic, sns.governance.canister_id, proposal_id)
        .await
        .unwrap()
        .proposal
        .unwrap()
        .action
        .unwrap();

    // 4. Inspect proposal data (and obtain store_canister_id for future inspection).
    let proposal::Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        canister_id,
        new_canister_wasm,
        canister_upgrade_arg,
        mode,
        chunked_canister_wasm,
    }) = action
    else {
        panic!("unexpected proposal action {action:?}");
    };
    assert_eq!(canister_id, Some(target_canister_id.into()));
    assert_eq!(new_canister_wasm, Vec::<u8>::new()); // Deprecated field, no longer in use.
    assert_eq!(canister_upgrade_arg, None);
    assert_eq!(mode, Some(CanisterInstallMode::Upgrade as i32));
    let store_canister_id = assert_matches!(chunked_canister_wasm, Some(ChunkedCanisterWasm {
        wasm_module_hash: observed_wasm_module_hash,
        store_canister_id: Some(store_canister_id),
        ..
    }) => {
        assert_eq!(observed_wasm_module_hash, wasm_module_hash);
        store_canister_id
    });

    // 5. Inspect the resulting state.
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

    // 6. Clean-up.
    let refund_arg = RefundAfterSnsControlledCanisterUpgradeArgs {
        target_canister_id,
        proposal_id: proposal_id.id,
    };
    upgrade_sns_controlled_canister::refund(refund_arg, &pocket_ic_agent)
        .await
        .unwrap();

    // 7. Assert that store canister has been deleted.
    let err = canister_status(
        &pocket_ic_agent,
        CanisterId::unchecked_from_principal(store_canister_id),
    )
    .await
    .unwrap_err();
    assert_matches!(err, PocketIc(pocket_ic::RejectResponse {
        error_code,
        ..
    }) => {
        assert_eq!(error_code, CanisterNotFound);
    });
}
