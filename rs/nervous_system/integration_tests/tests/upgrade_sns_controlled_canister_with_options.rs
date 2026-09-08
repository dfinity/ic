use canister_test::Wasm;
use ic_management_canister_types_private::WasmMemoryPersistence;
use ic_nervous_system_agent::{helpers::await_with_timeout, pocketic_impl::PocketIcAgent};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        NnsInstaller, add_wasms_to_sns_wasm, cycles_ledger, install_canister_on_subnet,
        load_registry_mutations, nns, sns,
        sns::governance::{find_neuron_with_majority_voting_power, wait_for_proposal_execution},
    },
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_protobuf::types::v1::{
    CanisterInstallMode as CanisterInstallModeProto,
    WasmMemoryPersistence as WasmMemoryPersistenceProto,
};
use ic_sns_cli::{
    neuron_id_to_candid_subaccount::ParsedSnsNeuron,
    upgrade_sns_controlled_canister::{
        self, UpgradeSnsControlledCanisterArgs, UpgradeSnsControlledCanisterInfo,
    },
};
use ic_sns_governance_api::pb::v1::{UpgradeSnsControlledCanister, proposal};
use ic_sns_swap::pb::v1::Lifecycle;
use icp_ledger::Tokens;
use lazy_static::lazy_static;
use pocket_ic::PocketIcBuilder;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};
use url::Url;

const MIN_UPGRADE_TIME_SECONDS: u64 = 5;
const MAX_UPGRADE_TIME_SECONDS: u64 = 5 * 60;

lazy_static! {
    /// Features:
    ///
    /// 1. Writes a sentinel value to main memory when installed. This is used
    ///    to verify the wasm_memory_persistence upgrade option.
    ///
    /// 2. Traps during pre_upgrade. This is to verify the skip_pre_upgrade
    ///    upgrade option.
    ///
    /// 3. Declares Enhanced Orthogonal Persistence (EOP) via
    ///    `icp:private enhanced-orthogonal-persistence` custom section.
    ///    This is also to test wasm_memory_persistence.
    static ref OLD_CANISTER_CODE: Vec<u8> = wat::parse_str(
        r#"
        (module
            (memory 1)

            ;; 1. Write sentinel.
            (func $initialize
                (i32.store (i32.const 0) (i32.const 0xCAFE_BABE))
            )
            (start $initialize)

            ;; 2. Trap during pre_upgrade.
            (func $pre_upgrade
                unreachable
            )
            (export "canister_pre_upgrade" (func $pre_upgrade))

            ;; 3. Declare EOP.
            (@custom "icp:private enhanced-orthogonal-persistence" "")
        )
        "#,
    )
    .unwrap();

    /// Traps during upgrade if the value written by OLD_CANISTER_CODE is not found.
    static ref NEW_CANISTER_CODE: Vec<u8> = wat::parse_str(
        r#"
        (module
            (memory 1)

            (func $check
                (if (i32.ne (i32.load (i32.const 0)) (i32.const 0xCAFE_BABE))
                    (then unreachable)
                )
            )
            (export "canister_post_upgrade" (func $check))

            (@custom "icp:private enhanced-orthogonal-persistence" "")
        )
        "#,
    )
    .unwrap();
}

/// This exercises the skip_pre_upgrade and wasm_memory_persistence upgrade
/// options, end-to-end, via the SNS CLI's upgrade_sns_controlled_canister
/// command.
#[tokio::test]
async fn upgrade_sns_controlled_canister_with_options() {
    // Step 1: Prepare the world.

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

    // Install NNS.
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

    // Publish SNS WASMs (to SNS-W).
    let with_mainnet_sns_canisters = false;
    add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    // Create dapp canister and install OLD_CANISTER_CODE into it.
    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let original_wasm = Wasm::from_bytes(OLD_CANISTER_CODE.clone());
    let original_wasm_hash = original_wasm.sha256_hash().to_vec();
    let target_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(original_wasm),
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

    // Give the user some cycles so that he can store chunks of the new code in
    // a store canister. The dapp upgrade proposal will point to this canister
    // as the place where the code can be sourced.
    let icp = Tokens::from_tokens(10).unwrap();
    cycles_ledger::mint_icp_and_convert_to_cycles(&pocket_ic, sender, icp).await;

    // The sns cli will upload the new code to the store canister from here.
    let mut new_wasm_file = NamedTempFile::new().unwrap();
    new_wasm_file.write_all(&NEW_CANISTER_CODE).unwrap();

    // Step 2: Run the code under test.

    // Step 2.1: Prepare command to submit proposal to upgrade the dapp canister.
    let cli_arg = UpgradeSnsControlledCanisterArgs {
        // The new upgrade flags that we are trying to test.
        skip_pre_upgrade: true,
        wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),

        // Basic upgrade parameters.
        target_canister_id,
        wasm_path: new_wasm_file.path().to_path_buf(),
        candid_arg: None,

        // Description.
        summary: "Upgrade the Dapp".to_string(),
        proposal_url: Url::try_from("https://forum.dfinity.org").unwrap(),

        // Who is proposing.
        sns_neuron_id: Some(ParsedSnsNeuron(sns_neuron_id)),
    };

    // Step 2.2: Submit proposal to upgrade the dapp canister.
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
    let proposal_id = proposal_id.unwrap();
    assert_ne!(wasm_module_hash, original_wasm_hash);

    // Step 2.3: Wait for the proposal to execute (successfully).
    let action = wait_for_proposal_execution(&pocket_ic, sns.governance.canister_id, proposal_id)
        .await
        .unwrap()
        .proposal
        .unwrap()
        .action
        .unwrap();

    // Step 3: Verify result(s).

    // Step 3.1: Inspect proposal. This is less interesting than what happens to
    // the dapp canister. The main reason this might fail is if somehow the sns
    // cli flags did not survive the whole way through, if they somehow got
    // dropped along the way.
    let proposal::Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        mode,
        canister_upgrade_options,
        ..
    }) = action
    else {
        panic!("unexpected proposal action {action:?}");
    };
    assert_eq!(mode, Some(CanisterInstallModeProto::Upgrade as i32));
    let canister_upgrade_options = canister_upgrade_options.unwrap();
    assert_eq!(canister_upgrade_options.skip_pre_upgrade, Some(true));
    assert_eq!(
        canister_upgrade_options.wasm_memory_persistence,
        Some(WasmMemoryPersistenceProto::Keep as i32),
    );

    // Step 3.2: Verify that the dapp canister has the new code. This allows us
    // to deduce that the upgrade options under test did what they are supposed
    // to:
    //
    // 1. skip_pre_upgrade: If pre-upgrade were not skipped, pre-upgrade
    //    function in OLD_CANISTER_CODE would have trapped.
    //
    // 2. wasm_memory_persistence: If main memory were not retained, the check
    //    in NEW_CANISTER_CODE would have trapped due to not seeing the value
    //    written to main memory by OLD_CANISTER_CODE.
    await_with_timeout(
        &pocket_ic,
        MIN_UPGRADE_TIME_SECONDS..MAX_UPGRADE_TIME_SECONDS,
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
