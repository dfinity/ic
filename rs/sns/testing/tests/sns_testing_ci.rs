use candid::{Decode, Encode, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    install_canister_on_subnet, load_registry_mutations, NnsInstaller, STARTING_CYCLES_PER_CANISTER,
};
use ic_nns_constants::{LEDGER_INDEX_CANISTER_ID, ROOT_CANISTER_ID};
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns_pocket_ic, install_test_canister, upgrade_sns_controlled_test_canister_pocket_ic,
    TestCanisterInitArgs,
};
use ic_sns_testing::utils::{
    validate_network, validate_target_canister, SnsTestingCanisterValidationError,
    SnsTestingNetworkValidationError,
};
use icp_ledger::Tokens;
use pocket_ic::management_canister::CanisterSettings;
use pocket_ic::PocketIcBuilder;
use tempfile::TempDir;

#[tokio::test]
async fn test_sns_testing_basic_scenario() {
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
    let registry_proto_path = state_dir.join("registry.proto");
    let initial_mutations = load_registry_mutations(registry_proto_path);
    let dev_participant_id = PrincipalId::new_user_test_id(1000);
    let treasury_principal_id = PrincipalId::new_user_test_id(322);

    bootstrap_nns(
        &pocket_ic,
        vec![initial_mutations],
        vec![(
            treasury_principal_id.into(),
            Tokens::from_tokens(10_000_000).unwrap(),
        )],
        vec![dev_participant_id],
    )
    .await;
    assert!(validate_network(&pocket_ic).await.is_empty());
    let greeting = "Hello there".to_string();
    let test_canister_id = install_test_canister(
        &pocket_ic,
        TestCanisterInitArgs {
            greeting: Some(greeting.clone()),
        },
    )
    .await;
    assert!(validate_target_canister(&pocket_ic, test_canister_id)
        .await
        .is_empty());
    let test_call_arg = "General Kenobi".to_string();
    let test_canister_response = pocket_ic
        .query_call(
            test_canister_id.into(),
            Principal::anonymous(),
            "greet",
            Encode!(&test_call_arg).unwrap(),
        )
        .await
        .expect("Call to a test canister failed");
    assert_eq!(
        Decode!(&test_canister_response, String).expect("Failed to decode test canister response"),
        format!("{}, {}!", greeting, test_call_arg.clone()),
    );
    let sns = create_sns_pocket_ic(
        &pocket_ic,
        dev_participant_id,
        treasury_principal_id,
        vec![test_canister_id],
    )
    .await;
    let new_greeting = "Hi".to_string();
    upgrade_sns_controlled_test_canister_pocket_ic(
        &pocket_ic,
        dev_participant_id,
        sns,
        test_canister_id,
        TestCanisterInitArgs {
            greeting: Some(new_greeting.clone()),
        },
    )
    .await;
    let test_canister_response = pocket_ic
        .query_call(
            test_canister_id.into(),
            Principal::anonymous(),
            "greet",
            Encode!(&test_call_arg).unwrap(),
        )
        .await
        .expect("Call to a test canister failed");
    assert_eq!(
        Decode!(&test_canister_response, String).expect("Failed to decode test canister response"),
        format!("{}, {}!", new_greeting, test_call_arg),
    );
}

#[tokio::test]
pub async fn test_missing_nns_canisters() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    bootstrap_nns(&pocket_ic, vec![], vec![], vec![]).await;
    pocket_ic
        .stop_canister(
            LEDGER_INDEX_CANISTER_ID.get().into(),
            Some(ROOT_CANISTER_ID.get().into()),
        )
        .await
        .unwrap();
    pocket_ic
        .delete_canister(
            LEDGER_INDEX_CANISTER_ID.get().into(),
            Some(ROOT_CANISTER_ID.get().into()),
        )
        .await
        .unwrap();
    assert_eq!(
        validate_network(&pocket_ic).await,
        vec![SnsTestingNetworkValidationError::MissingNnsCanister(
            "ledger-index".to_string(),
        )]
    )
}

#[tokio::test]
pub async fn test_missing_sns_wasm_upgrade_steps() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.with_test_governance_canister();
    nns_installer.with_cycles_minting_canister();
    nns_installer.with_cycles_ledger();
    nns_installer.with_index_canister();
    nns_installer.with_custom_registry_mutations(vec![]);
    nns_installer.with_ledger_balances(vec![]);
    nns_installer.with_neurons_fund_hotkeys(vec![]);
    nns_installer.install(&pocket_ic).await;
    assert_eq!(
        validate_network(&pocket_ic).await,
        vec![SnsTestingNetworkValidationError::MissingSnsWasmUpgradeSteps,]
    )
}

#[tokio::test]
pub async fn test_non_installed_target_canister() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let canister_id = pocket_ic
        .create_canister_on_subnet(
            None,
            Some(CanisterSettings {
                controllers: Some(vec![ROOT_CANISTER_ID.get().into()]),
                ..Default::default()
            }),
            application_subnet_id,
        )
        .await;
    pocket_ic
        .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    let canister_id = CanisterId::unchecked_from_principal(canister_id.into());
    assert_eq!(
        validate_target_canister(&pocket_ic, canister_id).await,
        vec![SnsTestingCanisterValidationError::CanisterNotInstalled(
            canister_id
        )],
    )
}

#[tokio::test]
pub async fn test_nonexisting_target_canister() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(1000));
    assert!(match validate_target_canister(&pocket_ic, canister_id)
        .await
        .as_slice()
    {
        [SnsTestingCanisterValidationError::FailedToGetCanisterInfo(err_canister_id, _)] => {
            err_canister_id == &canister_id
        }
        _ => false,
    })
}

#[tokio::test]
pub async fn test_target_canister_not_controlled_by_nns_root() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let test_canister_wasm = Wasm::from_bytes([0, 0x61, 0x73, 0x6D, 1, 0, 0, 0]);
    let canister_controller = PrincipalId::new_user_test_id(1000);
    let canister_id = install_canister_on_subnet(
        &pocket_ic,
        application_subnet_id,
        vec![],
        Some(test_canister_wasm),
        vec![canister_controller],
    )
    .await;
    assert_eq!(
        validate_target_canister(&pocket_ic, canister_id).await,
        vec![SnsTestingCanisterValidationError::CanisterNotControlledByNnsRoot(canister_id)]
    )
}
