use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::load_registry_mutations;
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns_pocket_ic, install_test_canister, upgrade_sns_controlled_test_canister_pocket_ic,
    TestCanisterInitArgs,
};
use icp_ledger::Tokens;
use pocket_ic::PocketIcBuilder;
use tempfile::TempDir;

#[tokio::test]
async fn test_sns_testing_pocket_ic() {
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
    let greeting = "Hello there".to_string();
    let test_canister_id = install_test_canister(
        &pocket_ic,
        TestCanisterInitArgs {
            greeting: Some(greeting.clone()),
        },
    )
    .await;
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
