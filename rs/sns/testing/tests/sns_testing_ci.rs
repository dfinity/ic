use candid::{Decode, Encode, Principal};
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns, install_test_canister, upgrade_sns_controlled_test_canister, TestCanisterInitArgs,
};
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_sns_testing_pocket_ic() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    bootstrap_nns(&pocket_ic).await;
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
    let (sns, _nns_proposal_id) = create_sns(&pocket_ic, vec![test_canister_id]).await;
    let new_greeting = "Hi".to_string();
    upgrade_sns_controlled_test_canister(
        &pocket_ic,
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
