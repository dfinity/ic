use candid::{Decode, Encode, Principal};
use ic_management_canister_types::CanisterIdRecord;
use ic_management_canister_types::CanisterSettings;
use pocket_ic::common::rest::{
    CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse, RawEffectivePrincipal,
};
use pocket_ic::PocketIc;
use test_fixtures::Setup;

#[tokio::test]
async fn should_make_http_post_request() {
    let setup = Setup::new("http_canister").await;

    let http_request_result = setup
        .canister()
        .update_call::<_, String>("make_http_post_request", ())
        .await;

    assert!(http_request_result.contains("Hello, World!"));
    assert!(http_request_result.contains("\"X-Id\": \"42\""));
}

#[test]
fn should_not_make_http_request_when_stopping() {
    let env = PocketIc::new();
    let canister_id = env.create_canister_with_settings(
        None,
        Some(CanisterSettings {
            controllers: Some(vec![Setup::DEFAULT_CONTROLLER]),
            ..CanisterSettings::default()
        }),
    );
    env.add_cycles(canister_id, u64::MAX as u128);
    env.install_canister(
        canister_id,
        test_fixtures::canister_wasm("http_canister"),
        Encode!().unwrap(),
        Some(Setup::DEFAULT_CONTROLLER),
    );

    let http_request = env
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "infinite_loop_make_http_post_request",
            Encode!().unwrap(),
        )
        .unwrap();

    while env.get_canister_http().is_empty() {
        env.tick();
    }
    for request in env.get_canister_http() {
        env.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: request.subnet_id,
            request_id: request.request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: vec![],
            }),
            additional_responses: vec![],
        })
    }

    let _stopping = env
        .submit_call_with_effective_principal(
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            Setup::DEFAULT_CONTROLLER,
            "stop_canister",
            Encode!(&CanisterIdRecord { canister_id }).unwrap(),
        )
        .unwrap();

    let result = Decode!(&env.await_call(http_request).unwrap(), String).unwrap();

    assert!(result.contains("Canister is not running and has status 2")); //Stopping
    assert_eq!(env.get_canister_http(), vec![]);
}
