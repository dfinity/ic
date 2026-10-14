use super::*;
use crate::pb::v1::nervous_system_function::{FunctionType, GenericNervousSystemFunction};
use crate::types::test_helpers::NativeEnvironment;
use lazy_static::lazy_static;

const FUNCTION_ID: u64 = 1000;
const TARGET_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
const TARGET_METHOD: &str = "do_something";
const VALIDATOR_METHOD: &str = "validate_do_something";

lazy_static! {
    static ref VALID_GENERIC_NERVOUS_SYSTEM_FUNCTION: NervousSystemFunction =
        NervousSystemFunction {
            id: FUNCTION_ID,
            name: "Test Function".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    topic: None,
                    target_canister_id: Some(TARGET_CANISTER_ID.get()),
                    target_method_name: Some(TARGET_METHOD.to_string()),
                    validator_canister_id: Some(TARGET_CANISTER_ID.get()),
                    validator_method_name: Some(VALIDATOR_METHOD.to_string()),
                },
            )),
        };
}

#[tokio::test]
async fn test_perform_execute_generic_nervous_system_function_call_returns_reply_bytes() {
    // Step 1: Prepare the world.
    let payload = b"the-payload".to_vec();
    let expected_reply = b"the-reply-bytes".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        payload.clone(),
        Ok(expected_reply.clone()),
    );

    let call = ExecuteGenericNervousSystemFunction {
        function_id: FUNCTION_ID,
        payload,
    };

    // Step 2: Run the code under test.
    let result = perform_execute_generic_nervous_system_function_call(
        &env,
        VALID_GENERIC_NERVOUS_SYSTEM_FUNCTION.clone(),
        call,
    )
    .await;

    // Step 3: Verify result(s).
    assert_eq!(result, Ok(expected_reply));
}

#[tokio::test]
async fn test_perform_execute_generic_nervous_system_function_call_propagates_ic_level_error() {
    // Step 1: Prepare the world.
    let payload = b"the-payload".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        payload.clone(),
        Err((Some(1), "target canister rejected the call".to_string())),
    );

    let call = ExecuteGenericNervousSystemFunction {
        function_id: FUNCTION_ID,
        payload,
    };

    // Step 2: Run the code under test.
    let result = perform_execute_generic_nervous_system_function_call(
        &env,
        VALID_GENERIC_NERVOUS_SYSTEM_FUNCTION.clone(),
        call,
    )
    .await;

    // Step 3: Verify result(s).
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::External as i32);
    assert!(error.error_message.contains("failed"));
}
