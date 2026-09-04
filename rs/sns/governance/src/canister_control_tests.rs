use super::*;
use crate::pb::v1::nervous_system_function::{FunctionType, GenericNervousSystemFunction};
use crate::types::test_helpers::NativeEnvironment;

fn new_valid_generic_nervous_system_function(
    id: u64,
    target_canister_id: CanisterId,
    target_method: &str,
) -> NervousSystemFunction {
    NervousSystemFunction {
        id,
        name: "Test Function".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None,
                target_canister_id: Some(target_canister_id.get()),
                target_method_name: Some(target_method.to_string()),
                validator_canister_id: Some(target_canister_id.get()),
                validator_method_name: Some(target_method.to_string()),
            },
        )),
    }
}

#[tokio::test]
async fn test_perform_execute_generic_nervous_system_function_call_returns_reply_bytes() {
    // Step 1: Prepare the world.
    let target_canister_id = CanisterId::from_u64(1);
    let target_method = "do_something";
    let function =
        new_valid_generic_nervous_system_function(1000, target_canister_id, target_method);
    let payload = b"the-payload".to_vec();
    let expected_reply = b"the-reply-bytes".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        target_canister_id,
        target_method,
        payload.clone(),
        Ok(expected_reply.clone()),
    );

    let call = ExecuteGenericNervousSystemFunction {
        function_id: 1000,
        payload,
    };

    // Step 2: Run the code under test.
    let result = perform_execute_generic_nervous_system_function_call(&env, function, call).await;

    // Step 3: Verify result(s).
    assert_eq!(result, Ok(expected_reply));
}

#[tokio::test]
async fn test_perform_execute_generic_nervous_system_function_call_propagates_ic_level_error() {
    // Step 1: Prepare the world.
    let target_canister_id = CanisterId::from_u64(1);
    let target_method = "do_something";
    let function =
        new_valid_generic_nervous_system_function(1000, target_canister_id, target_method);
    let payload = b"the-payload".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        target_canister_id,
        target_method,
        payload.clone(),
        Err((Some(1), "target canister rejected the call".to_string())),
    );

    let call = ExecuteGenericNervousSystemFunction {
        function_id: 1000,
        payload,
    };

    // Step 2: Run the code under test.
    let result = perform_execute_generic_nervous_system_function_call(&env, function, call).await;

    // Step 3: Verify result(s).
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::External as i32);
    // Do not assert exact wording; just look for a key phrase.
    assert!(error.error_message.contains("failed"));
}
