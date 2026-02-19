use crate::{IcError, Runtime, StubRuntime};
use candid::{CandidType, Principal};
use ic_error_types::RejectCode;
use serde::Deserialize;

const DEFAULT_PRINCIPAL: Principal = Principal::from_slice(&[0x9d, 0xf7, 0x01]);
const DEFAULT_METHOD: &str = "method";
const DEFAULT_ARGS: (&str,) = ("args",);

#[tokio::test]
#[should_panic(expected = "No available call response")]
async fn should_panic_if_no_more_stubs() {
    let runtime = StubRuntime::new();

    let _result: Result<MultiResult, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;
}

#[tokio::test]
#[should_panic(expected = "Failed to decode Candid stub response")]
async fn should_panic_if_result_cannot_be_decoded() {
    let runtime = StubRuntime::new().add_stub_response("Hello, world!");

    let _result: Result<MultiResult, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;
}

#[tokio::test]
async fn should_return_single_stub_response() {
    let expected = MultiResult::Consistent("Hello, world!".to_string());
    let runtime = StubRuntime::new().add_stub_response(expected.clone());

    let result: Result<MultiResult, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;

    assert_eq!(result, Ok(expected));
}

#[tokio::test]
async fn should_return_single_stub_error() {
    let expected = IcError::CallPerformFailed;
    let runtime = StubRuntime::new().add_stub_error(expected.clone());

    let result: Result<MultiResult, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;

    assert_eq!(result, Err(expected));
}

#[tokio::test]
async fn should_return_multiple_stub_responses() {
    let expected1 = MultiResult::Consistent("Hello, world!".to_string());
    let expected2 = MultiResult::Inconsistent(vec![
        "Hello, world!".to_string(),
        "Goodbye, world!".to_string(),
    ]);
    let expected3 = 0_u128;
    let expected4 = IcError::CallRejected {
        code: RejectCode::SysFatal,
        message: "Fatal error!".to_string(),
    };
    let runtime = StubRuntime::new()
        .add_stub_response(expected1.clone())
        .add_stub_response(expected2.clone())
        .add_stub_response(expected3)
        .add_stub_error(expected4.clone());

    let result1: Result<MultiResult, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;
    assert_eq!(result1, Ok(expected1));
    let result2: Result<MultiResult, IcError> = runtime
        .query_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS)
        .await;
    assert_eq!(result2, Ok(expected2));
    let result3: Result<u128, IcError> = runtime
        .query_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS)
        .await;
    assert_eq!(result3, Ok(expected3));
    let result4: Result<u128, IcError> = runtime
        .update_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS, 0)
        .await;
    assert_eq!(result4, Err(expected4));
}

#[tokio::test]
async fn should_have_same_responses_in_clone() {
    let original_runtime = StubRuntime::new()
        .add_stub_response(1_u64)
        .add_stub_response(2_u64)
        .add_stub_response(3_u64);
    let cloned_runtime = original_runtime.clone();

    let result1: Result<u64, IcError> = original_runtime
        .query_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS)
        .await;
    assert_eq!(result1, Ok(1));
    let result2: Result<u64, IcError> = cloned_runtime
        .query_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS)
        .await;
    assert_eq!(result2, Ok(2));
    let result3: Result<u64, IcError> = original_runtime
        .query_call(DEFAULT_PRINCIPAL, DEFAULT_METHOD, DEFAULT_ARGS)
        .await;
    assert_eq!(result3, Ok(3));
}

#[derive(Clone, Debug, PartialEq, CandidType, Deserialize)]
enum MultiResult {
    Consistent(String),
    Inconsistent(Vec<String>),
}
