use super::*;
use ic_base_types::PrincipalId;
use ic_registry_canister_api::{Chunk, GetChunkRequest};
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_mock_happy() {
    // Step 1: Prepare the world.
    let call_canisters = MockCallCanisters::new();

    // Step 1.1: Expect one get_chunk call.
    let callee = Principal::from(PrincipalId::new_user_test_id(42));
    let request_1 = GetChunkRequest {
        content_sha256: Some(vec![1, 2, 3]),
    };
    let response_1 = Chunk {
        content: Some(vec![101, 102, 103]),
    };
    call_canisters.expect_call(callee, request_1.clone(), Ok(Ok(response_1.clone())));

    // Step 1.2: Expect a DIFFERENT one. By having both, we make sure that
    // MockCallCanisters is not doing things in the wrong order.
    let callee = Principal::from(PrincipalId::new_user_test_id(42));
    let request_2 = GetChunkRequest {
        content_sha256: Some(vec![4, 5, 6]),
    };
    call_canisters.expect_call(callee, request_2.clone(), Ok(Err("DOH!".to_string())));

    // Step 2: Call the code under test.
    let result_1 = call_canisters.call(callee, request_1).await;
    let result_2 = call_canisters.call(callee, request_2).await;

    // Step 3: Verify result(s).
    assert_eq!(result_1, Ok(Ok(response_1)));
    assert_eq!(result_2, Ok(Err("DOH!".to_string())));

    // Step 3.1: When call_canisters is droped, it does not panic.
}

#[should_panic(expected = "left == right")]
#[tokio::test]
async fn test_mock_wrong_call() {
    // Step 1: Prepare the world: Expect a `get_chunk` call.

    let callee = Principal::from(PrincipalId::new_user_test_id(42));
    let request = GetChunkRequest {
        content_sha256: Some(vec![1, 2, 3]),
    };
    let response = Chunk {
        content: Some(vec![101, 102, 103]),
    };

    let call_canisters = MockCallCanisters::new();
    call_canisters.expect_call(callee, request.clone(), Ok(Ok(response.clone())));

    // Step 2: Call the code under test. This does not match `expect_call`.
    // Therefore, the correct behavior here is to panic.
    let _ = call_canisters
        .call(
            callee,
            GetChunkRequest {
                content_sha256: Some(vec![0xFF]),
            },
        )
        .await;

    // Step 3: Verify results. Actually, the should_panic at the top is what does the verification.
}

#[should_panic(expected = "expected calls were left over")]
#[tokio::test]
async fn test_mock_left_over_expected_call() {
    // Step 1: Prepare the world: Expect a couple of `get_chunk` calls.

    let callee = Principal::from(PrincipalId::new_user_test_id(42));
    let request = GetChunkRequest {
        content_sha256: Some(vec![1, 2, 3]),
    };
    let response = Chunk {
        content: Some(vec![101, 102, 103]),
    };

    let call_canisters = MockCallCanisters::new();
    call_canisters.expect_call(callee, request.clone(), Ok(Ok(response.clone())));

    // Step 2: Do not call call_canisters. This is supposed to trigger a panic.

    // Step 3: Verify result(s). Actually, the should_panic at the top is what does the verification.
}
