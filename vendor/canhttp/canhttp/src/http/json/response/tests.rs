use super::{try_order_responses_by_id, Id, JsonRpcError, JsonRpcResponse};
use crate::http::json::response::JsonRpcResult;
use proptest::{
    arbitrary::any,
    collection::{btree_set, vec},
    prelude::{Just, Strategy},
    prop_assert, prop_assert_eq, prop_oneof, proptest,
};
use serde_json::json;
use std::{iter, ops::Range};

mod json_rpc_batch_response_id_validation_tests {
    use super::*;

    #[test]
    fn should_succeed_for_empty_response() {
        let result = try_order_responses_by_id::<serde_json::Value>(&[], Vec::new());

        assert!(result.is_some());
        assert_eq!(result.unwrap(), Vec::new());
    }

    proptest! {
        #[test]
        fn should_succeed_with_responses_in_any_order(
            (shuffled_responses, request_ids) in arbitrary_responses_with_unique_nonnull_ids(2..10)
                .prop_flat_map(|responses| {
                    let request_ids = response_ids(&responses);
                    (Just(responses).prop_shuffle(), Just(request_ids))
                })
        ) {
            let result = try_order_responses_by_id(&request_ids, shuffled_responses);

            prop_assert!(result.is_some());
            prop_assert_eq!(request_ids, response_ids(&result.unwrap()));
        }
    }

    proptest! {
        #[test]
        fn should_succeed_with_invalid_request_errors_in_any_order(
            (shuffled_responses, request_ids) in arbitrary_responses_with_null_ids(2..10)
                .prop_flat_map(|responses| {
                    let request_ids = response_ids(&responses);
                    (Just(responses).prop_shuffle(), Just(request_ids))
                })
        ) {
            let result = try_order_responses_by_id(&request_ids, shuffled_responses);

            prop_assert!(result.is_some());
            prop_assert_eq!(request_ids, response_ids(&result.unwrap()));
        }
    }

    proptest! {
        #[test]
        fn should_return_error_for_unexpected_id_in_response(
            (mut responses, unexpected_id, i) in arbitrary_responses_with_unique_nonnull_ids(2..10)
                .prop_flat_map(|mut responses| {
                    let unexpected_id = responses.pop().unwrap().id().clone();
                    let batch_size = responses.len();
                    (Just(responses), Just(unexpected_id), 0..batch_size)
                })
        ) {
            let request_ids = response_ids(&responses);

            // Ensure one of the response IDs is not in the request IDs,
            set_id(&mut responses[i], unexpected_id);

            let result = try_order_responses_by_id(&request_ids, responses);

            prop_assert!(result.is_none());
        }
    }

    proptest! {
        #[test]
        fn should_return_error_for_duplicate_id_in_response(
            mut responses in arbitrary_responses_with_unique_nonnull_ids(2..10)
        ) {
            let n = responses.len();
            let request_ids = response_ids(&responses);

            // Duplicate the second last response ID
            let id = responses[n - 2].id().clone();
            set_id(&mut responses[n - 1], id);

            let result = try_order_responses_by_id(&request_ids, responses);

            prop_assert!(result.is_none());
        }
    }

    proptest! {
        #[test]
        fn should_return_error_for_too_few_responses(
            mut responses in arbitrary_responses_with_unique_nonnull_ids(2..10)
        ) {
            let request_ids = response_ids(&responses);

            // Ensure there is one more request ID than responses
            responses.remove(responses.len() - 1);

            let result = try_order_responses_by_id(&request_ids, responses);

            prop_assert!(result.is_none());
        }
    }

    proptest! {
        #[test]
        fn should_return_error_for_too_many_responses(
            responses in arbitrary_responses_with_unique_nonnull_ids(2..10)
        ) {
            let mut request_ids = response_ids(&responses);

            // Ensure there is one more response than expected request IDs
            request_ids.remove(request_ids.len() - 1);

            let result = try_order_responses_by_id(&request_ids, responses);

            prop_assert!(result.is_none());
        }
    }

    proptest! {
        #[test]
        fn should_return_error_for_response_with_null_id_that_is_not_invalid_request_error(
            mut responses in arbitrary_responses_with_unique_nonnull_ids(2..10)
        ) {
            let n = responses.len();
            let request_ids = response_ids(&responses);

            // Ensure there is one more request ID than responses
            set_id(&mut responses[n - 1], Id::Null);

            let result = try_order_responses_by_id(&request_ids, responses);

            prop_assert!(result.is_none());
        }
    }

    fn response_ids<T>(responses: &[JsonRpcResponse<T>]) -> Vec<Id> {
        responses
            .iter()
            .map(|response| response.id())
            .cloned()
            .collect()
    }

    fn arbitrary_responses_with_null_ids(
        size: Range<usize>,
    ) -> impl Strategy<Value = Vec<JsonRpcResponse<serde_json::Value>>> {
        (
            vec(Just(Id::Null), size.clone()),
            vec(Just(Err(JsonRpcError::invalid_request())), size.clone()),
            btree_set(arbitrary_nonnull_id(), size.clone()).prop_map(Vec::from_iter),
            vec(arbitrary_json_rpc_result(), size),
        )
            .prop_map(|(null_ids, invalid_request_errors, unique_ids, results)| {
                iter::zip(null_ids, invalid_request_errors)
                    .chain(iter::zip(unique_ids, results))
                    .map(|(id, result)| JsonRpcResponse::from_parts(id, result))
                    .collect()
            })
            .prop_shuffle()
    }

    fn arbitrary_responses_with_unique_nonnull_ids(
        size: Range<usize>,
    ) -> impl Strategy<Value = Vec<JsonRpcResponse<serde_json::Value>>> {
        (
            // Ensure the response IDs are unique
            btree_set(arbitrary_nonnull_id(), size.clone()).prop_map(Vec::from_iter),
            vec(arbitrary_json_rpc_result(), size),
        )
            .prop_map(|(ids, results)| {
                iter::zip(ids, results)
                    .map(|(id, result)| JsonRpcResponse::from_parts(id, result))
                    .collect()
            })
    }

    fn arbitrary_json_rpc_result() -> impl Strategy<Value = JsonRpcResult<serde_json::Value>> {
        prop_oneof![
            (".*", any::<u64>())
                .prop_map(|(key, value)| json!({key: value}))
                .prop_map(Ok),
            (any::<i32>(), ".*")
                .prop_map(|(code, message)| JsonRpcError::new(code, message))
                .prop_map(Err),
        ]
    }

    fn arbitrary_nonnull_id() -> impl Strategy<Value = Id> {
        prop_oneof![any::<u64>().prop_map(Id::Number), ".*".prop_map(Id::String),]
    }

    fn set_id<T: Clone>(response: &mut JsonRpcResponse<T>, id: Id) {
        *response = JsonRpcResponse::from_parts(id, response.clone().into_result());
    }
}
