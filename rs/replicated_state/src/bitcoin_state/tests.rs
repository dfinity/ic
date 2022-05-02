use crate::{BitcoinState, BitcoinStateError};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest, SendTransactionResponse,
};

#[test]
fn can_push_requests_until_capacity_reached() {
    let capacity = 3;
    let mut bitcoin_state = BitcoinState::new(capacity);

    // Enqueue 3 requests, it should succeed.
    for i in 0..3 {
        let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
            processed_block_hashes: vec![vec![i; 32]],
            anchor: vec![i; 32],
        });
        bitcoin_state.adapter_queues.push_request(request).unwrap();
    }
    assert_eq!(bitcoin_state.adapter_queues.num_requests(), 3);

    // Attempting to enqueue a fourth request should fail.
    let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
        processed_block_hashes: vec![vec![42; 32]],
        anchor: vec![42; 32],
    });
    let res = bitcoin_state.adapter_queues.push_request(request);
    assert_eq!(res, Err(BitcoinStateError::QueueFull { capacity }));
    assert_eq!(bitcoin_state.adapter_queues.num_requests(), 3);
}

#[test]
fn enqueueing_a_response_for_a_non_existing_callback_id_fails() {
    let mut bitcoin_state = BitcoinState::default();

    let callback_id = 10;
    let res = bitcoin_state.push_response(BitcoinAdapterResponse {
        response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
            GetSuccessorsResponse::default(),
        ),
        callback_id,
    });
    assert_eq!(
        res,
        Err(BitcoinStateError::NonMatchingResponse { callback_id })
    );
}

#[test]
fn can_push_response_successfully() {
    let mut bitcoin_state = BitcoinState::default();

    // First request to be enqueued, so callback_id 0 is assigned to it.
    let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
        processed_block_hashes: vec![vec![10; 32]],
        anchor: vec![10; 32],
    });
    bitcoin_state.adapter_queues.push_request(request).unwrap();
    assert_eq!(bitcoin_state.adapter_queues.num_requests(), 1);
    assert_eq!(bitcoin_state.adapter_queues.num_responses(), 0);

    // Push corresponding response -- should clear the request and enqueue the response.
    bitcoin_state
        .push_response(BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                GetSuccessorsResponse::default(),
            ),
            callback_id: 0,
        })
        .unwrap();
    assert_eq!(bitcoin_state.adapter_queues.num_requests(), 0);
    assert_eq!(bitcoin_state.adapter_queues.num_responses(), 1);
}

#[test]
fn can_detect_in_flight_get_successors_requests() {
    let mut bitcoin_state = BitcoinState::default();
    assert!(!bitcoin_state
        .adapter_queues
        .has_in_flight_get_successors_requests());

    // Enqueue a `SendTransactionRequest` -- should not affect the in flight `GetSuccessorsRequest`s.
    let request = BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
        transaction: vec![5; 32],
    });
    bitcoin_state.adapter_queues.push_request(request).unwrap();
    assert!(!bitcoin_state
        .adapter_queues
        .has_in_flight_get_successors_requests());

    // Enqueue a `GetSuccessorsRequest` -- should see the effect on in flight `GetSuccessorRequest`s.
    let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
        processed_block_hashes: vec![vec![10; 32]],
        anchor: vec![10; 32],
    });
    bitcoin_state.adapter_queues.push_request(request).unwrap();
    assert!(bitcoin_state
        .adapter_queues
        .has_in_flight_get_successors_requests());

    // Clear the `SendTransactionRequest` -- should not affect in flight `GetSuccessorsRequest`s.
    bitcoin_state
        .push_response(BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::SendTransactionResponse(
                SendTransactionResponse::default(),
            ),
            callback_id: 0,
        })
        .unwrap();
    assert!(bitcoin_state
        .adapter_queues
        .has_in_flight_get_successors_requests());

    // Clear the `GetSuccessorsRequest` -- should affect in flight `GetSuccessorsRequest`s.
    bitcoin_state
        .push_response(BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::SendTransactionResponse(
                SendTransactionResponse::default(),
            ),
            callback_id: 1,
        })
        .unwrap();
    assert!(!bitcoin_state
        .adapter_queues
        .has_in_flight_get_successors_requests());
}

#[test]
fn can_pop_responses_in_the_correct_order() {
    let mut bitcoin_state = BitcoinState::default();
    let num_adapter_responses = 3;

    let mut responses = vec![];
    for i in 0..num_adapter_responses {
        responses.push(BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                GetSuccessorsResponse::default(),
            ),
            callback_id: i,
        });
    }

    for i in 0..num_adapter_responses {
        let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequest {
            processed_block_hashes: vec![vec![i as u8; 32]],
            anchor: vec![i as u8; 32],
        });
        bitcoin_state.adapter_queues.push_request(request).unwrap();
        bitcoin_state
            .push_response(responses[i as usize].clone())
            .unwrap();
    }

    for i in 0..num_adapter_responses {
        assert_eq!(
            bitcoin_state.adapter_queues.pop_response(),
            Some(responses[i as usize].clone())
        );
    }
    assert_eq!(bitcoin_state.adapter_queues.pop_response(), None);
}
