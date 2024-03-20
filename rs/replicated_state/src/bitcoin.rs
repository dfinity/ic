use crate::{ReplicatedState, StateError};
use ic_btc_types_internal::{
    BitcoinAdapterResponse, BitcoinAdapterResponseWrapper, BlockBlob,
    GetSuccessorsResponseComplete, GetSuccessorsResponsePartial,
};
use ic_error_types::RejectCode;
use ic_management_canister_types::{BitcoinGetSuccessorsResponse, EmptyBlob, Payload as _};
use ic_types::{
    messages::{CallbackId, Payload, RejectContext, Response},
    CanisterId,
};
use std::cmp::min;

// The maximum size a response can have without applying pagination.
// This number is slightly less than the maximum payload size a canister can send (2MiB)
// to leave a small buffer for the additional space that candid encoding may need.
//
// NOTE: This constant should be = the `MAX_RESPONSE_SIZE` defined in the bitcoin adapter's
// `get_successors_handler.rs`.
const MAX_RESPONSE_SIZE: usize = 2_000_000;

/// Pushes a response from the Bitcoin Adapter into the state.
pub fn push_response(
    state: &mut ReplicatedState,
    response: BitcoinAdapterResponse,
) -> Result<(), StateError> {
    match response.response {
        BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) => {
            // Received a response to a request from the bitcoin wasm canister.
            // Retrieve the associated request.
            let callback_id = CallbackId::from(response.callback_id);
            let context = state
                .metadata
                .subnet_call_context_manager
                .bitcoin_get_successors_contexts
                .get_mut(&callback_id)
                .ok_or_else(|| StateError::BitcoinNonMatchingResponse {
                    callback_id: callback_id.get(),
                })?;

            let response_payload = match maybe_split_response(r) {
                Ok((initial_response, follow_ups)) => {
                    // Store the follow-ups for later (overwrites previous ones).
                    state
                        .metadata
                        .bitcoin_get_successors_follow_up_responses
                        .insert(context.request.sender(), follow_ups);

                    Payload::Data(initial_response.encode())
                }
                Err(err) => Payload::Reject(RejectContext::new(
                    RejectCode::CanisterError,
                    format!("Received invalid response from adapter: {:?}", err),
                )),
            };

            // Add response to the consensus queue.
            state.consensus_queue.push(Response {
                originator: context.request.sender(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: callback_id,
                refund: context.request.take_cycles(),
                response_payload,
                // Not relevant, the consensus queue is flushed every round by the
                // scheduler, which uses only the payload and originator callback.
                deadline: context.request.deadline,
            });

            Ok(())
        }
        BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            let context = state
                .metadata
                .subnet_call_context_manager
                .bitcoin_send_transaction_internal_contexts
                .get_mut(&callback_id)
                .ok_or_else(|| StateError::BitcoinNonMatchingResponse {
                    callback_id: callback_id.get(),
                })?;

            // The response to a `send_transaction` call is always the empty blob.
            let response_payload = Payload::Data(EmptyBlob.encode());

            // Add response to the consensus queue.
            state.consensus_queue.push(Response {
                originator: context.request.sender(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: callback_id,
                refund: context.request.take_cycles(),
                response_payload,
                // Not relevant, the consensus queue is flushed every round by the
                // scheduler, which uses only the payload and originator callback.
                deadline: context.request.deadline,
            });

            Ok(())
        }
        BitcoinAdapterResponseWrapper::GetSuccessorsReject(reject) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            let context = state
                .metadata
                .subnet_call_context_manager
                .bitcoin_get_successors_contexts
                .get_mut(&callback_id)
                .ok_or_else(|| StateError::BitcoinNonMatchingResponse {
                    callback_id: callback_id.get(),
                })?;

            let reject_payload =
                Payload::Reject(RejectContext::new(reject.reject_code, reject.message));

            // Add response to the consensus queue.
            state.consensus_queue.push(Response {
                originator: context.request.sender(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: callback_id,
                refund: context.request.take_cycles(),
                response_payload: reject_payload,
                // Not relevant, the consensus queue is flushed every round by the
                // scheduler, which uses only the payload and originator callback.
                deadline: context.request.deadline,
            });

            Ok(())
        }
        BitcoinAdapterResponseWrapper::SendTransactionReject(reject) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            let context = state
                .metadata
                .subnet_call_context_manager
                .bitcoin_send_transaction_internal_contexts
                .get_mut(&callback_id)
                .ok_or_else(|| StateError::BitcoinNonMatchingResponse {
                    callback_id: callback_id.get(),
                })?;

            let reject_payload =
                Payload::Reject(RejectContext::new(reject.reject_code, reject.message));

            // Add response to the consensus queue.
            state.consensus_queue.push(Response {
                originator: context.request.sender(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: callback_id,
                refund: context.request.take_cycles(),
                response_payload: reject_payload,
                // Not relevant, the consensus queue is flushed every round by the
                // scheduler, which uses only the payload and originator callback.
                deadline: context.request.deadline,
            });

            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SplitError {
    NotOneBlock,
    ResponseTooLarge,
}

// Splits a response if it's too large into a "partial response" and a list of "follow up"
// responses.
fn maybe_split_response(
    response: GetSuccessorsResponseComplete,
) -> Result<(BitcoinGetSuccessorsResponse, Vec<BlockBlob>), SplitError> {
    if response.count_bytes() > MAX_RESPONSE_SIZE {
        if response.blocks.len() != 1 {
            return Err(SplitError::NotOneBlock);
        }

        let block = &response.blocks[0];
        let mut follow_ups = vec![];

        let first_response_block_size =
            MAX_RESPONSE_SIZE.saturating_sub(response.count_next_bytes());
        let mut i = first_response_block_size;
        while i < block.len() {
            let follow_up_length = min(MAX_RESPONSE_SIZE, block.len() - i);
            follow_ups.push(block[i..i + follow_up_length].to_vec());
            i += follow_up_length;
        }

        let remaining_follow_ups = if follow_ups.len() > u8::MAX as usize {
            return Err(SplitError::ResponseTooLarge);
        } else {
            follow_ups.len() as u8
        };

        let initial_response = GetSuccessorsResponsePartial {
            partial_block: block[0..first_response_block_size].to_vec(),
            next: response.next,
            remaining_follow_ups,
        };

        Ok((
            BitcoinGetSuccessorsResponse::Partial(initial_response),
            follow_ups,
        ))
    } else {
        Ok((BitcoinGetSuccessorsResponse::Complete(response), vec![]))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn maybe_split_response_returns_error_if_not_exactly_one_block() {
        assert_eq!(
            maybe_split_response(GetSuccessorsResponseComplete {
                blocks: vec![vec![0; MAX_RESPONSE_SIZE], vec![0]], // two blocks exceeding size.
                next: vec![],
            }),
            Err(SplitError::NotOneBlock)
        );

        assert_eq!(
            maybe_split_response(GetSuccessorsResponseComplete {
                blocks: vec![],
                next: vec![vec![0; MAX_RESPONSE_SIZE + 1]],
            }),
            Err(SplitError::NotOneBlock)
        );
    }

    #[test]
    fn maybe_split_response_two_pages() {
        assert_eq!(
            maybe_split_response(GetSuccessorsResponseComplete {
                blocks: vec![vec![0; MAX_RESPONSE_SIZE + 1]],
                next: vec![],
            }),
            Ok((
                BitcoinGetSuccessorsResponse::Partial(GetSuccessorsResponsePartial {
                    partial_block: vec![0; MAX_RESPONSE_SIZE],
                    next: vec![],
                    remaining_follow_ups: 1
                }),
                vec![vec![0]]
            ))
        );
    }

    #[test]
    fn maybe_split_response_three_pages() {
        assert_eq!(
            maybe_split_response(GetSuccessorsResponseComplete {
                blocks: vec![vec![0; MAX_RESPONSE_SIZE * 2 + 1]],
                next: vec![],
            }),
            Ok((
                BitcoinGetSuccessorsResponse::Partial(GetSuccessorsResponsePartial {
                    partial_block: vec![0; MAX_RESPONSE_SIZE],
                    next: vec![],
                    remaining_follow_ups: 2
                }),
                vec![vec![0; MAX_RESPONSE_SIZE], vec![0]]
            ))
        );
    }
}
