use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsResponse, BitcoinSendTransactionInternalArgs,
    Payload,
};
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{
        BitcoinGetSuccessorsContext, BitcoinSendTransactionInternalContext, SubnetCallContext,
    },
};
use ic_types::{CanisterId, messages::Request};

/// Handles a `bitcoin_get_successors` request.
/// Returns Ok if the request has been accepted, and an error otherwise.
pub fn get_successors(
    privileged_access: &[CanisterId],
    request: &Request,
    state: &mut ReplicatedState,
) -> Result<Option<Vec<u8>>, UserError> {
    if !privileged_access.contains(&request.sender()) {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            String::from("Permission denied."),
        ));
    }

    // Remove follow-up responses for canisters that no longer have access to this API.
    state
        .metadata
        .bitcoin_get_successors_follow_up_responses
        .retain(|sender, _| privileged_access.contains(sender));

    match BitcoinGetSuccessorsArgs::decode(request.method_payload()) {
        Ok(get_successors_request) => {
            match get_successors_request {
                BitcoinGetSuccessorsArgs::Initial(payload) => {
                    // Insert request into subnet call contexts.
                    state.metadata.subnet_call_context_manager.push_context(
                        SubnetCallContext::BitcoinGetSuccessors(BitcoinGetSuccessorsContext {
                            request: request.clone(),
                            payload,
                            time: state.time(),
                        }),
                    );

                    Ok(None)
                }
                BitcoinGetSuccessorsArgs::FollowUp(follow_up_index) => {
                    match state
                        .metadata
                        .bitcoin_get_successors_follow_up_responses
                        .get(&request.sender())
                    {
                        Some(follow_up_responses) => {
                            match follow_up_responses.get(follow_up_index as usize) {
                                Some(payload) => Ok(Some(
                                    BitcoinGetSuccessorsResponse::FollowUp(payload.to_vec())
                                        .encode(),
                                )),
                                None => Err(UserError::new(
                                    ErrorCode::CanisterRejectedMessage,
                                    "Page not found.",
                                )),
                            }
                        }
                        None => Err(UserError::new(
                            ErrorCode::CanisterRejectedMessage,
                            "Follow up request not found",
                        )),
                    }
                }
            }
        }
        Err(err) => Err(err),
    }
}

/// Handles a `bitcoin_send_transaction_internal` request.
/// Returns Ok if the request has been accepted, and an error otherwise.
pub fn send_transaction_internal(
    privileged_access: &[CanisterId],
    request: &Request,
    state: &mut ReplicatedState,
) -> Result<(), UserError> {
    if !privileged_access.contains(&request.sender()) {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            String::from("Permission denied."),
        ));
    }

    match BitcoinSendTransactionInternalArgs::decode(request.method_payload()) {
        Ok(send_transaction_internal_request) => {
            // Insert request into subnet call contexts.
            state.metadata.subnet_call_context_manager.push_context(
                SubnetCallContext::BitcoinSendTransactionInternal(
                    BitcoinSendTransactionInternalContext {
                        request: request.clone(),
                        payload: send_transaction_internal_request,
                        time: state.time(),
                    },
                ),
            );

            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use ic_management_canister_types_private::{
        BitcoinGetSuccessorsArgs, IC_00, Method, Payload as Ic00Payload,
    };
    use ic_test_utilities::universal_canister::{call_args, wasm};
    use ic_test_utilities_execution_environment::ExecutionTestBuilder;
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::{CanisterId, PrincipalId};
    use std::str::FromStr;

    #[test]
    fn clears_state_of_former_bitcoin_canisters() {
        let bitcoin_canister_id = CanisterId::unchecked_from_principal(
            PrincipalId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap(),
        );

        let mut test = ExecutionTestBuilder::new()
            // Set the bitcoin canister to be the ID of the canister about to be created.
            .with_bitcoin_privileged_access(bitcoin_canister_id)
            .with_bitcoin_follow_up_responses(bitcoin_canister_id, vec![vec![1], vec![2]])
            .with_bitcoin_follow_up_responses(
                canister_test_id(123),
                vec![vec![1], vec![2], vec![3]],
            )
            .with_provisional_whitelist_all()
            .build();

        let uni = test.universal_canister().unwrap();
        assert_eq!(
            uni.get_ref(),
            &bitcoin_canister_id.get(),
            "id of universal canister doesn't match expected id"
        );

        let call = wasm()
            .call_simple(
                IC_00,
                Method::BitcoinGetSuccessors,
                call_args()
                    .other_side(BitcoinGetSuccessorsArgs::FollowUp(3).encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();

        test.ingress(uni, "update", call).unwrap();

        assert_eq!(
            test.state()
                .metadata
                .bitcoin_get_successors_follow_up_responses,
            maplit::btreemap! { bitcoin_canister_id => vec![vec![1], vec![2]] }
        );
    }
}
