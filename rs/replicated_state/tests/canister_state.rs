#[cfg(test)]
mod canister_state {
    use ic_replicated_state::StateError;
    use ic_test_utilities::state::{
        get_running_canister, get_stopped_canister, get_stopping_canister,
    };
    use ic_test_utilities::types::ids::canister_test_id;
    use ic_test_utilities::types::messages::{RequestBuilder, ResponseBuilder};
    use ic_types::messages::RequestOrResponse;
    use ic_types::QueueIndex;

    #[test]
    fn running_canister_accepts_requests() {
        let mut canister = get_running_canister(canister_test_id(0));

        assert_eq!(
            canister.push_input(
                QueueIndex::new(0),
                RequestOrResponse::Request(RequestBuilder::new().build())
            ),
            Ok(())
        );
    }

    #[test]
    fn running_canister_accepts_responses() {
        let mut canister = get_running_canister(canister_test_id(0));

        assert_eq!(
            canister.push_output_request(
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(canister_test_id(1))
                    .build(),
            ),
            Ok(())
        );

        assert_eq!(
            canister.push_input(
                QueueIndex::new(0),
                RequestOrResponse::Response(
                    ResponseBuilder::new()
                        .originator(canister_test_id(0))
                        .respondent(canister_test_id(1))
                        .build()
                )
            ),
            Ok(())
        );
    }

    #[test]
    fn stopping_canister_rejects_requests() {
        let mut canister = get_stopping_canister(canister_test_id(0));

        let request = RequestOrResponse::Request(RequestBuilder::new().build());
        assert_eq!(
            canister.push_input(QueueIndex::new(0), request.clone()),
            Err((StateError::CanisterStopping(canister_test_id(0)), request))
        );
    }

    #[test]
    fn stopping_canister_accepts_responses() {
        let mut canister = get_stopping_canister(canister_test_id(0));

        assert_eq!(
            canister.push_output_request(
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(canister_test_id(1))
                    .build(),
            ),
            Ok(())
        );

        let response = RequestOrResponse::Response(
            ResponseBuilder::new()
                .originator(canister_test_id(0))
                .respondent(canister_test_id(1))
                .build(),
        );
        assert_eq!(canister.push_input(QueueIndex::new(0), response), Ok(()));
    }

    #[test]
    fn stopped_canister_rejects_requests() {
        let mut canister = get_stopped_canister(canister_test_id(0));

        let request = RequestOrResponse::Request(RequestBuilder::new().build());
        assert_eq!(
            canister.push_input(QueueIndex::new(0), request.clone()),
            Err((StateError::CanisterStopped(canister_test_id(0)), request))
        );
    }

    #[test]
    fn stopped_canister_rejects_responses() {
        let mut canister = get_stopped_canister(canister_test_id(0));

        assert_eq!(
            canister.push_output_request(
                RequestBuilder::new()
                    .sender(canister_test_id(0))
                    .receiver(canister_test_id(1))
                    .build(),
            ),
            Ok(())
        );

        let response = RequestOrResponse::Response(
            ResponseBuilder::new()
                .originator(canister_test_id(0))
                .respondent(canister_test_id(1))
                .build(),
        );
        assert_eq!(
            canister.push_input(QueueIndex::new(0), response.clone()),
            Err((StateError::CanisterStopped(canister_test_id(0)), response))
        );
    }
}
