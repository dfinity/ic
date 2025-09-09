#![no_main]

use ic_types::messages::{
    HttpCallContent, HttpQueryContent, HttpReadStateContent, HttpRequest, HttpRequestEnvelope,
    HttpRequestError,
};
use ic_types::time::GENESIS;
use ic_validator_http_request_arbitrary::AnonymousContent;
use ic_validator_ingress_message::IngressMessageVerifier;
use ic_validator_ingress_message::RequestValidationError;
use ic_validator_ingress_message::{HttpRequestVerifier, TimeProvider};
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(|content: AnonymousContent| -> Corpus {
    let (call_content, query_content, read_content) = (
        HttpCallContent::from(content.clone()),
        HttpQueryContent::from(content.clone()),
        HttpReadStateContent::from(content),
    );
    match (
        HttpRequest::try_from(anonymous_http_request_envelope(call_content)),
        HttpRequest::try_from(anonymous_http_request_envelope(query_content)),
        HttpRequest::try_from(anonymous_http_request_envelope(read_content)),
    ) {
        (Err(_), Err(_), Err(_)) => Corpus::Reject,
        // canister id may be invalid but irrelevant for ReadStateContent
        (
            Err(HttpRequestError::InvalidPrincipalId(err_parse_call)),
            Err(HttpRequestError::InvalidPrincipalId(err_parse_query)),
            _,
        ) if err_parse_call.contains("Converting canister_id")
            && err_parse_query.contains("Converting canister_id") =>
        {
            Corpus::Reject
        }
        (Ok(call_request), Ok(query_request), Ok(read_request)) => {
            let verifier = IngressMessageVerifier::builder()
                .with_time_provider(TimeProvider::Constant(GENESIS))
                .build();
            let validation_call_request = verifier.validate_request(&call_request);
            let validation_query_request = verifier.validate_request(&query_request);
            let validation_read_request = verifier.validate_request(&read_request);
            assert_eq_ignoring_timestamps_in_error_messages(
                &validation_call_request,
                &validation_query_request,
            );
            match validation_read_request {
                Err(RequestValidationError::PathTooLongError { .. })
                | Err(RequestValidationError::TooManyPathsError { .. }) => Corpus::Reject,
                _ => {
                    assert_eq_ignoring_timestamps_in_error_messages(
                        &validation_call_request,
                        &validation_read_request,
                    );
                    Corpus::Keep
                }
            }
        }
        (result_call_request, result_query_request, result_read_request) => {
            panic!(
                "Parsing of HttpCallContent {result_call_request:?}, HttpQueryContent {result_query_request:?} and HttpReadStateContent are inconsistent {result_read_request:?}"
            )
        }
    }
});

fn anonymous_http_request_envelope<C>(content: C) -> HttpRequestEnvelope<C> {
    HttpRequestEnvelope {
        content,
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    }
}

fn assert_eq_ignoring_timestamps_in_error_messages(
    result: &std::result::Result<(), RequestValidationError>,
    other: &std::result::Result<(), RequestValidationError>,
) {
    match (result, other) {
        (
            Err(RequestValidationError::InvalidIngressExpiry(_msg1)), //contains output of chrono::Utc::now()
            Err(RequestValidationError::InvalidIngressExpiry(_msg2)),
        ) => {}
        (
            Err(RequestValidationError::InvalidDelegationExpiry(_msg1)), //contains output of chrono::Utc::now()
            Err(RequestValidationError::InvalidDelegationExpiry(_msg2)),
        ) => {}
        (a, b) => assert_eq!(a, b),
    }
}
