use candid::candid_method;
use ic_cdk::query;
use ic_types::Time;
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpRequest, HttpRequestEnvelope,
};
use ic_validator_ingress_message::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};

/// Validate an internally-created dummy HTTP request with a provided ingress expiry.
#[query]
#[candid_method(query)]
fn create_and_validate_anonymous_http_with_ingress_expiry_time(
    current_time_in_ns_since_unix_epoch: u64,
    ingress_expiry: u64,
) -> bool {
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(Time::from_nanos_since_unix_epoch(
            current_time_in_ns_since_unix_epoch,
        )))
        .build();
    let request = HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
        content: HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method".to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x04]),
                nonce: None,
                ingress_expiry,
            },
        },
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    })
    .expect("invalid http envelope");
    let result = verifier.validate_request(&request);
    result.is_ok()
}

#[cfg(not(test))]
fn main() {}
