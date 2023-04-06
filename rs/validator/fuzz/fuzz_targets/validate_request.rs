#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use assert_matches::assert_matches;
use ic_base_types::CanisterId;
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequest, HttpRequestEnvelope,
    HttpUserQuery,
};
use ic_types::time::GENESIS;
use ic_validator_ingress_message::IngressMessageVerifier;
use ic_validator_ingress_message::RequestValidationError;
use ic_validator_ingress_message::{HttpRequestVerifier, TimeProvider};
use lazy_static::lazy_static;
use libfuzzer_sys::{fuzz_target, Corpus};
use std::ops::RangeInclusive;

lazy_static! {
    static ref VERIFIER: IngressMessageVerifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(GENESIS))
        .build();
}

fuzz_target!(|content: AnonymousContent| -> Corpus {
    let (call_content, query_content) = (
        HttpCallContent::from(content.clone()),
        HttpQueryContent::from(content),
    );
    match (
        HttpRequest::try_from(anonymous_http_request_envelope(call_content)),
        HttpRequest::try_from(anonymous_http_request_envelope(query_content)),
    ) {
        (Err(_), Err(_)) => Corpus::Reject,
        (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
            panic!("Parsing of HttpCallContent inconsistent with that of HttpQueryContent")
        }
        (Ok(call_request), Ok(query_request)) => {
            let validation_call_request = VERIFIER.validate_request(&call_request);
            let validation_query_request = VERIFIER.validate_request(&query_request);
            assert_eq_ignoring_timestamps_in_error_messages(
                validation_call_request,
                validation_query_request,
            );
            Corpus::Keep
        }
    }
});

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnonymousContent {
    canister_id: Blob,
    method_name: String,
    arg: Blob,
    ingress_expiry: u64,
    nonce: Option<Blob>,
}

impl AnonymousContent {
    fn sender(&self) -> Blob {
        const ANONYMOUS_SENDER: u8 = 0x04;
        Blob(vec![ANONYMOUS_SENDER])
    }
}

impl<'a> Arbitrary<'a> for AnonymousContent {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(AnonymousContent {
            canister_id: somewhat_arbitrary_canister_id(u)?,
            method_name: String::arbitrary(u)?,
            arg: arbitrary_blob(u)?,
            ingress_expiry: u64::arbitrary(u)?,
            nonce: arbitrary_option_blob(u)?,
        })
    }
}

impl From<AnonymousContent> for HttpCallContent {
    fn from(content: AnonymousContent) -> Self {
        let sender = content.sender();
        HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: content.canister_id,
                method_name: content.method_name,
                arg: content.arg,
                sender,
                ingress_expiry: content.ingress_expiry,
                nonce: content.nonce,
            },
        }
    }
}

impl From<AnonymousContent> for HttpQueryContent {
    fn from(content: AnonymousContent) -> Self {
        let sender = content.sender();
        HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: content.canister_id,
                method_name: content.method_name,
                arg: content.arg,
                sender,
                ingress_expiry: content.ingress_expiry,
                nonce: content.nonce,
            },
        }
    }
}

fn arbitrary_blob(u: &mut Unstructured) -> Result<Blob> {
    Ok(Blob(<Vec<u8>>::arbitrary(u)?))
}

/// A CanisterId wraps a PrincipalId, whose length is at most 29 bytes.
/// We want to produce syntactically correct CanisterIds to avoid the fuzzer stopping too early,
/// while avoiding biasing the fuzzer too much.
fn somewhat_arbitrary_canister_id(u: &mut Unstructured) -> Result<Blob> {
    match u8::arbitrary(u)? % 4 {
        0 => arbitrary_blob(u),
        _ => {
            let bytes = arbitrary_variable_length_vector(u, 0..=29)?;
            assert_matches!(CanisterId::try_from(&bytes), Ok(_));
            Ok(Blob(bytes))
        }
    }
}

fn arbitrary_variable_length_vector<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    length_range: RangeInclusive<usize>,
) -> Result<Vec<T>> {
    let length: usize = u.int_in_range(length_range)?;
    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        result.push(T::arbitrary(u)?)
    }
    Ok(result)
}

fn arbitrary_option_blob<'a>(u: &mut Unstructured<'a>) -> Result<Option<Blob>> {
    Ok(if <bool as Arbitrary<'a>>::arbitrary(u)? {
        Some(arbitrary_blob(u)?)
    } else {
        None
    })
}

fn anonymous_http_request_envelope<C>(content: C) -> HttpRequestEnvelope<C> {
    HttpRequestEnvelope {
        content,
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    }
}

fn assert_eq_ignoring_timestamps_in_error_messages(
    result: std::result::Result<(), RequestValidationError>,
    other: std::result::Result<(), RequestValidationError>,
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
