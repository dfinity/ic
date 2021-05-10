use super::test_fixtures::*;
use crate::encoding::types;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    messages::{Payload, RejectContext, RequestOrResponse},
    user_error::RejectCode,
};
use std::convert::{TryFrom, TryInto};

#[test]
fn roundtrip_conversion_stream_header() {
    let header = stream_header();

    assert_eq!(
        header,
        types::StreamHeader::from(&header).try_into().unwrap()
    );
}

#[test]
fn roundtrip_conversion_request() {
    let request = request();

    assert_eq!(
        request,
        types::RequestOrResponse::from(&request).try_into().unwrap()
    );
}

#[test]
fn roundtrip_conversion_response() {
    let response = response();

    assert_eq!(
        response,
        types::RequestOrResponse::from(&response)
            .try_into()
            .unwrap()
    );
}

#[test]
fn roundtrip_conversion_reject_response() {
    let response = reject_response();

    assert_eq!(
        response,
        types::RequestOrResponse::from(&response)
            .try_into()
            .unwrap()
    );
}

#[test]
fn try_from_empty_request_or_response() {
    let message = types::RequestOrResponse {
        request: None,
        response: None,
    };

    match RequestOrResponse::try_from(message) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::Other(message)) => {
            assert_eq!(
                "RequestOrResponse: expected exactly one of `request` or `response` to be `Some(_)`, got `RequestOrResponse { request: None, response: None }`",
                message
            )
        }
        Err(err) => panic!(
            "Expected Err(ProxyDecodeError::Other), got Err({:?})",
            err
        ),
    }
}

#[test]
fn try_from_empty_payload() {
    let message = types::Payload {
        data: None,
        reject: None,
    };

    match Payload::try_from(message) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::Other(message)) => {
            assert_eq!(
                "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `Payload { data: None, reject: None }`",
                message
            )
        }
        Err(err) => panic!(
            "Expected Err(ProxyDecodeError::Other), got Err({:?})",
            err
        ),
    }
}

/// Invalid `RejectCode`: 0.
#[test]
fn try_from_reject_context_code_zero() {
    let context = types::RejectContext {
        code: 0,
        message: "Oops".into(),
    };

    match RejectContext::try_from(context) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::ValueOutOfRange { typ, err }) => {
            assert_eq!(("RejectCode", "0"), (typ, err.as_str()))
        }
        Err(err) => panic!(
            "Expected Err(ProxyDecodeError::ValueOutOfRange), got Err({:?})",
            err
        ),
    }
}

/// Invalid `RejectCode`: `RejectCode::MAX + 1`.
#[test]
fn try_from_reject_context_code_out_of_range() {
    let context = types::RejectContext {
        code: RejectCode::CanisterError as u8 + 1,
        message: "Oops".into(),
    };

    match RejectContext::try_from(context) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::ValueOutOfRange { typ, err }) => {
            assert_eq!(("RejectCode", "6"), (typ, err.as_str()))
        }
        Err(err) => panic!(
            "Expected Err(ProxyDecodeError::ValueOutOfRange), got Err({:?})",
            err
        ),
    }
}
