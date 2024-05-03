use super::test_fixtures::*;
use crate::encoding::types::{StreamFlagBits, STREAM_DEFAULT_FLAGS, STREAM_SUPPORTED_FLAGS};
use crate::{all_supported_versions, encoding::types};
use ic_error_types::RejectCode;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::messages::{Payload, RejectContext, RequestOrResponse};
use std::convert::{TryFrom, TryInto};
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn stream_flags_constant_default_and_default_are_equivalent() {
    let default_flags = ic_types::xnet::StreamFlags::default();
    assert_eq!(default_flags, STREAM_DEFAULT_FLAGS);

    let ic_types::xnet::StreamFlags {
        deprecated_responses_only,
    } = default_flags;
    assert!(!deprecated_responses_only);
}

/// Validates that the flags defined by `StreamFlagBits` are well-formed.
#[test]
fn validate_stream_flag_bits() {
    // Ensure stream flag bits are mutually exclusive.
    assert_eq!(
        StreamFlagBits::COUNT,
        STREAM_SUPPORTED_FLAGS.count_ones() as usize
    );

    for stream_flag in StreamFlagBits::iter() {
        let stream_flag = stream_flag as u64;
        // Ensure the flag encompasses only one bit.
        assert_eq!(1, stream_flag.count_ones());
        // Ensure the flag is included in the supported flags mask.
        assert!(stream_flag & STREAM_SUPPORTED_FLAGS != 0);
    }
}

#[test]
fn roundtrip_conversion_stream_header() {
    for certification_version in all_supported_versions() {
        let header = stream_header(certification_version);

        assert_eq!(
            header,
            types::StreamHeader::from((&header, certification_version))
                .try_into()
                .unwrap()
        );
    }
}

/// Decoding a slice with wildly invalid signals should return an error but not panic.
#[test]
fn convert_stream_header_with_invalid_signals() {
    let header_with_invalid_signals = types::StreamHeader {
        begin: 23,
        end: 25,
        signals_end: 256,
        reject_signal_deltas: vec![300, 50, 6],
        flags: StreamFlagBits::DeprecatedResponsesOnly as u64,
    };
    match ic_types::xnet::StreamHeader::try_from(header_with_invalid_signals) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::Other(message)) => {
            assert_eq!("StreamHeader: reject signals are invalid, got `signals_end` 256, `reject_signal_deltas` [300, 50, 6]", message);
        }
        Err(err) => panic!("Expected Err(ProxyDecodeError::Other), got Err({:?})", err),
    }
}

/// Decoding a slice with unsupported flags should return an error but not panic.
#[test]
fn convert_stream_header_with_unsupported_flags() {
    let bad_bits = 4;
    let header_with_unsupported_flags = types::StreamHeader {
        begin: 23,
        end: 25,
        signals_end: 256,
        reject_signal_deltas: vec![50, 6],
        flags: bad_bits,
    };
    match ic_types::xnet::StreamHeader::try_from(header_with_unsupported_flags) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::Other(message)) => {
            assert_eq!(
                format!(
                    "StreamHeader: unsupported flags: got `flags` {:#b}, `supported_flags` {:#b}",
                    bad_bits, STREAM_SUPPORTED_FLAGS,
                ),
                message
            );
        }
        Err(err) => panic!("Expected Err(ProxyDecodeError::Other), got Err({:?})", err),
    }
}

#[test]
fn roundtrip_conversion_request() {
    for certification_version in all_supported_versions() {
        let request = request(certification_version);

        assert_eq!(
            request,
            types::RequestOrResponse::from((&request, certification_version))
                .try_into()
                .unwrap()
        );
    }
}

#[test]
fn roundtrip_conversion_response() {
    for certification_version in all_supported_versions() {
        let response = response(certification_version);

        assert_eq!(
            response,
            types::RequestOrResponse::from((&response, certification_version))
                .try_into()
                .unwrap()
        );
    }
}

#[test]
fn roundtrip_conversion_reject_response() {
    for certification_version in all_supported_versions() {
        let response = reject_response(certification_version);

        assert_eq!(
            response,
            types::RequestOrResponse::from((&response, certification_version))
                .try_into()
                .unwrap()
        );
    }
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
        Err(err) => panic!("Expected Err(ProxyDecodeError::Other), got Err({:?})", err),
    }
}

#[test]
fn try_from_empty_payload() {
    let payload = types::Payload {
        data: None,
        reject: None,
    };

    match Payload::try_from(payload) {
        Ok(ctx) => panic!("Expected Err(_), got Ok({:?})", ctx),
        Err(ProxyDecodeError::Other(payload)) => {
            assert_eq!(
                "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `Payload { data: None, reject: None }`",
                payload
            )
        }
        Err(err) => panic!("Expected Err(ProxyDecodeError::Other), got Err({:?})", err),
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
            assert_eq!(("RejectContext", "0"), (typ, err.as_str()))
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
            assert_eq!(("RejectContext", "6"), (typ, err.as_str()))
        }
        Err(err) => panic!(
            "Expected Err(ProxyDecodeError::ValueOutOfRange), got Err({:?})",
            err
        ),
    }
}
