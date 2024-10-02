use super::test_fixtures::*;
use crate::encoding::types::{self, StreamFlagBits, STREAM_DEFAULT_FLAGS, STREAM_SUPPORTED_FLAGS};
use crate::{all_supported_versions, CertificationVersion, MAX_SUPPORTED_CERTIFICATION_VERSION};
use assert_matches::assert_matches;
use ic_error_types::RejectCode;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::messages::{Payload, RejectContext, RequestOrResponse};
use ic_types::xnet::RejectReason;
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

/// Decoding a slice with unsupported flags should return an error but not panic.
#[test]
fn try_from_stream_header_with_unsupported_flags() {
    let mut header = types::StreamHeader::from((
        &stream_header(CertificationVersion::V18),
        CertificationVersion::V18,
    ));
    header.flags = 4;

    assert_matches!(
        ic_types::xnet::StreamHeader::try_from(header),
        Err(ProxyDecodeError::Other(message)) if message.contains("unsupported flags")
    );
}

#[test]
fn try_from_stream_header_with_deprecated_reject_signal_deltas_containing_zero() {
    let mut header = types::StreamHeader::from((
        &stream_header(CertificationVersion::V18),
        CertificationVersion::V18,
    ));
    header.deprecated_reject_signal_deltas = vec![0, 1, 13];

    assert_matches!(
        ic_types::xnet::StreamHeader::try_from(header),
        Err(ProxyDecodeError::Other(message)) if message.contains("found bad delta: `0` is not allowed")
    );
}

#[test]
fn try_from_stream_header_with_out_of_range_deprecated_reject_signal_deltas() {
    let mut header = types::StreamHeader::from((
        &stream_header(CertificationVersion::V18),
        CertificationVersion::V18,
    ));
    header.deprecated_reject_signal_deltas = vec![header.signals_end + 100, 1, 13];

    assert_matches!(
        ic_types::xnet::StreamHeader::try_from(header),
        Err(ProxyDecodeError::Other(message)) if message.contains("reject signals are invalid, got `signals_end`")
    );
}

/// Takes a `types::StreamHeader` and overwrites a specific flavor of reject signal deltas.
fn with_stream_header_deltas(
    mut header: types::StreamHeader,
    reason: RejectReason,
    deltas: Vec<u64>,
) -> types::StreamHeader {
    use RejectReason::*;
    match reason {
        CanisterMigrating => header.reject_signals.canister_migrating_deltas = deltas,
        CanisterNotFound => header.reject_signals.canister_not_found_deltas = deltas,
        CanisterStopped => header.reject_signals.canister_stopped_deltas = deltas,
        CanisterStopping => header.reject_signals.canister_stopping_deltas = deltas,
        QueueFull => header.reject_signals.queue_full_deltas = deltas,
        OutOfMemory => header.reject_signals.out_of_memory_deltas = deltas,
        Unknown => header.reject_signals.unknown_deltas = deltas,
    }
    header
}

/// Decoding a `types::StreamHeader` with invalid signals that contain 0's should return an error but not panic.
#[test]
fn try_from_stream_header_with_invalid_signals_containing_zero() {
    for reason in RejectReason::iter() {
        let header = with_stream_header_deltas(
            types::StreamHeader::from((
                &stream_header(MAX_SUPPORTED_CERTIFICATION_VERSION),
                MAX_SUPPORTED_CERTIFICATION_VERSION,
            )),
            reason,
            vec![17, 0, 13],
        );

        assert_matches!(
            ic_types::xnet::StreamHeader::try_from(header),
            Err(ProxyDecodeError::Other(message)) if message.contains("found bad delta: `0` is not allowed")
        );
    }
}

/// Decoding a `types::StreamHeader` with out of range invalid signals should return an error but not panic.
#[test]
fn try_from_stream_header_with_invalid_signals_out_of_range() {
    for reason in RejectReason::iter() {
        let header = with_stream_header_deltas(
            types::StreamHeader::from((
                &stream_header(MAX_SUPPORTED_CERTIFICATION_VERSION),
                MAX_SUPPORTED_CERTIFICATION_VERSION,
            )),
            reason,
            vec![u64::MAX, 1, 13],
        );

        assert_matches!(
            ic_types::xnet::StreamHeader::try_from(header),
            Err(ProxyDecodeError::Other(message)) if message.contains("reject signals are invalid, got `signals_end`")
        );
    }
}

/// Decoding a `types::StreamHeader` with duplicate stream incides across two flavors should return
/// an error but not panic.
#[test]
fn try_from_stream_header_with_invalid_signals_duplicates() {
    let mut header = types::StreamHeader::from((
        &stream_header(MAX_SUPPORTED_CERTIFICATION_VERSION),
        MAX_SUPPORTED_CERTIFICATION_VERSION,
    ));
    header.reject_signals.canister_stopped_deltas = vec![3, 15]; // 15 + 3 = 18
    header.reject_signals.canister_stopping_deltas = vec![6, 12]; // 12 + 6 = 18

    assert_matches!(
        ic_types::xnet::StreamHeader::try_from(header),
        Err(ProxyDecodeError::Other(message)) if message.contains("reject signals are invalid, got duplicates")
    );
}

/// Tests that converting a canonical stream header with both deprecated and contemporary reject signals
/// should return an error but not panic.
#[test]
fn try_from_stream_header_with_deprecated_and_contemporary_reject_signals_populated() {
    let mut header = types::StreamHeader::from((
        &stream_header(MAX_SUPPORTED_CERTIFICATION_VERSION),
        MAX_SUPPORTED_CERTIFICATION_VERSION,
    ));
    header.deprecated_reject_signal_deltas = vec![1, 13, 17];

    assert_matches!(
        ic_types::xnet::StreamHeader::try_from(header),
        Err(ProxyDecodeError::Other(message)) if message.contains("both deprecated and contemporary reject signals are populated")
    );
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

    assert_matches!(
        RequestOrResponse::try_from(message),
        Err(ProxyDecodeError::Other(message)) if message == "RequestOrResponse: expected exactly one of `request` or `response` to be `Some(_)`, got `RequestOrResponse { request: None, response: None }`"
    );
}

#[test]
fn try_from_empty_payload() {
    let payload = types::Payload {
        data: None,
        reject: None,
    };

    assert_matches!(
        Payload::try_from(payload),
        Err(ProxyDecodeError::Other(payload)) if payload == "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `Payload { data: None, reject: None }`"
    );
}

/// Invalid `RejectCode`: 0.
#[test]
fn try_from_reject_context_code_zero() {
    let context = types::RejectContext {
        code: 0,
        message: "Oops".into(),
    };

    assert_matches!(
        RejectContext::try_from(context),
        Err(ProxyDecodeError::ValueOutOfRange { typ, err}) if typ == "RejectContext" && err == "0"
    );
}

/// Invalid `RejectCode`: `RejectCode::MAX + 1`.
#[test]
fn try_from_reject_context_code_out_of_range() {
    let context = types::RejectContext {
        code: RejectCode::SysUnknown as u8 + 1,
        message: "Oops".into(),
    };

    assert_matches!(
        RejectContext::try_from(context),
        Err(ProxyDecodeError::ValueOutOfRange { typ, err }) if typ == "RejectContext" && err == "7"
    );
}
