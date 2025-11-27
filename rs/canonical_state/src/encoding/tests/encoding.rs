use super::test_fixtures::*;
use crate::{all_supported_versions, encoding::*};

#[test]
fn roundtrip_encoding_stream_header() {
    for certification_version in all_supported_versions() {
        let header = stream_header(certification_version);

        assert_eq!(
            header,
            decode_stream_header(&encode_stream_header(&header, certification_version)).unwrap()
        );
    }
}

#[test]
fn roundtrip_encoding_request() {
    for certification_version in all_supported_versions() {
        let request = request(certification_version);

        assert_eq!(
            request,
            decode_message(&encode_message(&request, certification_version)).unwrap()
        );
    }
}

#[test]
fn roundtrip_encoding_response() {
    for certification_version in all_supported_versions() {
        let response = response(certification_version);

        assert_eq!(
            response,
            decode_message(&encode_message(&response, certification_version)).unwrap()
        );
    }
}

#[test]
fn roundtrip_encoding_reject_response() {
    for certification_version in all_supported_versions() {
        let reject = reject_response(certification_version);

        assert_eq!(
            reject,
            decode_message(&encode_message(&reject, certification_version)).unwrap()
        );
    }
}

#[test]
fn roundtrip_encoding_anonymous_refund() {
    for certification_version in
        all_supported_versions().filter(|v| v >= &CertificationVersion::V22)
    {
        let refund = anonymous_refund(certification_version);

        assert_eq!(
            refund,
            decode_message(&encode_message(&refund, certification_version)).unwrap()
        );
    }
}
