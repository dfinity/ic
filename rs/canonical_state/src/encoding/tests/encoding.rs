use super::test_fixtures::*;
use crate::{all_supported_versions, encoding::*};
use ic_test_utilities::types::messages::RequestBuilder;
use ic_types::messages::RequestMetadata;

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
fn request_missing_metadata_and_missing_metadata_fields_encode_the_same() {
    for certification_version in all_supported_versions() {
        let request1: RequestOrResponse = RequestBuilder::new().metadata(None).build().into();
        let request2: RequestOrResponse = RequestBuilder::new()
            .metadata(Some(RequestMetadata {
                call_tree_depth: None,
                call_tree_start_time: None,
            }))
            .build()
            .into();
        assert_eq!(
            encode_message(&request1, certification_version),
            encode_message(&request2, certification_version),
        );
    }
}

#[test]
fn roundtrip_encoding_response() {
    let response = response();

    for certification_version in all_supported_versions() {
        assert_eq!(
            response,
            decode_message(&encode_message(&response, certification_version)).unwrap()
        );
    }
}

#[test]
fn roundtrip_encoding_reject_response() {
    let reject = reject_response();

    for certification_version in all_supported_versions() {
        assert_eq!(
            reject,
            decode_message(&encode_message(&reject, certification_version)).unwrap()
        );
    }
}
