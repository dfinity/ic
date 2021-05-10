use super::test_fixtures::*;
use crate::encoding::*;

#[test]
fn roundtrip_encoding_stream_header() {
    let header = stream_header();

    assert_eq!(
        header,
        decode_stream_header(&encode_stream_header(&header)).unwrap()
    );
}

#[test]
fn roundtrip_encoding_request() {
    let request = request();

    assert_eq!(request, decode_message(&encode_message(&request)).unwrap());
}

#[test]
fn roundtrip_encoding_response() {
    let response = response();

    assert_eq!(
        response,
        decode_message(&encode_message(&response)).unwrap()
    );
}

#[test]
fn roundtrip_encoding_reject_response() {
    let reject = reject_response();

    assert_eq!(reject, decode_message(&encode_message(&reject)).unwrap());
}
