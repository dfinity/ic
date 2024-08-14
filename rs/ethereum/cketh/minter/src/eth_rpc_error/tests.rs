use crate::eth_rpc_error::{sanitize_send_raw_transaction_result, Parser};

#[test]
fn should_sanitize_ok_response() {
    let mut raw_response =
        br#"{"id":1,"jsonrpc":"2.0","result":"0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353"}"#.to_vec();
    check_sanitize_send_raw_transaction_result(&mut raw_response, sanitized_ok_response());
}

#[test]
fn should_ignore_already_known_error() {
    let mut raw_response =
        br#"{"jsonrpc": "2.0", "error": {"code": -32000, "message": "ALREADY_EXISTS: already known"}, "id": 1}"#.to_vec();
    check_sanitize_send_raw_transaction_result(&mut raw_response, sanitized_ok_response());
}

#[test]
fn should_sanitize_insufficient_funds_error() {
    let mut raw_response =
        br#"{"jsonrpc": "2.0", "error": {"code": -32000, "message": "out of gas"}, "id": 1}"#
            .to_vec();
    let sanitized_error = br#"{"id":1,"jsonrpc":"2.0","result":"InsufficientFunds"}"#.to_vec();
    check_sanitize_send_raw_transaction_result(&mut raw_response, sanitized_error);
}

#[test]
fn should_keep_unknown_error_and_normalize_response() {
    let mut raw_response =
        br#"{"jsonrpc": "2.0", "error": {"code": -32000, "message": "weird unknown error"}, "id": 1}"#
            .to_vec();
    let mut other_raw_response = br#"{"error": {"code": -32000, "message": "weird unknown error"}, "jsonrpc": "2.0", "id": 1}"#
        .to_vec();
    let expected_response =
        br#"{"id":1,"jsonrpc":"2.0","error":{"code":-32000,"message":"weird unknown error"}}"#
            .to_vec();

    check_sanitize_send_raw_transaction_result(&mut raw_response, &expected_response);
    check_sanitize_send_raw_transaction_result(&mut other_raw_response, &expected_response);
}

#[test]
fn should_not_modify_response_when_deserialization_fails() {
    let mut raw_response = br#"{"jsonrpc": "2.0", "unexpected": "value", "id": 1}"#.to_vec();
    let unmodified_response = raw_response.clone();
    check_sanitize_send_raw_transaction_result(&mut raw_response, unmodified_response);
}

fn check_sanitize_send_raw_transaction_result<T: AsRef<[u8]>>(
    raw_response: &mut Vec<u8>,
    expected: T,
) {
    sanitize_send_raw_transaction_result(raw_response, Parser::new());
    let expected_bytes = expected.as_ref();
    assert_eq!(
        raw_response,
        expected_bytes,
        "{:?} != {:?}",
        String::from_utf8_lossy(raw_response),
        String::from_utf8_lossy(expected_bytes)
    );
}

fn sanitized_ok_response() -> Vec<u8> {
    br#"{"id":1,"jsonrpc":"2.0","result":"Ok"}"#.to_vec()
}
