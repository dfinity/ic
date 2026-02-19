use crate::rpc_client::eth_rpc_error::{sanitize_send_raw_transaction_result, Parser};
use serde_json::json;

#[test]
fn should_sanitize_ok_response() {
    let raw_response = json!({"id":1,"jsonrpc":"2.0","result":"0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353"});
    check_sanitize_send_raw_transaction_result(raw_response, sanitized_ok_response());
}

#[test]
fn should_ignore_already_known_error() {
    let raw_response = json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": "ALREADY_EXISTS: already known"}, "id": 1});
    check_sanitize_send_raw_transaction_result(raw_response, sanitized_ok_response());
}

#[test]
fn should_sanitize_insufficient_funds_error() {
    let raw_response =
        json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": "out of gas"}, "id": 1});
    let sanitized_error = json!({"id":1,"jsonrpc":"2.0","result":"InsufficientFunds"});
    check_sanitize_send_raw_transaction_result(raw_response, sanitized_error);
}

#[test]
fn should_keep_unknown_error_and_normalize_response() {
    let raw_response = json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": "weird unknown error"}, "id": 1});
    let other_raw_response = json!({"error": {"code": -32000, "message": "weird unknown error"}, "jsonrpc": "2.0", "id": 1});
    let expected_response =
        json!({"id":1,"jsonrpc":"2.0","error":{"code":-32000,"message":"weird unknown error"}});

    check_sanitize_send_raw_transaction_result(raw_response, expected_response.clone());
    check_sanitize_send_raw_transaction_result(other_raw_response, expected_response);
}

#[test]
fn should_not_modify_response_when_deserialization_fails() {
    let raw_response = json!({"jsonrpc": "2.0", "result": "invalid", "id": 1});
    let unmodified_response = raw_response.clone();
    check_sanitize_send_raw_transaction_result(raw_response, unmodified_response);
}

fn check_sanitize_send_raw_transaction_result(
    raw_response: serde_json::Value,
    expected: serde_json::Value,
) {
    let unsanitized_response = serde_json::from_value(raw_response).unwrap();
    let sanitized_response =
        sanitize_send_raw_transaction_result(unsanitized_response, Parser::new());
    let expected_response = serde_json::from_value(expected).unwrap();
    assert_eq!(sanitized_response, expected_response);
}

fn sanitized_ok_response() -> serde_json::Value {
    json!({"id":1,"jsonrpc":"2.0","result":"Ok"})
}
