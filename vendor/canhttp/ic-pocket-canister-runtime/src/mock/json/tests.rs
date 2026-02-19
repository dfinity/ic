use crate::mock::{json::JsonRpcRequestMatcher, CanisterHttpRequestMatcher};
use candid::Principal;
use canhttp::http::json::{ConstantSizeId, Id};
use pocket_ic::common::rest::{CanisterHttpHeader, CanisterHttpMethod, CanisterHttpRequest};
use serde_json::{json, Value};
use std::string::ToString;

const SUBNET_ID: Principal = Principal::from_slice(&[0, 0, 0, 0, 2, 48, 0, 204, 1, 1]);
const DEFAULT_HOST: &str = "cloudflare-eth.com";
const DEFAULT_URL: &str = "https://cloudflare-eth.com";
const DEFAULT_RPC_METHOD: &str = "eth_gasPrice";
const DEFAULT_RPC_ID: u64 = 1234;
const DEFAULT_RPC_PARAMS: Value = Value::Array(vec![]);
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 1024;
const CONTENT_TYPE_HEADER_LOWERCASE: &str = "content-type";
const CONTENT_TYPE_VALUE: &str = "application/json";

mod json_rpc_request_matcher_tests {
    use super::*;

    #[test]
    fn should_match_request() {
        assert!(request_matcher().matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_method() {
        assert!(!JsonRpcRequestMatcher::with_method("eth_getLogs")
            .with_id(DEFAULT_RPC_ID)
            .with_params(DEFAULT_RPC_PARAMS)
            .matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_id() {
        assert!(!request_matcher().with_raw_id(Id::Null).matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_params() {
        assert!(!request_matcher()
            .with_params(Value::Null)
            .matches(&request()));
    }

    #[test]
    fn should_match_url() {
        assert!(request_matcher().with_url(DEFAULT_URL).matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_url() {
        assert!(!request_matcher()
            .with_url("https://rpc.ankr.com")
            .matches(&request()));
    }

    #[test]
    fn should_match_host() {
        assert!(request_matcher()
            .with_host(DEFAULT_HOST)
            .matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_host() {
        assert!(!request_matcher()
            .with_host("rpc.ankr.com")
            .matches(&request()));
    }

    #[test]
    fn should_match_request_headers() {
        assert!(request_matcher()
            .with_request_headers(vec![(CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE),])
            .matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_request_headers() {
        assert!(!request_matcher()
            .with_request_headers(vec![(CONTENT_TYPE_HEADER_LOWERCASE, "text/html"),])
            .matches(&request()));
    }

    #[test]
    fn should_match_max_response_bytes() {
        assert!(request_matcher()
            .with_max_response_bytes(DEFAULT_MAX_RESPONSE_BYTES)
            .matches(&request()));
    }

    #[test]
    fn should_not_match_wrong_max_response_bytes() {
        assert!(!request_matcher()
            .with_max_response_bytes(0_u64)
            .matches(&request()));
    }

    #[test]
    fn should_match_all() {
        assert!(JsonRpcRequestMatcher::with_method(DEFAULT_RPC_METHOD)
            .with_id(DEFAULT_RPC_ID)
            .with_params(DEFAULT_RPC_PARAMS)
            .with_url(DEFAULT_URL)
            .with_host(DEFAULT_HOST)
            .with_max_response_bytes(DEFAULT_MAX_RESPONSE_BYTES)
            .with_request_headers(vec![(CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE),])
            .matches(&request()));
    }
}

fn request_matcher() -> JsonRpcRequestMatcher {
    JsonRpcRequestMatcher::with_method(DEFAULT_RPC_METHOD)
        .with_id(DEFAULT_RPC_ID)
        .with_params(DEFAULT_RPC_PARAMS)
}

fn request() -> CanisterHttpRequest {
    CanisterHttpRequest {
        subnet_id: SUBNET_ID,
        request_id: 0,
        http_method: CanisterHttpMethod::POST,
        url: DEFAULT_URL.to_string(),
        headers: vec![CanisterHttpHeader {
            name: CONTENT_TYPE_HEADER_LOWERCASE.to_string(),
            value: CONTENT_TYPE_VALUE.to_string(),
        }],
        body: serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": DEFAULT_RPC_METHOD,
            "id": ConstantSizeId::from(DEFAULT_RPC_ID).to_string(),
            "params": DEFAULT_RPC_PARAMS,
        }))
        .unwrap(),
        max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
    }
}
