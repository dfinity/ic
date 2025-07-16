use crate::candid::CandidParser;
use canscan::CanisterEndpoint;
use maplit::btreeset;
use std::path::PathBuf;

#[test]
fn should_parse_candid_file() {
    let endpoints = CandidParser::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_canister/test_canister.did"),
    )
    .parse()
    .expect("Failed to parse Candid");

    assert_eq!(
        endpoints,
        btreeset! {
            CanisterEndpoint::Query("getBalance".to_string()),
            CanisterEndpoint::Update("send".to_string()),
        }
        .into()
    );
}

#[test]
fn should_fail_to_parse_candid_file() {
    let result = CandidParser::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/candid/invalid.did"),
    )
    .parse();

    assert!(result.is_err_and(|e| e
        .to_string()
        .contains("Top-level actor definition not found")));
}
