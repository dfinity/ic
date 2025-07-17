use crate::{candid::CandidParser, test_utils::get_runfile_path, types::CanisterEndpoint};
use maplit::btreeset;

#[test]
fn should_parse_candid_file() {
    let endpoints = CandidParser::new(get_runfile_path("test_resources/candid/valid.did"))
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
    let result = CandidParser::new(get_runfile_path("test_resources/candid/invalid.did")).parse();

    assert!(result.is_err_and(|e| e
        .to_string()
        .contains("Top-level actor definition not found")));
}
