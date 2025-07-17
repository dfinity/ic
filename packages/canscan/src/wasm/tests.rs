use crate::test_utils::get_runfile_path;
use crate::{types::CanisterEndpoint, wasm::WasmParser};
use maplit::btreeset;

#[test]
fn should_parse_wasm_file() {
    let endpoints = WasmParser::new(get_runfile_path("test_resources/wasm/canister.wasm"))
        .parse()
        .expect("Failed to parse WASM");

    assert_eq!(
        endpoints,
        btreeset! {
            CanisterEndpoint::Query("getBalance".to_string()),
            CanisterEndpoint::Update("send".to_string()),
            CanisterEndpoint::Update("setApiKey".to_string()),
        }
        .into()
    );
}

#[test]
fn should_parse_compressed_wasm_file() {
    let endpoints = WasmParser::new(get_runfile_path("test_resources/wasm/canister.wasm.gz"))
        .parse()
        .expect("Failed to parse WASM");

    assert_eq!(
        endpoints,
        btreeset! {
            CanisterEndpoint::Query("getBalance".to_string()),
            CanisterEndpoint::Update("send".to_string()),
            CanisterEndpoint::Update("setApiKey".to_string()),
        }
        .into()
    );
}
