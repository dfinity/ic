use crate::wasm::WasmParser;
use canscan::CanisterEndpoint;
use maplit::btreeset;
use std::path::PathBuf;

#[test]
fn should_parse_wasm_file() {
    let endpoints = WasmParser::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/wasm32-unknown-unknown/canister-release/test_canister.wasm"),
    )
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
    let endpoints = WasmParser::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/wasm32-unknown-unknown/canister-release/test_canister.wasm.gz"),
    )
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
