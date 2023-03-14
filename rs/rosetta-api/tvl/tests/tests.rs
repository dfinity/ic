fn tvl_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("TVL_WASM").unwrap()).unwrap()
}

fn xrc_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(std::env::var("XRC_WASM_PATH").unwrap(), "xrc", &[])
}

#[test]
fn test_tvl() {
    ic_tvl_sm_tests::test_tvl(tvl_wasm(), xrc_wasm())
}
