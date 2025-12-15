use super::*;
use std::io::Read;

#[test]
fn check_that_lifeline_wasm_is_legal() {
    let mut decoder = flate2::read::GzDecoder::new(LIFELINE_CANISTER_WASM);
    let mut decoded_wasm = vec![];
    decoder.read_to_end(&mut decoded_wasm).unwrap();
    wasmprinter::print_bytes(decoded_wasm).unwrap();
}
