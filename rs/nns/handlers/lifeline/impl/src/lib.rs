//! Exposes the lifeline canister wasm as a constant.
//! This crate is NOT part of the lifeline canister itself: it only exposes it
//! into rust.

pub const LIFELINE_CANISTER_WASM: &[u8] = include_bytes!(env!("LIFELINE_CANISTER_WASM_PATH"));

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Read;

    #[test]
    fn check_that_lifeline_wasm_is_legal() {
        let mut decoder = flate2::read::GzDecoder::new(LIFELINE_CANISTER_WASM);
        let mut decoded_wasm = vec![];
        decoder.read_to_end(&mut decoded_wasm).unwrap();
        wasmprinter::print_bytes(decoded_wasm).unwrap();
    }
}
