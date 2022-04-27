//! Exposes the lifeline canister wasm as a constant.
//! This crate is NOT part of the lifeline canister itself: it only exposes it
//! into rust.

pub const LIFELINE_CANISTER_WASM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/lifeline.wasm"));

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn check_that_lifeline_wasm_is_legal() {
        wabt::wasm2wat(LIFELINE_CANISTER_WASM).unwrap();
    }
}
