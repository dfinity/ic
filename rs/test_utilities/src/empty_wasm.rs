//! The EMPTY_WASM is a legal wasm module that can be installed as a canister on
//! the IC, but that does not do anything.

use hex_literal::hex;

/// A short wasm module that is a legal canister binary.
pub const EMPTY_WASM: &[u8] = &[0, 97, 115, 109, 1, 0, 0, 0];
pub const EMPTY_WASM_SHA256: [u8; 32] =
    hex!("93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476");

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wasm_is_legal() {
        wabt::wasm2wat(EMPTY_WASM).unwrap();
    }

    #[test]
    fn check_hardcoded_sha256_is_up_to_date() {
        assert_eq!(
            EMPTY_WASM_SHA256,
            ic_crypto_sha256::Sha256::hash(EMPTY_WASM)
        );
    }
}
