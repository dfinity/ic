//! Exposes the store canister Wasm as a constant.
//! This crate is NOT part of the store canister itself: it only exposes it
//! into rust.
use ic_base_types::PrincipalId;

pub const STORE_CANISTER_WASM: &[u8] = include_bytes!(env!("STORE_CANISTER_WASM_PATH"));

pub struct StoreCanisterInitArgs {
    pub authorized_principal: PrincipalId,
}

impl StoreCanisterInitArgs {
    pub fn render(&self) -> String {
        format!("(principal \"{}\")", self.authorized_principal)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use candid_utils::wasm::{InMemoryWasm, Wasm};
    use std::io::Read;

    #[test]
    fn check_that_store_wasm_is_legal() {
        let mut decoder = flate2::read::GzDecoder::new(STORE_CANISTER_WASM);
        let mut decoded_wasm = vec![];
        decoder.read_to_end(&mut decoded_wasm).unwrap();
        wasmprinter::print_bytes(decoded_wasm).unwrap();
    }

    #[test]
    fn check_that_store_wasm_has_candid_metadata() {
        let store_canister = InMemoryWasm::try_from(STORE_CANISTER_WASM).unwrap();

        let metadata = store_canister.list_metadata_sections().unwrap();
        assert_ne!(metadata, Vec::<String>::new());

        store_canister.encode_candid_args(&None).unwrap_err();

        {
            let store_arg = format!(
                "({{ authorized_principal = {} : nat64 }})",
                PrincipalId::new_user_test_id(42)
            );
            store_canister
                .encode_candid_args(&Some(store_arg))
                .unwrap_err();
        }

        {
            let store_arg = StoreCanisterInitArgs {
                authorized_principal: PrincipalId::new_user_test_id(42),
            };
            store_canister
                .encode_candid_args(&Some(store_arg.render()))
                .unwrap();
        }
    }
}
