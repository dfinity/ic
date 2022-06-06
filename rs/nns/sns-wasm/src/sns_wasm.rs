use crate::pb::hash_to_hex_string;
use crate::pb::v1::add_wasm_response::{AddWasmError, AddWasmOk};
use crate::pb::v1::{
    add_wasm_response, AddWasm, AddWasmResponse, GetWasm, GetWasmResponse, SnsCanisterType, SnsWasm,
};
use std::collections::BTreeMap;
use std::convert::TryInto;

type SnsWasmMap = BTreeMap<[u8; 32], SnsWasm>;

/// The struct that implements the public API of the canister
#[derive(Default)]
pub struct SnsWasmCanister {
    wasm_storage: SnsWasmStorage,
}

impl SnsWasmCanister {
    pub fn new() -> Self {
        SnsWasmCanister::default()
    }

    /// Returns an Option(SnsWasm) in the GetWasmResponse (a struct with wasm bytecode and the install target)
    pub fn get_wasm(&self, get_wasm_payload: GetWasm) -> GetWasmResponse {
        let hash = vec_to_hash(get_wasm_payload.hash);
        GetWasmResponse {
            wasm: self.wasm_storage.get_wasm(&hash).cloned(),
        }
    }

    /// Adds a WASM to the canister's storage, validating that the expected hash matches that of the
    /// provided WASM bytecode.
    pub fn add_wasm(&mut self, add_wasm_payload: AddWasm) -> AddWasmResponse {
        let wasm = add_wasm_payload.wasm.expect("Wasm is required");
        let hash = vec_to_hash(add_wasm_payload.hash);

        let result = match self.wasm_storage.add_wasm(wasm, &hash) {
            Ok(_) => Some(add_wasm_response::Result::Ok(AddWasmOk {
                hash: hash.to_vec(),
            })),
            Err(msg) => Some(add_wasm_response::Result::Error(AddWasmError {
                error: msg,
            })),
        };
        AddWasmResponse { result }
    }
}

/// This struct is responsible for storing and retrieving the wasms held by the canister
#[derive(Default)]
pub struct SnsWasmStorage {
    wasm_map: SnsWasmMap,
}

/// Converts a vector to a sha256 hash, or panics if the vector is the wrong length
fn vec_to_hash(v: Vec<u8>) -> [u8; 32] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; 32]> = match boxed_slice.try_into() {
        Ok(hash) => hash,
        Err(o) => panic!("Expected a hash of length {} but it was {}", 32, o.len()),
    };
    *boxed_array
}

impl SnsWasmStorage {
    pub fn new() -> Self {
        SnsWasmStorage::default()
    }

    /// Adds a wasm to the storage
    /// Validates that the expected hash matches the sha256 hash of the WASM.
    fn add_wasm(&mut self, wasm: SnsWasm, expected_hash: &[u8; 32]) -> Result<(), String> {
        if wasm.canister_type == i32::from(SnsCanisterType::Unspecified) {
            return Err("SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string());
        }

        if !SnsCanisterType::is_valid(wasm.canister_type) {
            return Err(
                "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                    .to_string(),
            );
        }

        if expected_hash != &wasm.sha256_hash() {
            return Err(format!(
                "Invalid Sha256 given for submitted WASM bytes.  Provided hash was '{}'  but \
                calculated hash was '{}'",
                hash_to_hex_string(expected_hash),
                wasm.sha256_string()
            ));
        }

        self.wasm_map.insert(expected_hash.to_owned(), wasm);

        Ok(())
    }

    /// Retrieves a wasm by its hash.
    pub fn get_wasm(&self, hash: &[u8; 32]) -> Option<&SnsWasm> {
        self.wasm_map.get(hash)
    }
}

#[cfg(test)]
mod test {
    use crate::pb::hash_to_hex_string;
    use crate::pb::v1::add_wasm_response::{AddWasmError, AddWasmOk};
    use crate::pb::v1::{add_wasm_response, AddWasm, GetWasm, SnsCanisterType};
    use crate::sns_wasm::{SnsWasm, SnsWasmCanister, SnsWasmStorage};
    use ic_crypto_sha::Sha256;

    /// Provides a small wasm
    fn smallest_valid_wasm() -> SnsWasm {
        SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Governance),
        }
    }

    fn new_wasm_storage() -> SnsWasmStorage {
        SnsWasmStorage::new()
    }

    fn new_wasm_canister() -> SnsWasmCanister {
        SnsWasmCanister::new()
    }

    #[test]
    fn canister_can_store_wasm() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        canister.add_wasm(wasm.clone(), &expected_hash).unwrap();

        let stored_wasm = canister.get_wasm(&expected_hash);

        assert_eq!(stored_wasm.unwrap(), &wasm);
    }

    #[test]
    fn storage_fails_on_invalid_wasm_hash() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let invalid_hash = Sha256::hash("Something else".as_bytes());

        let result = canister.add_wasm(wasm.clone(), &invalid_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Sha256 given for submitted WASM bytes.  Provided hash was \
            'CC72843144841A6F8110B7EBE7A1768101E03C4C8C152865CB7207E8E4BF8745'  but calculated \
            hash was '93A44BBB96C751218E4C00D479E4C14358122A389ACCA16205B1E4D0DC5F9476'"
        );
        // Assert that it is not stored
        let retrieved_wasm = canister.get_wasm(&wasm.sha256_hash());
        assert!(retrieved_wasm.is_none());
    }

    #[test]
    fn retrieval_fails_on_invalid_wasm_hash() {
        let mut canister = new_wasm_storage();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);

        canister.add_wasm(wasm, &expected_hash).unwrap();

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let stored_wasm = canister.get_wasm(&bad_hash);

        assert!(stored_wasm.is_none());
    }

    #[test]
    fn test_api_get_wasm_returns_right_response() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        canister.add_wasm(AddWasm {
            wasm: Some(wasm.clone()),
            hash: expected_hash.to_vec(),
        });

        let bad_hash = Sha256::hash("something_else".as_bytes());
        let wasm_response = canister.get_wasm(GetWasm {
            hash: bad_hash.to_vec(),
        });

        // When given non-existent hash, return None
        assert!(wasm_response.wasm.is_none());

        let wasm_response = canister.get_wasm(GetWasm {
            hash: expected_hash.to_vec(),
        });
        // When given valid hash return correct SnsWasm
        assert_eq!(wasm_response.wasm.unwrap(), wasm);
    }

    #[test]
    fn test_api_add_wasm_fails_on_unspecified_canister_type() {
        let mut canister = new_wasm_canister();
        let unspecified_canister_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: i32::from(SnsCanisterType::Unspecified),
        };

        let response = canister.add_wasm(AddWasm {
            wasm: Some(unspecified_canister_wasm.clone()),
            hash: unspecified_canister_wasm.sha256_hash().to_vec(),
        });

        assert_eq!(
            response.result.unwrap(),
            add_wasm_response::Result::Error(add_wasm_response::AddWasmError {
                error: "SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string()
            })
        )
    }

    #[test]
    fn test_api_add_wasm_fails_on_unsupported_canister_type() {
        let mut canister = new_wasm_canister();
        let invalid_canister_type_wasm = SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: 1000,
        };

        let response = canister.add_wasm(AddWasm {
            wasm: Some(invalid_canister_type_wasm.clone()),
            hash: invalid_canister_type_wasm.sha256_hash().to_vec(),
        });

        assert_eq!(
            response.result.unwrap(),
            add_wasm_response::Result::Error(add_wasm_response::AddWasmError {
                error:
                    "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                        .to_string()
            })
        )
    }

    #[test]
    fn test_api_add_wasm_responses() {
        let mut canister = new_wasm_canister();

        let wasm = smallest_valid_wasm();
        let expected_hash = Sha256::hash(&wasm.wasm);
        let bad_hash = Sha256::hash("Something else".as_bytes());
        // First try with incorrect hash
        let failure = canister.add_wasm(AddWasm {
            wasm: Some(wasm.clone()),
            hash: bad_hash.to_vec(),
        });
        assert_eq!(
            failure.result.unwrap(),
            add_wasm_response::Result::Error(AddWasmError {
                error: format!(
                    "Invalid Sha256 given for submitted WASM bytes.  Provided hash was \
                '{}'  but calculated hash was \
                '{}'",
                    hash_to_hex_string(&bad_hash),
                    hash_to_hex_string(&expected_hash),
                )
            })
        );

        let valid_hash = wasm.sha256_hash();
        let success = canister.add_wasm(AddWasm {
            wasm: Some(wasm),
            hash: valid_hash.to_vec(),
        });

        assert_eq!(
            success.result.unwrap(),
            add_wasm_response::Result::Ok(AddWasmOk {
                hash: valid_hash.to_vec()
            })
        );
    }
}
