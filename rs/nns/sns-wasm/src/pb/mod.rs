use crate::pb::v1::{
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, SnsCanisterType, SnsVersion, SnsWasm,
};
use ic_crypto_sha::Sha256;
use std::fmt::Write;

#[rustfmt::skip]
#[allow(clippy::all)]
#[path = "../../gen/ic_sns_wasm.pb.v1.rs"]
pub mod v1;

/// Converts a sha256 hash into a hex string representation
pub fn hash_to_hex_string(hash: &[u8; 32]) -> String {
    let mut result_hash = String::new();
    for b in hash {
        let _ = write!(result_hash, "{:02X}", b);
    }
    result_hash
}

impl SnsWasm {
    /// Calculate the sha256 hash for the wasm.
    pub fn sha256_hash(&self) -> [u8; 32] {
        Sha256::hash(&self.wasm)
    }

    /// Provide string representation of the sha256 hash for the wasm.
    pub fn sha256_string(&self) -> String {
        let bytes = self.sha256_hash();
        hash_to_hex_string(&bytes)
    }

    /// Return the SnsCanisterType if it's valid, else return an error
    pub fn checked_sns_canister_type(&self) -> Result<SnsCanisterType, String> {
        match SnsCanisterType::from_i32(self.canister_type) {
            None => Err(
                "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                    .to_string(),
            ),
            Some(canister_type) => {
                if canister_type == SnsCanisterType::Unspecified {
                    Err("SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string())
                } else {
                    Ok(canister_type)
                }
            }
        }
    }
}

impl From<SnsVersion> for GetNextSnsVersionRequest {
    fn from(version: SnsVersion) -> GetNextSnsVersionRequest {
        GetNextSnsVersionRequest {
            current_version: Some(version),
        }
    }
}

impl From<SnsVersion> for GetNextSnsVersionResponse {
    fn from(version: SnsVersion) -> GetNextSnsVersionResponse {
        GetNextSnsVersionResponse {
            next_version: Some(version),
        }
    }
}
