use crate::pb::v1::ArchivedMonthlyNodeProviderRewards;
use ic_crypto_sha2::Sha256;
use ic_stable_structures::{storable::Bound, Storable};
use prost::Message;
use std::borrow::Cow;

#[allow(clippy::all)]
#[path = "../gen/ic_nns_governance.pb.v1.rs"]
pub mod v1;

mod conversions;
mod convert_struct_to_enum;

impl Storable for ArchivedMonthlyNodeProviderRewards {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoidable in the case of Err.)
            .expect("Unable to deserialize ArchivedMonthlyNodeProviderRewards.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

/// Calculates the SHA256 hash of the given bytes.
fn calculate_hash(bytes: &[u8]) -> [u8; 32] {
    let mut wasm_sha = Sha256::new();
    wasm_sha.write(bytes);
    wasm_sha.finish()
}

#[cfg(test)]
mod tests;
