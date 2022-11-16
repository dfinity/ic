use crate::registry::crypto::v1::PublicKey;

#[allow(clippy::all)]
#[path = "../../gen/registry/registry.crypto.v1.rs"]
pub mod v1;

impl PublicKey {
    pub fn equal_ignoring_timestamp(&self, other: &Self) -> bool {
        self.version == other.version
            && self.algorithm == other.algorithm
            && self.key_value == other.key_value
            && self.proof_data == other.proof_data
    }
}
