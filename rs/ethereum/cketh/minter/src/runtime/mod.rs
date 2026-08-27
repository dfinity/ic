use crate::management::CallError;
use crate::time::TimeProvider;
use async_trait::async_trait;

/// The canister capabilities the minter needs from its environment.
///
/// Abstracting them away lets the logic that drives them be exercised without a canister.
#[async_trait]
pub trait CanisterRuntime: TimeProvider {
    /// Signs a message hash with the tECDSA key `key_name` derived along `derivation_path`.
    async fn sign_with_ecdsa(
        &self,
        key_name: String,
        derivation_path: Vec<Vec<u8>>,
        message_hash: [u8; 32],
    ) -> Result<[u8; 64], CallError>;
}
