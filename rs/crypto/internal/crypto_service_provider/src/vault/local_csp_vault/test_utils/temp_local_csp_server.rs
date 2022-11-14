//! Utilities to test the local CSP vault.

use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::LocalCspVault;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use tempfile::TempDir;

/// This local CSP vault has key stores in a newly created temporary directory,
/// which will exist for as long as the object stays in scope. As soon as the
/// object (or rather, the contained tempdir field) goes out of scope, the
/// created temporary directory will automatically be deleted.
pub struct TempLocalCspVault<R: Rng + CryptoRng> {
    pub vault: LocalCspVault<R, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore>,
    pub _temp_dir: TempDir,
}

impl<R: Rng + CryptoRng> TempLocalCspVault<R> {
    pub fn new_with_rng(rng: R) -> Self {
        let (vault, tempdir) = LocalCspVault::new_in_temp_dir(rng);
        Self {
            vault,
            _temp_dir: tempdir,
        }
    }
}

impl TempLocalCspVault<OsRng> {
    pub fn new() -> Self {
        Self::new_with_rng(OsRng)
    }
}
