//! The crypto service provider API for querying secret keys.
use crate::server::api::SecretKeyStoreCspServer;
use crate::server::local_csp_server::LocalCspServer;
use crate::SecretKeyStore;
use ic_types::crypto::KeyId;

use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore> SecretKeyStoreCspServer
    for LocalCspServer<R, S, C>
{
    fn sks_contains(&self, id: &KeyId) -> bool {
        self.sks_read_lock().contains(id)
    }
}
