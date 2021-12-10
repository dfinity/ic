use crate::api::CspTlsHandshakeSignerProvider;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSignature;
use crate::vault::api::{CspTlsKeygenError, CspTlsSignError, CspVault};
use crate::{Csp, TlsHandshakeCspVault};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::KeyId;
use ic_types::NodeId;
use rand::{CryptoRng, Rng};
use std::sync::Arc;

/// Note that `R: 'static`, `S: 'static`, and `C: 'static` here does not mean
/// that `R`, `S`, and `C` must _have_ a 'static lifetime, but rather that `R`,
/// `S` and `C` are _bounded by_ a 'static lifetime. Also note that `&'static T`
/// and `T: 'static` are _not_ the same thing, and that `T: 'static` means that
/// `T` can be a borrowed type with a 'static lifetime or an _owned_ type.
///
/// Said differently, the 'static trait bound on a generic type `T` requires
/// that any references inside the type must live at least as long as 'static.
/// For our purposes where `R`, `S`, and `C` are (at least currently) always
/// owned types (i.e. don't have references) in the form of
/// `OsRng`/`ChaCha20Rng` for `R` and `ProtoSecretKeyStore`/
/// `VolatileSecretKeyStore` for `S` and `C`, the 'static lifetime bounds on
/// `R`, `S` and `C` have no impact at all.
///
/// See also [Common Rust Lifetime Misconceptions].
///
/// [Common Rust Lifetime Misconceptions]: https://github.com/pretzelhammer/rust-blog/blob/master/posts/common-rust-lifetime-misconceptions.md#2-if-t-static-then-t-must-be-valid-for-the-entire-program
impl<
        R: Rng + CryptoRng + Send + Sync + 'static,
        S: SecretKeyStore + 'static,
        C: SecretKeyStore + 'static,
    > CspTlsHandshakeSignerProvider for Csp<R, S, C>
{
    fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault> {
        Arc::new(CspTlsHandshakeSignerImpl {
            csp_vault: Arc::clone(&self.csp_vault),
        })
    }
}

struct CspTlsHandshakeSignerImpl {
    csp_vault: Arc<dyn CspVault>,
}

impl TlsHandshakeCspVault for CspTlsHandshakeSignerImpl {
    fn gen_tls_key_pair(
        &self,
        _node: NodeId,
        _not_after: &str,
    ) -> Result<(KeyId, TlsPublicKeyCert), CspTlsKeygenError> {
        unimplemented!("CspTlsHandshakeSigner on purpose supports only tls_sign()-operation")
    }

    fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError> {
        self.csp_vault.tls_sign(message, key_id)
    }
}
