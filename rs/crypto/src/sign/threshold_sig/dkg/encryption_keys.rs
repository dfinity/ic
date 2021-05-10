//! Implements the encryption key methods of `DkgAlgorithm`.

use super::*;

use ic_crypto_internal_csp::api::DistributedKeyGenerationCspClient;
use ic_crypto_internal_csp::types::CspPop;
use ic_types::crypto::dkg::EncryptionPublicKey;
use ic_types::crypto::dkg::EncryptionPublicKeyPop;
use ic_types::crypto::dkg::EncryptionPublicKeyWithPop;

pub use generate::generate_encryption_keys;
pub use verify::verify_encryption_public_key;

#[cfg(test)]
mod tests;

mod generate {
    use super::*;

    pub fn generate_encryption_keys<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        dkg_config: &DkgConfig,
        node_id: NodeId,
    ) -> CryptoResult<EncryptionPublicKeyWithPop> {
        // TODO (CRP-313): Handle the errors returned by the CSP
        let (csp_enc_pk, csp_pop) =
            dkg_csp_client.dkg_create_ephemeral(dkg_config.dkg_id(), &node_id.get().into_vec())?;
        // TODO (CRP-313): The conversion may change to simply wrapping the CSP type
        Ok(EncryptionPublicKeyWithPop {
            key: EncryptionPublicKey::from(&csp_enc_pk),
            proof_of_possession: EncryptionPublicKeyPop::from(&csp_pop),
        })
    }
}

mod verify {
    use super::*;
    use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
    use ic_types::crypto::dkg::{Dealers, Receivers};

    pub fn verify_encryption_public_key<C: DistributedKeyGenerationCspClient>(
        dkg_csp_client: &C,
        dkg_config: &DkgConfig,
        sender: NodeId,
        key: &EncryptionPublicKeyWithPop,
    ) -> CryptoResult<()> {
        ensure_sender_in_receivers_or_dealers(
            sender,
            dkg_config.receivers(),
            dkg_config.dealers(),
        )?;
        Ok(dkg_csp_client.dkg_verify_ephemeral(
            dkg_config.dkg_id(),
            &sender.get().into_vec(),
            (
                CspEncryptionPublicKey::from(&key.key),
                CspPop::from(&key.proof_of_possession),
            ),
        )?)
    }

    fn ensure_sender_in_receivers_or_dealers(
        sender: NodeId,
        receivers: &Receivers,
        dealers: &Dealers,
    ) -> CryptoResult<()> {
        if !receivers.get().contains(&sender) && !dealers.get().contains(&sender) {
            return Err(CryptoError::InvalidArgument {
                message: format!(
                    "The sender node ID \"{:?}\" must be contained in the DKG config's receivers or \
                    dealers (or both).",
                    sender
                ),
            });
        }
        Ok(())
    }
}
