use crate::key_id::KeyId;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::{VetKdCspVault, VetKdEncryptedKeyShareCreationVaultError};
use crate::vault::local_csp_vault::LocalCspVault;
use ic_crypto_internal_bls12_381_vetkd::{
    DerivationContext, EncryptedKeyShare, G2Affine, PairingInvalidPoint, Scalar,
    TransportPublicKey, TransportPublicKeyDeserializationError,
};
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_types::crypto::vetkd::{VetKdDerivationContext, VetKdEncryptedKeyShareContent};
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore> VetKdCspVault
    for LocalCspVault<R, S, C, P>
{
    /// Generates an encrypted vetKD key share.
    fn create_encrypted_vetkd_key_share(
        &self,
        key_id: KeyId,
        master_public_key: Vec<u8>,
        transport_public_key: Vec<u8>,
        context: VetKdDerivationContext,
        input: Vec<u8>,
    ) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError> {
        let start_time = self.metrics.now();
        let result = self.create_encrypted_vetkd_key_share_internal(
            key_id,
            master_public_key,
            transport_public_key,
            context,
            input,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::VetKd,
            MetricsScope::Local,
            "create_encrypted_vetkd_key_share",
            MetricsResult::from(&result),
            start_time,
        );
        result
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    fn create_encrypted_vetkd_key_share_internal(
        &self,
        key_id: KeyId,
        master_public_key: Vec<u8>,
        transport_public_key: Vec<u8>,
        context: VetKdDerivationContext,
        input: Vec<u8>,
    ) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError> {
        let master_public_key = G2Affine::deserialize_cached(&master_public_key).map_err(
            |_: PairingInvalidPoint| {
                VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentMasterPublicKey
            },
        )?;

        let transport_public_key =
            TransportPublicKey::deserialize(&transport_public_key).map_err(|e| match e {
                TransportPublicKeyDeserializationError::InvalidPublicKey => {
                    VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentEncryptionPublicKey
                }
            })?;

        let secret_key_from_store = self.sks_read_lock().get(&key_id).ok_or(
            VetKdEncryptedKeyShareCreationVaultError::SecretKeyMissingOrWrongType(format!(
                "missing key with ID {key_id}"
            )),
        )?;
        let secret_bls_scalar =
            if let CspSecretKey::ThresBls12_381(secret_key_bytes) = &secret_key_from_store {
                // We use the unchecked deserialization here because it is slightly cheaper, but mainly because
                // it cannot fail, and the data is anyway trusted as it comes from the secret key store.
                Ok(Scalar::deserialize_unchecked(
                    secret_key_bytes.inner_secret().expose_secret(),
                ))
            } else {
                Err(
                    VetKdEncryptedKeyShareCreationVaultError::SecretKeyMissingOrWrongType(format!(
                        "wrong secret key type for key with ID {key_id}: expected ThresBls12_381"
                    )),
                )
            }?;

        // Create encrypted key share using our library
        let encrypted_key_share = EncryptedKeyShare::create(
            &mut *self.rng_write_lock(),
            &master_public_key,
            &secret_bls_scalar,
            &transport_public_key,
            &DerivationContext::new(context.caller.as_slice(), &context.context),
            &input,
        );

        Ok(VetKdEncryptedKeyShareContent(
            encrypted_key_share.serialize().to_vec(),
        ))
    }
}
