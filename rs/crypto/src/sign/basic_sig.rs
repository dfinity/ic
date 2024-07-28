use super::*;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::SigConverter;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;

#[cfg(test)]
mod tests;

pub struct BasicSigVerifierInternal {}

impl BasicSigVerifierInternal {
    pub fn verify_basic_sig<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: &dyn RegistryClient,
        signature: &BasicSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto =
            key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;

        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_sig = SigConverter::for_target(algorithm_id).try_from_basic(signature)?;
        let csp_pk = CspPublicKey::try_from(pk_proto)?;

        csp_signer.verify(&csp_sig, &message.as_signed_bytes(), algorithm_id, csp_pk)
    }

    pub fn combine_basic_sig<H: Signable>(
        signatures: BTreeMap<NodeId, &BasicSigOf<H>>,
    ) -> CryptoResult<BasicSignatureBatch<H>> {
        if signatures.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "No signatures to combine in a batch. At least one signature is needed to create a batch"
                    .to_string(),
            });
        };
        let mut signatures_map = BTreeMap::new();
        for (signer, signature) in signatures.into_iter() {
            signatures_map.insert(signer, signature.clone());
        }

        Ok(BasicSignatureBatch { signatures_map })
    }

    pub fn verify_basic_sig_batch<H: Signable>(
        vault: &dyn CspVault,
        registry: &dyn RegistryClient,
        signatures: &BasicSignatureBatch<H>,
        message: &H,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        if signatures.signatures_map.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "Empty BasicSignatureBatch. At least one signature should be included in the batch.".to_string(),
            });
        };

        let message = message.as_signed_bytes();
        let mut msgs = Vec::with_capacity(signatures.signatures_map.len());
        let mut sigs = Vec::with_capacity(signatures.signatures_map.len());
        let mut keys = Vec::with_capacity(signatures.signatures_map.len());

        for (signer, signature) in signatures.signatures_map.iter() {
            let pk_proto =
                key_from_registry(registry, *signer, KeyPurpose::NodeSigning, registry_version)?;

            let pubkey_alg = AlgorithmId::from(pk_proto.algorithm);
            if pubkey_alg != AlgorithmId::Ed25519 {
                return Err(CryptoError::AlgorithmNotSupported {
                    algorithm: pubkey_alg,
                    reason: "Only Ed25519 is supported in batched basic sig verification."
                        .to_string(),
                });
            }
            let pk = ic_crypto_ed25519::PublicKey::deserialize_raw(&pk_proto.key_value).map_err(
                |e| CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: Some(pk_proto.key_value),
                    internal_error: e.to_string(),
                },
            )?;

            msgs.push(&message[..]);
            sigs.push(&signature.get_ref().0[..]);
            keys.push(pk);
        }

        let seed = vault.new_public_seed().map_err(|e| match e {
            PublicRandomSeedGeneratorError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        })?;
        let rng = &mut seed.into_rng();

        ic_crypto_ed25519::PublicKey::batch_verify(&msgs, &sigs, &keys, rng).map_err(|e| {
            CryptoError::SignatureVerification {
                algorithm: AlgorithmId::Ed25519,
                public_key_bytes: vec![],
                sig_bytes: vec![],
                internal_error: e.to_string(),
            }
        })
    }
}

pub struct BasicSignerInternal {}

impl BasicSignerInternal {
    pub fn sign_basic<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: &dyn RegistryClient,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<H>> {
        let pk_proto =
            key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;
        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_pk = CspPublicKey::try_from(pk_proto)?;
        let key_id = KeyId::try_from(&csp_pk)?;
        let csp_sig = csp_signer.sign(algorithm_id, message.as_signed_bytes(), key_id)?;

        Ok(BasicSigOf::new(BasicSig(csp_sig.as_ref().to_vec())))
    }
}
