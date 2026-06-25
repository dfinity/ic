use super::*;
use crate::CryptoComponentRng;
use ic_crypto_internal_csp::CspRwLock;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::types::SigConverter;
use ic_crypto_internal_csp::vault::api::{BasicSignatureCspVault, CspBasicSignatureError};
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult};

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

    pub fn verify_basic_sig_batch<H: Signable, R: CryptoComponentRng>(
        csprng: &CspRwLock<R>,
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
        // Compute the signed bytes once, since all signatures share the same
        // message.
        let message_bytes = message.as_signed_bytes();
        Self::verify_basic_sig_batch_internal(
            csprng,
            registry,
            signatures.signatures_map.iter().map(|(signer, signature)| {
                (
                    *signer,
                    signature,
                    message_bytes.as_slice(),
                    registry_version,
                )
            }),
        )
    }

    /// Verifies a batch of basic signatures on potentially different messages.
    ///
    /// Unlike `verify_basic_sig_batch`, the entries in `inputs` may have
    /// distinct messages, and the same `NodeId` may appear more than once.
    pub fn verify_basic_sig_batch_multi_msg<H: Signable, R: CryptoComponentRng>(
        csprng: &CspRwLock<R>,
        registry: &dyn RegistryClient,
        inputs: &[(NodeId, &BasicSigOf<H>, &H, RegistryVersion)],
    ) -> CryptoResult<()> {
        if inputs.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message:
                    "Empty signature batch. At least one signature should be included in the batch."
                        .to_string(),
            });
        };
        // Serialize each message once and keep the owned buffers alive so we
        // can borrow them into the helper's input iterator.
        let entries: Vec<(NodeId, &BasicSigOf<H>, Vec<u8>, RegistryVersion)> = inputs
            .iter()
            .map(|(signer, signature, message, registry_version)| {
                (
                    *signer,
                    *signature,
                    message.as_signed_bytes(),
                    *registry_version,
                )
            })
            .collect();
        Self::verify_basic_sig_batch_internal(
            csprng,
            registry,
            entries
                .iter()
                .map(|(signer, signature, msg_bytes, registry_version)| {
                    (*signer, *signature, msg_bytes.as_slice(), *registry_version)
                }),
        )
    }

    /// Shared implementation of batched Ed25519 basic-sig verification.
    fn verify_basic_sig_batch_internal<'a, H: 'a, R: CryptoComponentRng>(
        csprng: &CspRwLock<R>,
        registry: &dyn RegistryClient,
        inputs: impl ExactSizeIterator<Item = (NodeId, &'a BasicSigOf<H>, &'a [u8], RegistryVersion)>,
    ) -> CryptoResult<()> {
        let mut msgs = Vec::with_capacity(inputs.len());
        let mut sigs = Vec::with_capacity(inputs.len());
        let mut keys = Vec::with_capacity(inputs.len());

        for (signer, signature, msg_bytes, registry_version) in inputs {
            let pk_proto =
                key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;

            let pubkey_alg = AlgorithmId::from(pk_proto.algorithm);
            if pubkey_alg != AlgorithmId::Ed25519 {
                return Err(CryptoError::AlgorithmNotSupported {
                    algorithm: pubkey_alg,
                    reason: "Only Ed25519 is supported in batched basic sig verification."
                        .to_string(),
                });
            }
            let pk = ic_ed25519::PublicKey::deserialize_raw(&pk_proto.key_value).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: Some(pk_proto.key_value),
                    internal_error: e.to_string(),
                }
            })?;

            msgs.push(msg_bytes);
            sigs.push(signature.get_ref().0.as_slice());
            keys.push(pk);
        }

        let seed: [u8; 32] = csprng.write().r#gen();

        ic_ed25519::PublicKey::batch_verify_with_seed(&msgs, &sigs, &keys, &seed).map_err(|e| {
            CryptoError::SignatureVerification {
                algorithm: AlgorithmId::Ed25519,
                public_key_bytes: vec![],
                sig_bytes: vec![],
                internal_error: e.to_string(),
            }
        })
    }
}

pub fn sign<H: Signable>(
    message: &H,
    vault: &dyn BasicSignatureCspVault,
    metrics: &CryptoMetrics,
) -> CryptoResult<BasicSigOf<H>> {
    let message_bytes = message.as_signed_bytes();
    let message_bytes_len = message_bytes.len();

    let result = vault
        .sign(message_bytes)
        .map_err(|e: CspBasicSignatureError| CryptoError::from(e));

    metrics.observe_parameter_size(
        MetricsDomain::BasicSignature,
        "sign_basic",
        "message",
        message_bytes_len,
        MetricsResult::from(&result),
    );
    Ok(BasicSigOf::new(BasicSig(result?.as_ref().to_vec())))
}
