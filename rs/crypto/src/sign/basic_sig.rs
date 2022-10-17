use super::*;
use ic_crypto_internal_csp::api::{CspSigVerifier, CspSigner};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::SigConverter;

#[cfg(test)]
mod tests;

pub struct BasicSigVerifierInternal {}

impl BasicSigVerifierInternal {
    pub fn verify_basic_sig<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
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

    pub fn verify_basic_sig_batch_vartime<S: CspSigVerifier, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        signature: &BasicSignatureBatch<H>,
        message: &H,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        if signature.signatures_map.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "Empty BasicSignatureBatch. At least one signature should be included in the batch."
                    .to_string(),
            });
        };
        let mut pk_sig_pairs =
            Vec::<(CspPublicKey, CspSignature)>::with_capacity(signature.signatures_map.len());
        let mut first_algorithm_id: Option<AlgorithmId> = None;

        for (signer, signature) in signature.signatures_map.iter() {
            let pk_proto = key_from_registry(
                registry.to_owned(),
                *signer,
                KeyPurpose::NodeSigning,
                registry_version,
            )?;

            let this_algorithm_id = AlgorithmId::from(pk_proto.algorithm);
            match first_algorithm_id {
                Some(algorithm_id) => {
                    if algorithm_id != this_algorithm_id {
                        return Err(CryptoError::InvalidArgument {
                            message: format!(
                                "Inconsistent input AlgorithmIds in batched basic sig verification: {}, {}",
                                algorithm_id, this_algorithm_id
                            ),
                        });
                    }
                }
                None => first_algorithm_id = Some(this_algorithm_id),
            }

            let csp_pk = CspPublicKey::try_from(pk_proto)?;
            let csp_sig = SigConverter::for_target(this_algorithm_id).try_from_basic(signature)?;
            pk_sig_pairs.push((csp_pk, csp_sig));
        }
        // `first_algorithm_id.expect()` does not panic because it's guaranteed that there was at least one valid AlgorithmId by
        // 1) it's checked that `signature_map` is not empty, and
        // 2) it's checked that at least `pk_proto` is well-formed,
        // and thus `this_algorithm_id` is never `None` at this point in code.
        csp_signer.verify_batch_vartime(
            &pk_sig_pairs[..],
            &message.as_signed_bytes(),
            first_algorithm_id.expect("Something went wrong with the AlgorithmId assignment"),
        )?;
        Ok(())
    }
}

pub struct BasicSignerInternal {}

impl BasicSignerInternal {
    pub fn sign_basic<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<H>> {
        let pk_proto =
            key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;
        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_pk = CspPublicKey::try_from(pk_proto)?;
        let key_id = KeyId::from(&csp_pk);
        let csp_sig = csp_signer.sign(algorithm_id, &message.as_signed_bytes(), key_id)?;

        Ok(BasicSigOf::new(BasicSig(csp_sig.as_ref().to_vec())))
    }
}

pub struct BasicSignVerifierByPublicKeyInternal {}

impl BasicSignVerifierByPublicKeyInternal {
    pub fn verify_basic_sig_by_public_key<C: CspSigner, S: Signable>(
        csp_signer: &C,
        signature: &BasicSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        let pubkey_algorithm = public_key.algorithm_id;
        let csp_pk = CspPublicKey::try_from(public_key)?;
        let csp_sig = SigConverter::for_target(pubkey_algorithm).try_from_basic(signature)?;

        csp_signer.verify(
            &csp_sig,
            &signed_bytes.as_signed_bytes(),
            pubkey_algorithm,
            csp_pk,
        )
    }
}
