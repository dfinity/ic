use super::*;
use ic_crypto_internal_csp::api::CspSigner;
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
        let key_id = public_key_hash_as_key_id(&csp_pk);
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
