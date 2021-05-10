use super::*;
use ic_crypto_internal_csp::api::CspSigner;

#[cfg(test)]
mod tests;

pub struct MultiSigVerifierInternal {}

impl MultiSigVerifierInternal {
    pub fn verify_multi_sig_individual<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        signature: &IndividualMultiSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto = key_from_registry(registry, signer, CommitteeSigning, registry_version)?;
        let message_bytes = message.as_signed_bytes();
        let csp_sig = CspSignature::try_from(signature)?;
        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_pubkey = CspPublicKey::try_from(pk_proto)?;

        csp_signer.verify(&csp_sig, &message_bytes, algorithm_id, csp_pubkey)
    }

    /// Combines a non-empty collection of individual signatures into a combined
    /// signature. Panics if called with zero signatures.
    pub fn combine_multi_sig_individuals<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        signatures: BTreeMap<NodeId, IndividualMultiSigOf<H>>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<CombinedMultiSigOf<H>> {
        if signatures.is_empty() {
            panic!("At least one signature required");
        }

        let (pubkey_sig_pairs, algorithm) = node_sigs_to_pubkey_sig_pairs(
            registry,
            signatures,
            CommitteeSigning,
            registry_version,
        )?;

        let combined_sig = csp_signer.combine_sigs(pubkey_sig_pairs, algorithm)?;

        Ok(CombinedMultiSigOf::new(CombinedMultiSig(
            combined_sig.as_ref().to_vec(),
        )))
    }

    /// Verifies a combined signature from a non-empty set of signers.
    /// Panics if called with zero signers.
    pub fn verify_multi_sig_combined<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        signature: &CombinedMultiSigOf<H>,
        message: &H,
        signers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        if signers.is_empty() {
            panic!("At least one signer required");
        }

        let message_bytes = message.as_signed_bytes();
        let csp_sig = CspSignature::try_from(signature)?;
        let (csp_pubkeys, algorithm) =
            node_ids_to_pubkeys(registry, signers, CommitteeSigning, registry_version)?;

        csp_signer.verify_multisig(csp_pubkeys, csp_sig, &message_bytes, algorithm)
    }
}

/// This helper method performs the following two tasks:
/// 1. maps node IDs to CSP public keys by querying the registry
/// 2. ensures that the public keys' algorithm IDs are all equal
///
/// Returns the public keys as well as the unique algorithm ID.
///
/// Returns an error if
/// - a node's public key is not found in the registry
/// - one of the public keys fetched from the registry is invalid
/// - the public key's algorithms are not all equal
fn node_ids_to_pubkeys(
    registry: Arc<dyn RegistryClient>,
    nodes: BTreeSet<NodeId>,
    key_purpose: KeyPurpose,
    registry_version: RegistryVersion,
) -> CryptoResult<(Vec<CspPublicKey>, AlgorithmId)> {
    let mut algorithm_set = BTreeSet::<AlgorithmId>::new();
    let csp_pubkeys = {
        let csp_pubkeys: CryptoResult<Vec<CspPublicKey>> = nodes
            .iter()
            .map(|node_id| {
                let pk_proto = key_from_registry(
                    Arc::clone(&registry),
                    node_id.to_owned(),
                    key_purpose,
                    registry_version,
                )?;
                let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
                algorithm_set.insert(algorithm_id);
                CspPublicKey::try_from(pk_proto)
            })
            .collect();
        // Using ? directly on collect() does not have the intended effect, so it is
        // applied to the result below. Alternatively, the ? could be applied further
        // below, but then algorithm inconsistency errors would take priority over
        // missing/invalid keys from the registry.
        csp_pubkeys?
    };

    let algorithm = {
        if algorithm_set.len() != 1 {
            return Err(CryptoError::InconsistentAlgorithms {
                algorithms: algorithm_set,
                key_purpose,
                registry_version,
            });
        }
        *algorithm_set
            .iter()
            .next()
            .expect("Set was unexpectedly empty")
    };

    Ok((csp_pubkeys, algorithm))
}

/// This helper method performs the following two tasks:
/// 1. maps node-specific multisigs to corresponding CSP (pubkey, sig) pairs
///    by querying the registry
/// 2. ensures that the public key's algorithm IDs are all equal
///
/// Returns the pairs together with the unique algorithm ID.
///
/// Returns an error if
/// - a node's public key is not found in the registry
/// - one of the public keys fetched from the registry is invalid
/// - the public key's algorithms are not all equal
/// - one of the given signatures is not valid
fn node_sigs_to_pubkey_sig_pairs<H>(
    registry: Arc<dyn RegistryClient>,
    node_sigs: BTreeMap<NodeId, IndividualMultiSigOf<H>>,
    key_purpose: KeyPurpose,
    registry_version: RegistryVersion,
) -> CryptoResult<(Vec<(CspPublicKey, CspSignature)>, AlgorithmId)>
where
    H: Signable,
{
    let mut algorithm_set = BTreeSet::<AlgorithmId>::new();
    let pubkey_sig_pairs = {
        let pubkey_sig_pairs: CryptoResult<Vec<(CspPublicKey, CspSignature)>> = node_sigs
            .iter()
            .map(|(node_id, individual_sig)| {
                let pk_proto = key_from_registry(
                    Arc::clone(&registry),
                    node_id.to_owned(),
                    key_purpose,
                    registry_version,
                )?;
                let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
                algorithm_set.insert(algorithm_id);

                let csp_pk = CspPublicKey::try_from(pk_proto)?;
                let csp_sig = CspSignature::try_from(individual_sig)?;

                Ok((csp_pk, csp_sig))
            })
            .collect();
        // Using ? directly on collect() does not have the intended effect, so it is
        // applied to the result below. Alternatively, the ? could be applied further
        // below, but then algorithm inconsistency errors would take priority over
        // missing/invalid keys from the registry.
        pubkey_sig_pairs?
    };

    let algorithm = {
        if algorithm_set.len() != 1 {
            return Err(CryptoError::InconsistentAlgorithms {
                algorithms: algorithm_set,
                key_purpose,
                registry_version,
            });
        }
        *algorithm_set
            .iter()
            .next()
            .expect("Set was unexpectedly empty")
    };

    Ok((pubkey_sig_pairs, algorithm))
}

pub struct MultiSignerInternal {}

impl MultiSignerInternal {
    pub fn sign_multi<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: Arc<dyn RegistryClient>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<IndividualMultiSigOf<H>> {
        let pk_proto = key_from_registry(
            registry,
            signer,
            KeyPurpose::CommitteeSigning,
            registry_version,
        )?;
        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_pk = CspPublicKey::try_from(pk_proto)?;
        let message_bytes = message.as_signed_bytes();
        let key_id = public_key_hash_as_key_id(&csp_pk);
        let csp_sig = csp_signer.sign(algorithm_id, &message_bytes, key_id)?;

        Ok(IndividualMultiSigOf::new(IndividualMultiSig(
            csp_sig.as_ref().to_vec(),
        )))
    }
}
