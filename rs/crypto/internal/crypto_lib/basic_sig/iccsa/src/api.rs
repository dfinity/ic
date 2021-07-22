//! ICCSA (Internet Computer Canister Signature Algorithm) API
use crate::types::{PublicKey, PublicKeyBytes, Signature, SignatureBytes};
use ic_certified_vars::CertificateValidationError;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_sha256::Sha256;
use ic_crypto_tree_hash::{Digest, LabeledTree};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{
    crypto::{AlgorithmId, CryptoError, CryptoResult},
    CanisterId,
};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// The object identifier for ICCSA public keys
pub fn algorithm_identifier() -> der_utils::PkixAlgorithmIdentifier {
    der_utils::PkixAlgorithmIdentifier::new_with_empty_param(simple_asn1::oid!(
        1, 3, 6, 1, 4, 1, 56387, 1, 2
    ))
}

/// Parse `pk_der` as DER-encoded public key with OID 1.3.6.1.4.1.56387.1.2, and
/// returns the unwrapped public key bytes. See
/// * https://sdk.dfinity.org/docs/interface-spec/index.html#canister-signatures
/// * https://tools.ietf.org/html/rfc8410#section-4
pub fn public_key_bytes_from_der(pk_der: &[u8]) -> CryptoResult<PublicKeyBytes> {
    let pk = der_utils::parse_public_key(
        pk_der,
        AlgorithmId::IcCanisterSignature,
        algorithm_identifier(),
        None,
    )?;
    Ok(PublicKeyBytes(pk))
}

/// Verify a canister signature
///
/// # Arguments
/// * `msg` the message to verify
/// * `sig` the signature
/// * `pk` the canister public key
/// * `root_pubkey` the root subnet public key
///
/// # Errors
/// * `MalformedPublicKey` if the public key cannot be parsed or has an
///   unexpected OID
/// * `MalformedSignature` if the signature could not be parsed
/// * `SignatureVerification` if the signature could not be verified
pub fn verify(
    msg: &[u8],
    sig: SignatureBytes,
    pk: PublicKeyBytes,
    root_pubkey: &ThresholdSigPublicKey,
) -> CryptoResult<()> {
    let (canister_id, seed) = parse_pubkey_bytes(&pk)?;
    let parsed_sig = parse_signature_bytes(&sig)?;
    verify_certified_vars_certificate(
        parsed_sig.certificate.as_ref(),
        &canister_id,
        root_pubkey,
        &parsed_sig.tree.digest(),
        &sig,
        &pk,
    )?;
    let canister_sig_tree = canister_sig_tree(parsed_sig, &sig)?;
    lookup_path_in_tree(&seed, msg, &canister_sig_tree, &pk, &sig)?;
    Ok(())
}

fn parse_pubkey_bytes(pubkey_bytes: &PublicKeyBytes) -> CryptoResult<(CanisterId, Vec<u8>)> {
    let pk = PublicKey::try_from(pubkey_bytes).map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::IcCanisterSignature,
        key_bytes: Some(pubkey_bytes.0.clone()),
        internal_error: format!("{:?}", e),
    })?;
    Ok((pk.signing_canister_id(), pk.into_seed()))
}

fn parse_signature_bytes(sig: &SignatureBytes) -> CryptoResult<Signature> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if sig.0.len() < 3 || sig.0[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::IcCanisterSignature,
            sig_bytes: sig.0.clone(),
            internal_error: "signature CBOR doesn't have a self-describing tag".to_string(),
        });
    }

    serde_cbor::from_slice::<Signature>(&sig.0).map_err(|err| CryptoError::MalformedSignature {
        algorithm: AlgorithmId::IcCanisterSignature,
        sig_bytes: sig.0.clone(),
        internal_error: format!("failed to parse signature CBOR: {}", err),
    })
}

fn verify_certified_vars_certificate(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pubkey: &ThresholdSigPublicKey,
    digest: &Digest,
    sig: &SignatureBytes,
    pk: &PublicKeyBytes,
) -> CryptoResult<()> {
    ic_certified_vars::verify_certificate(
        certificate,
        &canister_id,
        root_pubkey,
        digest.as_bytes(),
    )
    .map_err(|err| match &err {
        CertificateValidationError::DeserError(_)
        | CertificateValidationError::MalformedHashTree(_) => CryptoError::MalformedSignature {
            algorithm: AlgorithmId::IcCanisterSignature,
            sig_bytes: sig.0.clone(),
            internal_error: format!("malformed certificate: {}", err),
        },
        CertificateValidationError::InvalidSignature(_)
        | CertificateValidationError::CertifiedDataMismatch { .. }
        | CertificateValidationError::SubnetDelegationNotAllowed => {
            CryptoError::SignatureVerification {
                algorithm: AlgorithmId::IcCanisterSignature,
                public_key_bytes: pk.0.clone(),
                sig_bytes: sig.0.clone(),
                internal_error: format!("certificate verification failed: {}", err),
            }
        }
    })?;
    Ok(())
}

fn canister_sig_tree(
    parsed_sig: Signature,
    sig: &SignatureBytes,
) -> CryptoResult<LabeledTree<Vec<u8>>> {
    LabeledTree::<Vec<u8>>::try_from(parsed_sig.tree).map_err(|err| {
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::IcCanisterSignature,
            sig_bytes: sig.0.clone(),
            internal_error: format!("failed to flatten signature hash tree: {:?}", err),
        }
    })
}

fn lookup_path_in_tree(
    seed: &[u8],
    msg: &[u8],
    canister_sig_tree: &LabeledTree<Vec<u8>>,
    pk: &PublicKeyBytes,
    sig: &SignatureBytes,
) -> CryptoResult<()> {
    let seed_hash = Sha256::hash(&seed);
    let msg_hash = Sha256::hash(&msg);
    let tree =
        ic_crypto_tree_hash::lookup_path(&canister_sig_tree, &[b"sig", &seed_hash, &msg_hash])
            .ok_or_else(|| CryptoError::SignatureVerification {
                algorithm: AlgorithmId::IcCanisterSignature,
                public_key_bytes: pk.0.clone(),
                sig_bytes: sig.0.clone(),
                internal_error: format!(
                    "the signature tree doesn't contain sig/{}/{} path",
                    hex::encode(&seed_hash),
                    hex::encode(&msg_hash)
                ),
            })?;
    match tree {
        LabeledTree::Leaf(leaf) if leaf.is_empty() => Ok(()),
        _ => Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::IcCanisterSignature,
            public_key_bytes: pk.0.clone(),
            sig_bytes: sig.0.clone(),
            internal_error:
                "The result of 'lookup_path' in the signature tree was not a leaf containing \"\""
                    .to_string(),
        }),
    }
}
