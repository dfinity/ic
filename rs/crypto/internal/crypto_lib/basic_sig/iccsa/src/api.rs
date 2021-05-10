//! ICCSA (Internet Computer Canister Signature Algorithm) API
use crate::types::{PublicKey, PublicKeyBytes, Signature, SignatureBytes};
use ic_certified_vars::CertificateValidationError;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_sha256::Sha256;
use ic_crypto_tree_hash::{lookup_path, LabeledTree};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{
    crypto::{AlgorithmId, CryptoError, CryptoResult},
    CanisterId,
};
use simple_asn1::{BigUint, OID};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Parse `pk_der` as DER-encoded public key with OID 1.3.6.1.4.1.56387.1.2, and
/// returns the unwrapped public key bytes. See
/// * https://sdk.dfinity.org/docs/interface-spec/index.html#canister-signatures
/// * https://tools.ietf.org/html/rfc8410#section-4
pub fn public_key_bytes_from_der(pk_der: &[u8]) -> CryptoResult<PublicKeyBytes> {
    let (oid, pk_bytes) = der_utils::oid_and_public_key_bytes_from_der(pk_der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::IcCanisterSignature,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: e.internal_error,
        }
    })?;
    ensure_correct_oid(oid, pk_der)?;
    Ok(PublicKeyBytes(pk_bytes))
}

fn ensure_correct_oid(oid: simple_asn1::OID, pk_der: &[u8]) -> CryptoResult<()> {
    if oid != simple_asn1::oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2) {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::IcCanisterSignature,
            key_bytes: Some(Vec::from(pk_der)),
            internal_error: format!("Wrong OID: {:?}", oid),
        });
    }
    Ok(())
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
    let algorithm = AlgorithmId::IcCanisterSignature;
    let (canister_id, seed) = parse_pubkey_bytes(&pk)?;
    let parsed_sig = parse_signature_bytes(&sig)?;

    ic_certified_vars::verify_certificate(
        parsed_sig.certificate.as_ref(),
        &canister_id,
        root_pubkey,
        parsed_sig.tree.digest().as_bytes(),
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

    let canister_sig_tree = LabeledTree::<Vec<u8>>::try_from(parsed_sig.tree).map_err(|err| {
        CryptoError::MalformedSignature {
            algorithm,
            sig_bytes: sig.0.clone(),
            internal_error: format!("failed to flatten signature hash tree: {:?}", err),
        }
    })?;

    let seed_hash = Sha256::hash(&seed);
    let msg_hash = Sha256::hash(&msg);
    lookup_path(&canister_sig_tree, &[b"sig", &seed_hash, &msg_hash]).ok_or_else(|| {
        CryptoError::SignatureVerification {
            algorithm,
            public_key_bytes: pk.0,
            sig_bytes: sig.0,
            internal_error: format!(
                "the signature tree doesn't contain sig/{}/{} path",
                hex::encode(&seed_hash),
                hex::encode(&msg_hash)
            ),
        }
    })?;

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

    Ok(serde_cbor::from_slice::<Signature>(&sig.0).map_err(|err| {
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::IcCanisterSignature,
            sig_bytes: sig.0.clone(),
            internal_error: format!("failed to parse signature CBOR: {}", err),
        }
    })?)
}
