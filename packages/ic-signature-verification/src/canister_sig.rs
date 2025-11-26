use ic_certification::{
    Certificate, Delegation, HashTree, LookupResult, SubtreeLookupResult, leaf,
};
use ic_principal::Principal;
use ic_verify_bls_signature::verify_bls_signature;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

pub const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

use ic_canister_sig_creation::{CanisterSigPublicKey, extract_raw_root_pk_from_der};

/// Verifies that `signature` is a valid canister signature on `message`.
/// https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
pub fn verify_canister_sig(
    message: &[u8],
    signature_cbor: &[u8],
    public_key_der: &[u8],
    ic_root_public_key_raw: &[u8],
) -> Result<(), String> {
    let signature = parse_signature_cbor(signature_cbor)?;
    let public_key = CanisterSigPublicKey::try_from(public_key_der)
        .map_err(|e| format!("failed to parse canister sig public key: {e}"))?;
    let certificate =
        check_certified_data_and_get_certificate(&signature, &public_key.canister_id)?;
    check_sig_path(&signature, &public_key, message)?;
    verify_certificate(&certificate, public_key.canister_id, ic_root_public_key_raw)
}

// Check that signature.certificate's tree contains for the canister identified by
// signing_canister_id an entry for certified_data that matches signature.tree.digest.
fn check_certified_data_and_get_certificate(
    signature: &CanisterSignature,
    signing_canister_id: &Principal,
) -> Result<Certificate, String> {
    let certificate = parse_certificate_cbor(&signature.certificate)?;
    let cert_data_path = [
        "canister".as_bytes(),
        signing_canister_id.as_slice(),
        "certified_data".as_bytes(),
    ];
    let SubtreeLookupResult::Found(cert_data_leaf) =
        certificate.tree.lookup_subtree(&cert_data_path)
    else {
        return Err("certified_data entry not found".to_string());
    };
    if cert_data_leaf != leaf(signature.tree.digest()) {
        return Err("certified_data doesn't match sig tree digest".to_string());
    }
    Ok(certificate)
}

// Check that signature.tree contains an empty leaf at correct "sig"-path,
// where the path is determined by hashes of canister_sig_pk.seed and msg.
fn check_sig_path(
    signature: &CanisterSignature,
    canister_sig_pk: &CanisterSigPublicKey,
    msg: &[u8],
) -> Result<(), String> {
    let seed_hash = hash_sha256(&canister_sig_pk.seed);
    let msg_hash = hash_sha256(msg);
    let sig_path = ["sig".as_bytes(), &seed_hash, &msg_hash];
    let SubtreeLookupResult::Found(sig_leaf) = signature.tree.lookup_subtree(&sig_path) else {
        return Err("signature entry not found".to_string());
    };
    if sig_leaf != leaf(b"") {
        return Err("signature entry is not an empty leaf".to_string());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct CanisterSignature {
    pub certificate: ByteBuf,
    pub tree: HashTree,
}

fn parse_signature_cbor(signature_cbor: &[u8]) -> Result<CanisterSignature, String> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if signature_cbor.len() < 3 || signature_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err("signature CBOR doesn't have a self-describing tag".to_string());
    }
    serde_cbor::from_slice::<CanisterSignature>(signature_cbor)
        .map_err(|e| format!("failed to parse signature CBOR: {e}"))
}

fn parse_certificate_cbor(certificate_cbor: &[u8]) -> Result<Certificate, String> {
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if certificate_cbor.len() < 3 || certificate_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        return Err("certificate CBOR doesn't have a self-describing tag".to_string());
    }
    serde_cbor::from_slice::<Certificate>(certificate_cbor)
        .map_err(|e| format!("failed to parse certificate CBOR: {e}"))
}

fn verify_certificate(
    certificate: &Certificate,
    signing_canister_id: Principal,
    root_public_key_raw: &[u8],
) -> Result<(), String> {
    let bls_pk_raw = match &certificate.delegation {
        Some(delegation) => {
            verify_delegation(delegation, signing_canister_id, root_public_key_raw)?
        }
        _ => root_public_key_raw.to_vec(),
    };
    check_bls_signature(certificate, &bls_pk_raw)
}

fn verify_delegation(
    delegation: &Delegation,
    signing_canister_id: Principal,
    root_public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let cert: Certificate = parse_certificate_cbor(&delegation.certificate)
        .map_err(|e| format!("invalid delegation certificate: {e}"))?;

    // disallow nested delegations
    if cert.delegation.is_some() {
        return Err("multiple delegations not allowed".to_string());
    }

    check_bls_signature(&cert, root_public_key)?;

    // check delegation range
    let canister_range_path = [
        "subnet".as_bytes(),
        delegation.subnet_id.as_ref(),
        "canister_ranges".as_bytes(),
    ];
    let LookupResult::Found(canister_range) = cert.tree.lookup_path(&canister_range_path) else {
        return Err("canister_ranges-entry not found".to_string());
    };

    let canister_ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(canister_range)
        .map_err(|e| format!("invalid canister range: {e}"))?;
    if !principal_is_within_ranges(&signing_canister_id, &canister_ranges[..]) {
        return Err("signing canister id not in canister_ranges".to_string());
    }

    // lookup the public key delegated to
    let public_key_path = [
        "subnet".as_bytes(),
        delegation.subnet_id.as_ref(),
        "public_key".as_bytes(),
    ];
    let LookupResult::Found(subnet_public_key_der) = cert.tree.lookup_path(&public_key_path) else {
        return Err("subnet public key not found".to_string());
    };
    extract_raw_root_pk_from_der(subnet_public_key_der)
}

fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| (start..=end).contains(&principal))
}

const SHA256_DIGEST_LEN: usize = 32;
fn hash_sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut hash = Sha256::default();
    hash.update(data);
    <[u8; SHA256_DIGEST_LEN]>::from(hash.finalize())
}

fn check_bls_signature(certificate: &Certificate, signing_pk_raw: &[u8]) -> Result<(), String> {
    let sig = certificate.signature.as_slice();
    let root_hash = certificate.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);
    if verify_bls_signature(sig, &msg, signing_pk_raw).is_err() {
        return Err("invalid BLS signature".to_string());
    }
    Ok(())
}
