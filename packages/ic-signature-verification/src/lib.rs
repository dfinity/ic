use candid::Principal;
use ic_cbor::CertificateToCbor;
use ic_certification::{
    leaf, Certificate, Delegation, HashTree, LookupResult, SubtreeLookupResult,
};
use ic_verify_bls_signature::verify_bls_signature;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

pub const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

use canister_sig_util::{extract_raw_root_pk_from_der, CanisterSigPublicKey};

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
        .map_err(|e| format!("failed to parse canister sig public key: {}", e))?;
    let certificate = check_certified_data_and_get_certificate(&signature, &public_key, message)?;
    verify_certificate(&certificate, public_key.canister_id, ic_root_public_key_raw)
}

fn check_certified_data_and_get_certificate(
    signature: &CanisterSignature,
    canister_sig_pk: &CanisterSigPublicKey,
    msg: &[u8],
) -> Result<Certificate, String> {
    let certificate = Certificate::from_cbor(&signature.certificate)
        .map_err(|e| format!("failed to parse certificate CBOR: {}", e))?;
    let seed_hash = hash_sha256(&canister_sig_pk.seed);
    let msg_hash = hash_sha256(msg);

    // Check that signature.certificate's tree contains for the canister identified by
    // canister_sig_pk an entry for certified_data that matches signature.tree.digest.
    let cert_data_path = [
        "canister".as_bytes(),
        canister_sig_pk.canister_id.as_slice(),
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

    // Check that signature.tree contains an empty leaf at correct "sig"-path
    let sig_path = ["sig".as_bytes(), &seed_hash, &msg_hash];
    let SubtreeLookupResult::Found(sig_leaf) = signature.tree.lookup_subtree(&sig_path) else {
        return Err("signature entry not found".to_string());
    };
    if sig_leaf != leaf(b"") {
        return Err("signature entry is not an empty leaf".to_string());
    }
    Ok(certificate)
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
        .map_err(|e| format!("failed to parse signature CBOR: {}", e))
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
        _ => root_public_key_raw.into(),
    };
    check_bls_signature(certificate, &bls_pk_raw)
}

fn verify_delegation(
    delegation: &Delegation,
    signing_canister_id: Principal,
    root_public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let cert: Certificate = Certificate::from_cbor(&delegation.certificate)
        .map_err(|e| format!("invalid delegation certificate: {}", e))?;

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

    let canister_ranges: Vec<(Principal, Principal)> =
        serde_cbor::from_slice(canister_range).unwrap();
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
        .any(|r| principal >= &r.0 && principal <= &r.1)
}

const SHA256_DIGEST_LEN: usize = 32;
fn hash_sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut hash = Sha256::default();
    hash.update(data);
    hash.finalize().into()
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

// The code below is copied from II's canister_sig_util.
// TODO: remove the copy once canister_sig_util is published on crates.io
#[allow(unused)]
pub mod canister_sig_util {
    use candid::Principal;

    pub const IC_ROOT_PK_DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
    pub const IC_ROOT_PK_LENGTH: usize = 96;

    pub const CANISTER_SIG_PK_DER_PREFIX_LENGTH: usize = 19;
    // Canister signatures' public key OID is 1.3.6.1.4.1.56387.1.2,
    // cf. https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
    pub const CANISTER_SIG_PK_DER_OID: &[u8; 14] =
        b"\x30\x0C\x06\x0A\x2B\x06\x01\x04\x01\x83\xB8\x43\x01\x02";

    #[derive(Clone, Eq, PartialEq, Debug)]
    pub struct CanisterSigPublicKey {
        pub canister_id: Principal,
        pub seed: Vec<u8>,
    }

    impl TryFrom<&[u8]> for CanisterSigPublicKey {
        type Error = String;

        fn try_from(pk_der: &[u8]) -> Result<Self, Self::Error> {
            let pk_raw = extract_raw_canister_sig_pk_from_der(pk_der)?;
            Self::try_from_raw(pk_raw.as_slice())
        }
    }

    impl CanisterSigPublicKey {
        /// Constructs a new canister signatures public key.
        pub fn new(canister_id: Principal, seed: Vec<u8>) -> Self {
            CanisterSigPublicKey { canister_id, seed }
        }

        pub fn try_from_raw(pk_raw: &[u8]) -> Result<Self, String> {
            let canister_id_len: usize = if !pk_raw.is_empty() {
                usize::from(pk_raw[0])
            } else {
                return Err("empty raw canister sig pk".to_string());
            };
            if pk_raw.len() < (1 + canister_id_len) {
                return Err("canister sig pk too short".to_string());
            }
            let canister_id_raw = &pk_raw[1..(1 + canister_id_len)];
            let seed = &pk_raw[canister_id_len + 1..];
            let canister_id = Principal::try_from_slice(canister_id_raw)
                .map_err(|e| format!("invalid canister id in canister sig pk: {}", e))?;
            Ok(CanisterSigPublicKey {
                canister_id,
                seed: seed.to_vec(),
            })
        }

        /// Returns a byte vector with DER-encoding of this key, see
        /// https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
        pub fn to_der(&self) -> Vec<u8> {
            let raw_pk = self.to_raw();

            let mut der_pk: Vec<u8> = vec![];
            // sequence of length 17 + the bit string length
            der_pk.push(0x30);
            der_pk.push(17 + raw_pk.len() as u8);
            der_pk.extend(CANISTER_SIG_PK_DER_OID);
            // BIT string of given length
            der_pk.push(0x03);
            der_pk.push(1 + raw_pk.len() as u8);
            der_pk.push(0x00);
            der_pk.extend(raw_pk);
            der_pk
        }

        /// Returns a byte vector with raw encoding of this key (i.e. a bit string with
        /// canister id length, canister id, and seed, without the DER-envelope)
        /// https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
        pub fn to_raw(&self) -> Vec<u8> {
            let mut raw_pk: Vec<u8> = vec![];
            raw_pk.push(self.canister_id.as_ref().len() as u8);
            raw_pk.extend(self.canister_id.as_ref());
            raw_pk.extend(self.seed.as_slice());
            raw_pk
        }
    }

    /// Verifies the structure given public key in DER-format, and returns raw bytes of the key.
    pub fn extract_raw_root_pk_from_der(pk_der: &[u8]) -> Result<Vec<u8>, String> {
        let expected_length = IC_ROOT_PK_DER_PREFIX.len() + IC_ROOT_PK_LENGTH;
        if pk_der.len() != expected_length {
            return Err(String::from("invalid root pk length"));
        }

        let prefix = &pk_der[0..IC_ROOT_PK_DER_PREFIX.len()];
        if prefix[..] != IC_ROOT_PK_DER_PREFIX[..] {
            return Err(String::from("invalid OID"));
        }

        let key = &pk_der[IC_ROOT_PK_DER_PREFIX.len()..];
        Ok(key.to_vec())
    }

    /// Verifies the structure given public key in DER-format, and returns raw bytes of the key.
    pub fn extract_raw_canister_sig_pk_from_der(pk_der: &[u8]) -> Result<Vec<u8>, String> {
        let oid_part = &pk_der[2..(CANISTER_SIG_PK_DER_OID.len() + 2)];
        if oid_part[..] != CANISTER_SIG_PK_DER_OID[..] {
            return Err(String::from("invalid OID of canister sig pk"));
        }
        let bitstring_offset: usize = CANISTER_SIG_PK_DER_PREFIX_LENGTH;
        let canister_id_len: usize = if pk_der.len() > bitstring_offset {
            usize::from(pk_der[bitstring_offset])
        } else {
            return Err(String::from("canister sig pk shorter than DER prefix"));
        };
        if pk_der.len() < (bitstring_offset + 1 + canister_id_len) {
            return Err(String::from("canister sig pk too short"));
        }
        Ok(pk_der[(bitstring_offset)..].to_vec())
    }
}
