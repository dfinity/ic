//! Library crate for verifying the validity of a node's public key material.
//!
//! Such verification is used, for example, to ensure that only valid node key
//! material is stored in the registry or to check registry invariants.
//!
//! Use `ValidNodePublicKeys::try_from(keys, node_id)` to perform the validation
//! checks.
//!
//! Validation of a *node's signing key* includes verifying that
//! * the key is present and well-formed
//! * the node ID derived from the key matches the `node_id`
//! * the public key is valid, which includes checking that the key is a point
//!   on the curve and in the right subgroup
//!
//! Validation of a *node's committee signing key* includes verifying that
//! * the key is present and well-formed
//! * the public key's proof of possession (PoP) is valid
//! * the public key is a point on the curve and in the right subgroup
//!
//! Validation of a *node's non-interactive DKG dealing encryption key* includes
//! verifying that
//! * the key is present and well-formed
//! * the public key's proof of possession (PoP) is valid
//! * the public key is a point on the curve and in the right subgroup
//!
//! Validation of a *node's interactive DKG dealing encryption key* is done
//! if (and only if) the key material version is >= 1 and includes verifying
//! that
//! * the key is present and well-formed
//! * the public key is a valid point on the curve
//!
//! How a *node's TLS certificate* is validated is described in the Rust doc of
//! `ic_crypto_tls_cert_validation::validate_tls_certificate`. Note that the
//! certificate is required to be present.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use crate::proto_conversions::fs_ni_dkg::fs_ni_dkg_pubkey_from_proto;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes as BasicSigEd25519PublicKeyBytes;
use ic_crypto_internal_multi_sig_bls12381::types::PopBytes as MultiSigBls12381PopBytes;
use ic_crypto_internal_multi_sig_bls12381::types::PublicKeyBytes as MultiSigBls12381PublicKeyBytes;
use ic_crypto_internal_threshold_sig_ecdsa::{verify_mega_public_key, EccCurveType};
use ic_crypto_tls_cert_validation::TlsCertValidationError;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

mod proto_conversions;

/// Validated public key material of a node.
///
/// Instances of this struct have successfully passed the validity checks and
/// are immutable, i.e., the contained public key material is guaranteed to be
/// valid.
///
/// Use `try_from` to create an instance from unvalidated `NodePublicKeys`.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidNodePublicKeys {
    node_id: NodeId,
    node_signing_pubkey: PublicKey,
    committee_signing_pubkey: PublicKey,
    dkg_dealing_encryption_pubkey: PublicKey,
    idkg_dealing_encryption_pubkey: Option<PublicKey>,
    tls_certificate: X509PublicKeyCert,
}

/// Validated iDKG dealing encryption public key of a node.
///
/// Instances have successfully passed the validity check and are immutable,
/// i.e., the contained public key material is guaranteed to be valid.
///
/// Use `try_from` to create an instance from an unvalidated public key.
///
/// Note: this struct will only exist temporarily while not all nodes have an
/// iDKG dealing encryption key yet. Once all nodes have such a key,
/// individually validating iDKG dealing encryption keys will become obsolete
/// and this struct will be removed.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidIDkgDealingEncryptionPublicKey {
    idkg_dealing_encryption_pubkey: PublicKey,
}

impl ValidNodePublicKeys {
    /// Determines if the given node public key material is valid.
    ///
    /// Returns `ValidNodePublicKeys` iff the `keys` are valid and iff they
    /// are valid for `node_id`. After successful validation, callers should
    /// only work with `ValidNodePublicKeys` in their API and not with
    /// the possibly invalid `NodePublicKeys` so as to avoid confusion about
    /// whether key material is validated or not.
    pub fn try_from(keys: &NodePublicKeys, node_id: NodeId) -> Result<Self, KeyValidationError> {
        validate_node_signing_key(&keys.node_signing_pk, node_id)?;
        validate_committee_signing_key(&keys.committee_signing_pk)?;
        validate_dkg_dealing_encryption_key(&keys.dkg_dealing_encryption_pk, node_id)?;
        validate_tls_certificate(&keys.tls_certificate, node_id)?;
        if keys.version >= 1 {
            validate_idkg_dealing_encryption_key(&keys.idkg_dealing_encryption_pk)?;
        }

        let node_signing_pubkey = keys
            .node_signing_pk
            .as_ref()
            .expect("Value missing")
            .clone();
        let committee_signing_pubkey = keys
            .committee_signing_pk
            .as_ref()
            .expect("Value missing")
            .clone();
        let dkg_dealing_encryption_pubkey = keys
            .dkg_dealing_encryption_pk
            .as_ref()
            .expect("Value missing")
            .clone();
        let idkg_dealing_encryption_pubkey = {
            if keys.version >= 1 {
                let idkg_pubkey = keys
                    .idkg_dealing_encryption_pk
                    .as_ref()
                    .expect("Value missing")
                    .clone();
                Some(idkg_pubkey)
            } else {
                None
            }
        };
        let tls_certificate = keys
            .tls_certificate
            .as_ref()
            .expect("Value missing")
            .clone();

        Ok(ValidNodePublicKeys {
            node_id,
            node_signing_pubkey,
            committee_signing_pubkey,
            dkg_dealing_encryption_pubkey,
            idkg_dealing_encryption_pubkey,
            tls_certificate,
        })
    }

    /// Returns the node ID for which the public key material's validity was
    /// successfully verified.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the validated node signing key.
    pub fn node_signing_key(&self) -> &PublicKey {
        &self.node_signing_pubkey
    }

    /// Returns the validated committee signing key.
    pub fn committee_signing_key(&self) -> &PublicKey {
        &self.committee_signing_pubkey
    }

    /// Returns the validated DKG dealing encryption key.
    pub fn dkg_dealing_encryption_key(&self) -> &PublicKey {
        &self.dkg_dealing_encryption_pubkey
    }

    /// Returns the validated DKG dealing encryption key.
    pub fn idkg_dealing_encryption_key(&self) -> Option<&PublicKey> {
        self.idkg_dealing_encryption_pubkey.as_ref()
    }

    /// Returns the validated TLS certificate.
    pub fn tls_certificate(&self) -> &X509PublicKeyCert {
        &self.tls_certificate
    }
}

impl ValidIDkgDealingEncryptionPublicKey {
    /// Determines if the given iDKG dealing encryption public key is valid.
    ///
    /// Returns a `ValidIDkgDealingEncryptionPublicKey` iff the `key` is valid.
    /// After successful validation, callers should only work with the returned
    /// instance in their API so as to avoid confusion about whether the key
    /// is validated or not.
    pub fn try_from(key: PublicKey) -> Result<Self, KeyValidationError> {
        validate_idkg_dealing_encryption_key(&Some(key.clone()))?;
        Ok(Self {
            idkg_dealing_encryption_pubkey: key,
        })
    }

    /// Returns the validated I-DKG dealing encryption key.
    pub fn get(&self) -> &PublicKey {
        &self.idkg_dealing_encryption_pubkey
    }
}

/// A key validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValidationError {
    pub error: String,
}

impl fmt::Display for KeyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Validates a node's signing key.
///
/// See the crate documentation for the exact checks that are performed.
fn validate_node_signing_key(
    node_signing_key: &Option<PublicKey>,
    node_id: NodeId,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = node_signing_key
        .as_ref()
        .ok_or_else(|| invalid_node_signing_key_error("key is missing"))?;

    let pubkey_bytes = BasicSigEd25519PublicKeyBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_node_signing_key_error(format!("{}", e)))?;

    if node_id != derive_node_id(pubkey_bytes) {
        return Err(invalid_node_signing_key_error(format!(
            "key not valid for node ID {}",
            node_id
        )));
    }
    if !ic_crypto_internal_basic_sig_ed25519::verify_public_key(&pubkey_bytes) {
        return Err(invalid_node_signing_key_error("verification failed"));
    }
    Ok(())
}

/// Validates a node's committee signing key.
///
/// See the crate documentation for the exact checks that are performed.
fn validate_committee_signing_key(
    committee_signing_key: &Option<PublicKey>,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = committee_signing_key
        .as_ref()
        .ok_or_else(|| invalid_committee_signing_key_error("key is missing"))?;

    let pubkey_bytes = MultiSigBls12381PublicKeyBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))?;
    let pop_bytes = MultiSigBls12381PopBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))?;

    // Note that `verify_pop` also ensures that the public key is a point on the
    // curve and in the right subgroup.
    ic_crypto_internal_multi_sig_bls12381::verify_pop(pop_bytes, pubkey_bytes)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))
}

/// Validates a node's non-interactive DKG dealing encryption key.
///
/// See the crate documentation for the exact checks that are performed.
fn validate_dkg_dealing_encryption_key(
    dkg_dealing_encryption_key: &Option<PublicKey>,
    node_id: NodeId,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = dkg_dealing_encryption_key
        .as_ref()
        .ok_or_else(|| invalid_dkg_dealing_enc_pubkey_error("key is missing"))?;

    // Note: `fs_ni_dkg_pubkey_from_proto` also ensures that the
    // public key is a point on the curve and in the right subgroup.
    let fs_ni_dkg_pubkey = fs_ni_dkg_pubkey_from_proto(pubkey_proto)
        .map_err(|e| invalid_dkg_dealing_enc_pubkey_error(format!("{}", e)))?;
    if !fs_ni_dkg_pubkey.verify(node_id.get().as_slice()) {
        return Err(invalid_dkg_dealing_enc_pubkey_error("verification failed"));
    }
    Ok(())
}

/// Validates a node's interactive DKG dealing encryption key.
///
/// See the crate documentation for the exact checks that are performed.
fn validate_idkg_dealing_encryption_key(
    idkg_dealing_encryption_key: &Option<PublicKey>,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = idkg_dealing_encryption_key
        .as_ref()
        .ok_or_else(|| invalid_idkg_dealing_enc_pubkey_error("key is missing"))?;

    let curve_type = match AlgorithmIdProto::from_i32(pubkey_proto.algorithm) {
        Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
        alg_id => Err(invalid_idkg_dealing_enc_pubkey_error(format!(
            "unsupported algorithm: {:?}",
            alg_id
        ))),
    }?;
    // `verify_mega_public_key` also ensures that the public key is a valid point on the curve.
    verify_mega_public_key(curve_type, &pubkey_proto.key_value).map_err(|e| {
        invalid_idkg_dealing_enc_pubkey_error(format!("verification failed: {:?}", e))
    })?;
    Ok(())
}

pub fn validate_tls_certificate(
    tls_certificate: &Option<X509PublicKeyCert>,
    node_id: NodeId,
) -> Result<(), TlsCertValidationError> {
    let cert = tls_certificate
        .as_ref()
        .ok_or_else(|| TlsCertValidationError {
            error: "invalid TLS certificate: certificate is missing".to_string(),
        })?;

    ic_crypto_tls_cert_validation::validate_tls_certificate(cert, node_id)
}

fn derive_node_id(pk_bytes: BasicSigEd25519PublicKeyBytes) -> NodeId {
    let pubkey_der = ic_crypto_internal_basic_sig_ed25519::public_key_to_der(pk_bytes);
    NodeId::from(PrincipalId::new_self_authenticating(&pubkey_der))
}

fn invalid_node_signing_key_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!("invalid node signing key: {}", internal_error.into()),
    }
}

fn invalid_committee_signing_key_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!("invalid committee signing key: {}", internal_error.into()),
    }
}

fn invalid_dkg_dealing_enc_pubkey_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!(
            "invalid DKG dealing encryption key: {}",
            internal_error.into()
        ),
    }
}

fn invalid_idkg_dealing_enc_pubkey_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!(
            "invalid I-DKG dealing encryption key: {}",
            internal_error.into()
        ),
    }
}

impl From<TlsCertValidationError> for KeyValidationError {
    fn from(e: TlsCertValidationError) -> Self {
        let TlsCertValidationError { error } = e;
        KeyValidationError { error }
    }
}
