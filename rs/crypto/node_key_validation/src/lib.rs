//! Library crate for verifying the validity of a node's public key material.
//!
//! Such verification is used, for example, to ensure that only valid node key
//! material is stored in the registry or to check registry invariants.
//!
//! Use `ValidNodePublicKeys::try_from(keys, node_id, current_time)` to perform
//! the validation checks.
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
//! Validation of a *node's interactive DKG dealing encryption key* includes verifying that
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
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    EccCurveType, verify_mega_public_key,
};
pub use ic_crypto_tls_cert_validation::TlsCertValidationError;
pub use ic_crypto_tls_cert_validation::ValidTlsCertificate;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::Time;
use ic_types::crypto::CurrentNodePublicKeys;
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ValidNodePublicKeys {
    node_signing_public_key: ValidNodeSigningPublicKey,
    committee_signing_public_key: ValidCommitteeSigningPublicKey,
    tls_certificate: ValidTlsCertificate,
    dkg_dealing_encryption_public_key: ValidDkgDealingEncryptionPublicKey,
    idkg_dealing_encryption_public_key: ValidIDkgDealingEncryptionPublicKey,
}

impl
    From<(
        ValidNodeSigningPublicKey,
        ValidCommitteeSigningPublicKey,
        ValidTlsCertificate,
        ValidDkgDealingEncryptionPublicKey,
        ValidIDkgDealingEncryptionPublicKey,
    )> for ValidNodePublicKeys
{
    fn from(
        (
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_key,
        ): (
            ValidNodeSigningPublicKey,
            ValidCommitteeSigningPublicKey,
            ValidTlsCertificate,
            ValidDkgDealingEncryptionPublicKey,
            ValidIDkgDealingEncryptionPublicKey,
        ),
    ) -> Self {
        Self {
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_key,
        }
    }
}

impl ValidNodePublicKeys {
    /// Determines if the given node public key material is valid.
    ///
    /// Returns `ValidNodePublicKeys` iff the `keys` are valid with respect to
    /// the given `node_id` and `current_time`. For additional information on
    /// how the keys are validated, see this crate's documentation.
    ///
    /// After successful validation, callers shall only work with
    /// `ValidNodePublicKeys` in their API and not with the possibly invalid
    /// `CurrentNodePublicKeys` so as to avoid confusion about whether key
    /// material is validated or not.
    pub fn try_from(
        keys: CurrentNodePublicKeys,
        node_id: NodeId,
        current_time: Time,
    ) -> Result<Self, KeyValidationError> {
        let node_signing_public_key_proto = keys
            .node_signing_public_key
            .ok_or_else(|| invalid_node_signing_key_error("key is missing"))?;
        let node_signing_public_key =
            ValidNodeSigningPublicKey::try_from((node_signing_public_key_proto, node_id))?;

        let committee_signing_public_key_proto = keys
            .committee_signing_public_key
            .ok_or_else(|| invalid_committee_signing_key_error("key is missing"))?;
        let committee_signing_public_key =
            ValidCommitteeSigningPublicKey::try_from(committee_signing_public_key_proto)?;

        let tls_certificate_proto = keys.tls_certificate.ok_or_else(|| TlsCertValidationError {
            error: "invalid TLS certificate: certificate is missing".to_string(),
        })?;
        let tls_certificate =
            ValidTlsCertificate::try_from((tls_certificate_proto, node_id, current_time))?;

        let dkg_dealing_encryption_public_key_proto = keys
            .dkg_dealing_encryption_public_key
            .ok_or_else(|| invalid_dkg_dealing_enc_pubkey_error("key is missing"))?;
        let dkg_dealing_encryption_public_key = ValidDkgDealingEncryptionPublicKey::try_from((
            dkg_dealing_encryption_public_key_proto,
            node_id,
        ))?;

        let idkg_dealing_encryption_public_key_proto = keys
            .idkg_dealing_encryption_public_key
            .ok_or_else(|| invalid_idkg_dealing_enc_pubkey_error("key is missing"))?;
        let idkg_dealing_encryption_public_key = ValidIDkgDealingEncryptionPublicKey::try_from(
            idkg_dealing_encryption_public_key_proto,
        )?;

        Ok(ValidNodePublicKeys {
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_key,
        })
    }

    /// Returns the node ID for which the public key material's validity was
    /// successfully verified.
    pub fn node_id(&self) -> NodeId {
        self.node_signing_public_key.derived_node_id
    }

    /// Returns the validated node signing key.
    pub fn node_signing_key(&self) -> &PublicKey {
        &self.node_signing_public_key.public_key
    }

    /// Returns the validated committee signing key.
    pub fn committee_signing_key(&self) -> &PublicKey {
        &self.committee_signing_public_key.public_key
    }

    /// Returns the validated DKG dealing encryption key.
    pub fn dkg_dealing_encryption_key(&self) -> &PublicKey {
        &self.dkg_dealing_encryption_public_key.public_key
    }

    /// Returns the validated DKG dealing encryption key.
    pub fn idkg_dealing_encryption_key(&self) -> &PublicKey {
        &self.idkg_dealing_encryption_public_key.public_key
    }

    /// Returns the validated TLS certificate.
    pub fn tls_certificate(&self) -> &X509PublicKeyCert {
        self.tls_certificate.get()
    }
}

/// Validated node signing public key.
///
/// The [`public_key`] contained is guaranteed to be immutable and a valid node signing public key.
/// The [`derived_node_id`] contains the node id derived from the [`public_key`].
///
/// Use `try_from` to create an instance from an unvalidated public key.
///
/// See `try_from((PublicKey, NodeId))` if you need to validate the [`derived_node_id`] against an
/// expected trustworthy node id.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ValidNodeSigningPublicKey {
    public_key: PublicKey,
    derived_node_id: NodeId,
}

impl TryFrom<PublicKey> for ValidNodeSigningPublicKey {
    type Error = KeyValidationError;

    fn try_from(public_key: PublicKey) -> Result<Self, Self::Error> {
        let public_key_bytes = BasicSigEd25519PublicKeyBytes::try_from(&public_key)
            .map_err(|e| invalid_node_signing_key_error(format!("{e}")))?;
        if !ic_crypto_internal_basic_sig_ed25519::verify_public_key(&public_key_bytes) {
            return Err(invalid_node_signing_key_error("verification failed"));
        }
        let derived_node_id = derive_node_id(public_key_bytes);
        Ok(Self {
            public_key,
            derived_node_id,
        })
    }
}

impl TryFrom<(PublicKey, NodeId)> for ValidNodeSigningPublicKey {
    type Error = KeyValidationError;

    fn try_from((public_key, expected_node_id): (PublicKey, NodeId)) -> Result<Self, Self::Error> {
        let valid_public_key = ValidNodeSigningPublicKey::try_from(public_key)?;
        if expected_node_id != valid_public_key.derived_node_id {
            return Err(invalid_node_signing_key_error(format!(
                "key not valid for node ID {expected_node_id}"
            )));
        }
        Ok(valid_public_key)
    }
}

impl ValidNodeSigningPublicKey {
    pub fn get(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the node ID derived from the `public_key`.
    pub fn derived_node_id(&self) -> &NodeId {
        &self.derived_node_id
    }
}

/// Validated node committee signing public key.
///
/// The [`public_key`] contained is guaranteed to be immutable and a valid node committee signing public key.
/// Use `try_from` to create an instance from an unvalidated public key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ValidCommitteeSigningPublicKey {
    public_key: PublicKey,
}

/// Validates a node's committee signing public key.
///
/// See the crate documentation for the exact checks that are performed.
impl TryFrom<PublicKey> for ValidCommitteeSigningPublicKey {
    type Error = KeyValidationError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        let pubkey_bytes = MultiSigBls12381PublicKeyBytes::try_from(&value)
            .map_err(|e| invalid_committee_signing_key_error(format!("{e}")))?;
        let pop_bytes = MultiSigBls12381PopBytes::try_from(&value)
            .map_err(|e| invalid_committee_signing_key_error(format!("{e}")))?;

        // Note that `verify_pop` also ensures that the public key is a point on the
        // curve and in the right subgroup.
        ic_crypto_internal_multi_sig_bls12381::verify_pop(&pop_bytes, &pubkey_bytes)
            .map_err(|e| invalid_committee_signing_key_error(format!("{e}")))?;
        Ok(Self { public_key: value })
    }
}

impl ValidCommitteeSigningPublicKey {
    pub fn get(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Validated NIDKG dealing encryption public key.
///
/// The [`public_key`] contained is guaranteed to be immutable and
/// a valid NIDGK dealing encryption public key.
/// Use `try_from((PublicKey, NodeId))` to create an instance from an unvalidated public key and node id.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ValidDkgDealingEncryptionPublicKey {
    public_key: PublicKey,
}

/// Validates a node's non-interactive DKG dealing encryption key.
///
/// See the crate documentation for the exact checks that are performed.
impl TryFrom<(PublicKey, NodeId)> for ValidDkgDealingEncryptionPublicKey {
    type Error = KeyValidationError;

    fn try_from((public_key, node_id): (PublicKey, NodeId)) -> Result<Self, Self::Error> {
        // Note: `fs_ni_dkg_pubkey_from_proto` also ensures that the
        // public key is a point on the curve and in the right subgroup.
        let fs_ni_dkg_pubkey = fs_ni_dkg_pubkey_from_proto(&public_key)
            .map_err(|e| invalid_dkg_dealing_enc_pubkey_error(format!("{e}")))?;
        if !fs_ni_dkg_pubkey.verify(node_id.get().as_slice()) {
            return Err(invalid_dkg_dealing_enc_pubkey_error("verification failed"));
        }
        Ok(Self { public_key })
    }
}

impl ValidDkgDealingEncryptionPublicKey {
    pub fn get(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Validated iDKG dealing encryption public key of a node.
///
/// Instances have successfully passed the validity check and are immutable,
/// i.e., the contained public key material is guaranteed to be valid.
///
/// Use `try_from` to create an instance from an unvalidated public key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ValidIDkgDealingEncryptionPublicKey {
    public_key: PublicKey,
}

/// Validates a node's interactive DKG dealing encryption key.
///
/// See the crate documentation for the exact checks that are performed.
impl TryFrom<PublicKey> for ValidIDkgDealingEncryptionPublicKey {
    type Error = KeyValidationError;

    fn try_from(public_key: PublicKey) -> Result<Self, Self::Error> {
        let curve_type = match AlgorithmIdProto::try_from(public_key.algorithm).ok() {
            Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
            alg_id => Err(invalid_idkg_dealing_enc_pubkey_error(format!(
                "unsupported algorithm: {alg_id:?}"
            ))),
        }?;
        // `verify_mega_public_key` also ensures that the public key is a valid point on the curve.
        verify_mega_public_key(curve_type, &public_key.key_value).map_err(|e| {
            invalid_idkg_dealing_enc_pubkey_error(format!("verification failed: {e:?}"))
        })?;
        Ok(Self { public_key })
    }
}

impl ValidIDkgDealingEncryptionPublicKey {
    /// Returns the validated I-DKG dealing encryption key.
    pub fn get(&self) -> &PublicKey {
        &self.public_key
    }
}

/// A key validation error.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValidationError {
    pub error: String,
}

impl fmt::Display for KeyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
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
