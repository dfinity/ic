//! Static crypto utility methods.
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::api::{
    CspCreateMEGaKeyError, CspSecretKeyStoreChecker, NodePublicKeyData,
};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_crypto_internal_csp::Csp;
use ic_crypto_internal_csp::{public_key_store, CryptoServiceProvider};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_utils_basic_sig::conversions as basicsig_conversions;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::crypto::v1::{AlgorithmId as AlgorithmIdProto, X509PublicKeyCert};
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult, CurrentNodePublicKeys};
use ic_types::NodeId;
use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use tempfile::TempDir;

use ic_crypto_internal_csp::types::conversions::CspPopFromPublicKeyProtoError;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_interfaces::crypto::ErrorReproducibility;

#[cfg(test)]
mod tests;

pub fn derive_node_id(node_signing_pk: &PublicKeyProto) -> NodeId {
    basicsig_conversions::derive_node_id(node_signing_pk)
        .expect("Corrupted node signing public key")
}

pub fn generate_node_signing_keys(csp: &dyn CryptoServiceProvider) -> PublicKeyProto {
    let generated = csp
        .gen_node_signing_key_pair()
        .expect("Could not generate node signing keys");
    ic_crypto_internal_csp::keygen::utils::node_signing_pk_to_proto(generated)
}

pub fn generate_committee_signing_keys(csp: &dyn CryptoServiceProvider) -> PublicKeyProto {
    let generated = csp
        .gen_committee_signing_key_pair()
        .expect("Could not generate committee signing keys");
    ic_crypto_internal_csp::keygen::utils::committee_signing_pk_to_proto(generated)
}

/// Generates (forward-secure) NI-DKG dealing encryption key material given the
/// `node_id` of the node.
///
/// The secret key is stored in the key store of the provided `csp`, while the corresponding
/// public key is returned by this function.
pub fn generate_dkg_dealing_encryption_keys(
    csp: &mut dyn CryptoServiceProvider,
    node_id: NodeId,
) -> PublicKeyProto {
    let (pubkey, pop) = csp
        .gen_dealing_encryption_key_pair(node_id)
        .expect("Failed to generate DKG dealing encryption keys");
    ic_crypto_internal_csp::keygen::utils::dkg_dealing_encryption_pk_to_proto(pubkey, pop)
}

/// Generates (MEGa) I-DKG dealing encryption key material.
///
/// The secret key is stored in the key store of the provided `csp`, while the corresponding
/// public key is returned by this function.
///
/// # Errors
/// * `IDkgDealingEncryptionKeysGenerationError::InternalError` if an unrecoverable error occurs
/// * `IDkgDealingEncryptionKeysGenerationError::TransientInternalError` if a transient error (e.g.,
///   an RPC timeout, or an error persisting the secret key store) occurs
pub fn generate_idkg_dealing_encryption_keys(
    csp: &mut dyn CryptoServiceProvider,
) -> Result<PublicKeyProto, IDkgDealingEncryptionKeysGenerationError> {
    let pubkey = csp
        .idkg_gen_dealing_encryption_key_pair()
        .map_err(|e| match e {
            CspCreateMEGaKeyError::TransientInternalError { internal_error } => {
                IDkgDealingEncryptionKeysGenerationError::TransientInternalError(internal_error)
            }
            _ => IDkgDealingEncryptionKeysGenerationError::InternalError(format!("{}", e)),
        })?;
    Ok(ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto(pubkey))
}

#[derive(Debug)]
pub enum IDkgDealingEncryptionKeysGenerationError {
    InternalError(String),
    TransientInternalError(String),
}

impl ErrorReproducibility for IDkgDealingEncryptionKeysGenerationError {
    fn is_reproducible(&self) -> bool {
        match &self {
            // true, since regular internal errors are treated as reproducible
            IDkgDealingEncryptionKeysGenerationError::InternalError(_) => true,
            // false, since by definition, transient errors are non-reproducible
            IDkgDealingEncryptionKeysGenerationError::TransientInternalError(_) => false,
        }
    }
}

/// Generates TLS key material for a `node`.
///
/// The secret key is stored in the key store of the provided `csp`,
/// and is used to create a self-signed public key certificate returned by this function.
///
/// The certificate's notAfter date indicates according to RFC5280 (section
/// 4.1.2.5; see https://tools.ietf.org/html/rfc5280#section-4.1.2.5) that the
/// certificate has no well-defined expiration date.
pub fn generate_tls_keys(csp: &mut dyn CryptoServiceProvider, node: NodeId) -> TlsPublicKeyCert {
    csp.gen_tls_key_pair(node, "99991231235959Z")
        .expect("error generating TLS key pair")
}

/// Obtains the node's cryptographic keys or generates them if they are missing.
///
/// To check/generate the keys, a CSP client is created according to the given `config`.
/// First, tries to retrieve the node's public keys from `config.crypto_root`. If they
/// exist and they are consistent with the secret keys in kept by the CSP, the
/// public keys are returned together with the corresponding node ID.
///
/// If they do not exist, new keys are generated: the secret parts are stored in
/// the secret key store of the CSP, and the public parts are stored in a
/// public key store at `config.crypto_root`. The keys are generated for a particular
/// node ID, which is derived from the node's signing public key. In particular,
/// the node's TLS certificate and the node's DKG dealing encryption key are
/// bound to this node ID. The newly generated public keys are then returned
/// together with the corresponding node ID.
///
/// The `config.crypto_root` directory must exist and have the [permissions required
/// for storing crypto state](CryptoConfig::check_dir_has_required_permissions).
/// If there exists no key store in `config.crypto_root`, a new one is created.
///
/// # Panics
///  * if public keys exist but are inconsistent with the secret keys.
///  * if an error occurs when accessing or generating the keys.
pub fn get_node_keys_or_generate_if_missing(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> (CurrentNodePublicKeys, NodeId) {
    match check_keys_locally(config, tokio_runtime_handle.clone()) {
        Ok(None) => {
            // Generate new keys.
            let mut csp = csp_for_config(config, tokio_runtime_handle.clone());
            let node_signing_public_key = generate_node_signing_keys(&csp);
            let node_id = derive_node_id(&node_signing_public_key);
            let _committee_signing_public_key = generate_committee_signing_keys(&csp);
            let _tls_certificate = generate_tls_keys(&mut csp, node_id);
            let _dkg_dealing_encryption_public_key =
                generate_dkg_dealing_encryption_keys(&mut csp, node_id);
            let _idkg_dealing_encryption_public_key =
                generate_idkg_dealing_encryption_keys(&mut csp).unwrap_or_else(|e| {
                    panic!("Error generating I-DKG dealing encryption keys: {:?}", e)
                });
            let _check_again_generated_keys = check_keys_locally(config, tokio_runtime_handle)
                .expect("Could not read generated keys.")
                .expect("Newly generated keys are inconsistent.");

            (csp.current_node_public_keys(), node_id)
        }
        Ok(Some(node_pks)) => {
            let csp = csp_for_config(config, tokio_runtime_handle);
            let node_signing_pk = node_pks
                .node_signing_pk
                .as_ref()
                .expect("Missing node signing public key");
            let node_id = derive_node_id(node_signing_pk);
            (csp.current_node_public_keys(), node_id)
        }
        Err(e) => panic!("Node contains inconsistent key material: {}", e),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MEGaPublicKeyFromProtoError {
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    MalformedPublicKey {
        key_bytes: Vec<u8>,
    },
}

/// Deserialize a Protobuf public key to a MEGaPublicKey.
pub fn mega_public_key_from_proto(
    proto: &PublicKeyProto,
) -> Result<MEGaPublicKey, MEGaPublicKeyFromProtoError> {
    let curve_type = match AlgorithmIdProto::from_i32(proto.algorithm) {
        Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
        alg_id => Err(MEGaPublicKeyFromProtoError::UnsupportedAlgorithm {
            algorithm_id: alg_id,
        }),
    }?;

    MEGaPublicKey::deserialize(curve_type, &proto.key_value).map_err(|_| {
        MEGaPublicKeyFromProtoError::MalformedPublicKey {
            key_bytes: proto.key_value.clone(),
        }
    })
}

/// Checks whether this crypto component has complete local key material, i.e.
/// whether the public key store contains the required public keys, and whether
/// the secret key store contains the required secret keys.
/// Returns:
///  - `Ok(Some(node_public_keys))` if all public keys are found and they are
///    consistent with the secret keys.
///  - `Ok(None)` if no public keys are found.
///  - `Err(...)` in all other cases.
fn check_keys_locally(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> CryptoResult<Option<NodePublicKeys>> {
    let csp = csp_for_config(config, tokio_runtime_handle);
    let crypto_root = config.crypto_root.as_path();
    let node_pks = match read_public_keys(crypto_root) {
        Ok(pks) => pks,
        Err(_) => return Ok(None),
    };
    if node_public_keys_are_empty(&node_pks) {
        return Ok(None);
    }
    ensure_node_signing_key_is_set_up_locally(node_pks.node_signing_pk.clone(), &csp)?;
    ensure_committee_signing_key_is_set_up_locally(node_pks.committee_signing_pk.clone(), &csp)?;
    ensure_dkg_dealing_encryption_key_is_set_up_locally(
        node_pks.dkg_dealing_encryption_pk.clone(),
        &csp,
    )?;
    ensure_tls_cert_is_set_up_locally(node_pks.tls_certificate.clone(), &csp)?;
    ensure_idkg_dealing_encryption_keys_are_set_up_locally(
        &node_pks.idkg_dealing_encryption_pks,
        &csp,
    )?;
    Ok(Some(node_pks))
}

fn csp_for_config(
    config: &CryptoConfig,
    tokio_runtime_handle: Option<tokio::runtime::Handle>,
) -> Csp {
    Csp::new(
        config,
        tokio_runtime_handle,
        None,
        Arc::new(CryptoMetrics::none()),
    )
}

fn ensure_node_signing_key_is_set_up_locally(
    maybe_pk_proto: Option<PublicKeyProto>,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let pk_proto = maybe_pk_proto.ok_or_else(|| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Placeholder,
        key_bytes: None,
        internal_error: "missing node signing key in local public key store".to_string(),
    })?;
    ensure_node_signing_key_material_is_set_up_correctly(pk_proto, csp)?;
    Ok(())
}

fn ensure_committee_signing_key_is_set_up_locally(
    maybe_pk_proto: Option<PublicKeyProto>,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let pk_proto = maybe_pk_proto.ok_or_else(|| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::MultiBls12_381,
        key_bytes: None,
        internal_error: "missing committee signing key in local public key store".to_string(),
    })?;
    ensure_committee_signing_key_material_is_set_up_correctly(pk_proto, csp)?;
    Ok(())
}

fn ensure_dkg_dealing_encryption_key_is_set_up_locally(
    maybe_pk_proto: Option<PublicKeyProto>,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let pk_proto = maybe_pk_proto.ok_or_else(|| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Groth20_Bls12_381,
        key_bytes: None,
        internal_error: "missing NI-DKG dealing encryption key in local public key store"
            .to_string(),
    })?;
    ensure_dkg_dealing_encryption_key_material_is_set_up_correctly(pk_proto, csp)?;
    Ok(())
}

fn ensure_idkg_dealing_encryption_keys_are_set_up_locally(
    pk_protos: &[PublicKeyProto],
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if pk_protos.is_empty() {
        Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MegaSecp256k1,
            key_bytes: None,
            internal_error: "missing iDKG dealing encryption key in local public key store"
                .to_string(),
        })
    } else {
        for pk_proto in pk_protos {
            ensure_idkg_dealing_encryption_key_material_is_set_up_correctly(pk_proto, csp)?;
        }
        Ok(())
    }
}

fn ensure_tls_cert_is_set_up_locally(
    maybe_tls_cert_proto: Option<X509PublicKeyCert>,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let tls_cert_proto = maybe_tls_cert_proto.ok_or_else(|| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Tls,
        key_bytes: None,
        internal_error: "missing TLS public key certificate in local public key store".to_string(),
    })?;
    ensure_tls_key_material_is_set_up_correctly(tls_cert_proto, csp)?;
    Ok(())
}

fn ensure_node_signing_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::Ed25519 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm Ed25519, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    let csp_key = CspPublicKey::try_from(pubkey_proto)?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Ed25519,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

fn ensure_committee_signing_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::MultiBls12_381 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MultiBls12_381,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm MultiBls12_381, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    ensure_committe_signing_key_pop_is_well_formed(&pubkey_proto)?;
    let csp_key = CspPublicKey::try_from(pubkey_proto)?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MultiBls12_381,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

fn ensure_committe_signing_key_pop_is_well_formed(pk_proto: &PublicKeyProto) -> CryptoResult<()> {
    CspPop::try_from(pk_proto).map_err(|e| match e {
        CspPopFromPublicKeyProtoError::NoPopForAlgorithm { algorithm } => {
            CryptoError::MalformedPop {
                algorithm,
                pop_bytes: vec![],
                internal_error: format!("{:?}", e),
            }
        }
        CspPopFromPublicKeyProtoError::MissingProofData => CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: vec![],
            internal_error: format!("{:?}", e),
        },
        CspPopFromPublicKeyProtoError::MalformedPop {
            pop_bytes,
            internal_error,
        } => CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes,
            internal_error,
        },
    })?;

    Ok(())
}

fn ensure_dkg_dealing_encryption_key_material_is_set_up_correctly(
    pubkey_proto: PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    if AlgorithmId::from(pubkey_proto.algorithm) != AlgorithmId::Groth20_Bls12_381 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: format!(
                "expected public key algorithm Groth20_Bls12_381, but found {:?}",
                AlgorithmId::from(pubkey_proto.algorithm),
            ),
        });
    }
    let _csp_pop = CspFsEncryptionPop::try_from(&pubkey_proto).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: None,
            internal_error: format!("{:?}", e),
        }
    })?;
    let csp_key = CspFsEncryptionPublicKey::try_from(pubkey_proto).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_bytes: Some(e.key_bytes),
            internal_error: e.internal_error,
        }
    })?;
    let key_id = KeyId::from(&csp_key);
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Groth20_Bls12_381,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

fn ensure_idkg_dealing_encryption_key_material_is_set_up_correctly(
    pubkey_proto: &PublicKeyProto,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let idkg_dealing_encryption_pk =
        mega_public_key_from_proto(pubkey_proto).map_err(|e| match e {
            MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { algorithm_id } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: None,
                    internal_error: format!(
                        "unsupported algorithm ({:?}) of I-DKG dealing encryption key",
                        algorithm_id,
                    ),
                }
            }
            MEGaPublicKeyFromProtoError::MalformedPublicKey { key_bytes } => {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::MegaSecp256k1,
                    key_bytes: Some(key_bytes),
                    internal_error: "I-DKG dealing encryption key malformed".to_string(),
                }
            }
        })?;

    let key_id =
        KeyId::try_from(&idkg_dealing_encryption_pk).unwrap_or_else(|err| panic!("{}", err));
    if !csp.sks_contains(&key_id)? {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::MegaSecp256k1,
            key_id: key_id.to_string(),
        });
    }
    Ok(())
}

fn ensure_tls_key_material_is_set_up_correctly(
    pubkey_cert_proto: X509PublicKeyCert,
    csp: &dyn CspSecretKeyStoreChecker,
) -> CryptoResult<()> {
    let public_key_cert = TlsPublicKeyCert::new_from_der(pubkey_cert_proto.certificate_der)
        .map_err(|e| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Tls,
                key_bytes: None, // The DER is included in the `internal_error` below.
                internal_error: format!("{}", e),
            }
        })?;

    if !csp.sks_contains_tls_key(&public_key_cert)? {
        return Err(CryptoError::TlsSecretKeyNotFound {
            certificate_der: public_key_cert.as_der().clone(),
        });
    }
    Ok(())
}

fn node_public_keys_are_empty(node_pks: &NodePublicKeys) -> bool {
    node_pks.node_signing_pk.is_none()
        && node_pks.committee_signing_pk.is_none()
        && node_pks.dkg_dealing_encryption_pk.is_none()
        && node_pks.idkg_dealing_encryption_pks.is_empty()
        && node_pks.tls_certificate.is_none()
}

fn read_public_keys(crypto_root: &Path) -> CryptoResult<NodePublicKeys> {
    public_key_store::read_node_public_keys(crypto_root).map_err(|e| CryptoError::InvalidArgument {
        message: format!("Failed reading public keys: {:?}", e),
    })
}

#[cfg(test)]
pub(crate) fn local_csp_in_temp_dir() -> (Csp, TempDir) {
    let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
    let csp = csp_for_config(&config, None);
    (csp, temp_dir)
}
