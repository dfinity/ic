//! Static crypto utility methods.
use crate::common::utils::dkg::InitialDkgConfig;
use crate::CryptoComponent;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_csp::api::{CspKeyGenerator, NiDkgCspClient};
use ic_crypto_internal_csp::keygen::public_key_hash_as_key_id;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_crypto_internal_csp::Csp;
use ic_crypto_internal_csp::{public_key_store, CryptoServiceProvider};
use ic_interfaces::crypto::DkgAlgorithm;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::dkg::EncryptionPublicKeyWithPop;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use ic_types::{NodeId, PrincipalId};
use rand_core::OsRng;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::Arc;

pub mod dkg;
pub mod ni_dkg;

mod temp_crypto;

pub use crate::sign::utils::combined_threshold_signature_and_public_key;
pub use temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};

#[cfg(test)]
mod tests;

/// Generates initial DKG ephemeral encryption keys for the `dkg_config` and the
/// `node_id`.
/// * The secret key is stored in the crypto secret key store at the
///   `crypto_root`.
/// * The corresponding public key is returned
/// * If the crypto root does not exist yet, it is created and the appropriate
///   permissions are set.
pub fn generate_initial_dkg_encryption_keys(
    crypto_root: &Path,
    dkg_config: &InitialDkgConfig,
    node_id: NodeId,
) -> CryptoResult<EncryptionPublicKeyWithPop> {
    let config = config_with_dir_and_permissions(crypto_root);
    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    let crypto_component = CryptoComponent::new_with_fake_node_id(
        &config,
        Arc::new(registry_client),
        node_id,
        no_op_logger(),
    );
    crypto_component.generate_encryption_keys(dkg_config.get(), node_id)
}

/// Generates (forward-secure) NI-DKG dealing encryption key material given the
/// `node_id` of the node.
///
/// Stores the secret key in the key store at `crypto_root` and returns the
/// corresponding public key.
///
/// If the `crypto_root` directory does not exist, it is created with the
/// required permissions. If there exists no key store in `crypto_root`, a new
/// one is created.
pub fn generate_dkg_dealing_encryption_keys(crypto_root: &Path, node_id: NodeId) -> PublicKeyProto {
    let mut csp = csp_at_root(crypto_root);
    let (pubkey, pop) = csp
        .create_forward_secure_key_pair(AlgorithmId::NiDkg_Groth20_Bls12_381, node_id)
        .expect("Failed to generate DKG dealing encryption keys");
    ic_crypto_internal_csp::keygen::utils::dkg_dealing_encryption_pk_to_proto(pubkey, pop)
}

/// Obtains the node keys or generates them for the given `node_id` if they are
/// missing.
///
/// Retrieves the node's public keys from `crypto_root`, and checks their
/// consistency with the secret keys.
/// If there are no public keys in `crypto_root`, new keys are generated: the
/// secret parts are stored in the secret key store and the public parts are
/// stored in the public key store.
///
/// # Panics
///  * if public keys exist but are inconsistent with the secret keys.
///  * if an error occurs when accessing or generating the key.
///
/// # Notes
/// There are two variants of the function:
/// - `get_node_keys_or_generate_if_missing_for_node_id()` which takes an
///   additional `node_id` argument, and uses it when generating TLS keys.  This
///   is a temporary variant intended for the setup when node ids are generated
///   externally.
/// - `get_node_keys_or_generate_if_missing()` which derives `node_id` from the
///   retrieved or generated node signing public key, uses the derived `node_id`
///   when generating TLS keys, and returns `node_id` together with all the
///   generated public keys.  This is the variant to be used eventually by node
///   manager and other clients.
// TODO(CRP-356): remove the note above and the temporary variant
// `get_node_keys_or_generate_if_missing_for_node_id()`.
pub fn get_node_keys_or_generate_if_missing_for_node_id(
    crypto_root: &Path,
    node_id: NodeId,
) -> NodePublicKeys {
    match check_keys_locally(crypto_root) {
        Ok(None) => {
            // Generate new keys.
            let committee_signing_pk = generate_committee_signing_keys(crypto_root);
            let node_signing_pk = generate_node_signing_keys(crypto_root);
            let dkg_dealing_encryption_pk =
                generate_dkg_dealing_encryption_keys(crypto_root, node_id);
            let tls_certificate = generate_tls_keys(crypto_root, node_id);
            let node_pks = NodePublicKeys {
                version: 0,
                node_signing_pk: Some(node_signing_pk),
                committee_signing_pk: Some(committee_signing_pk),
                tls_certificate: Some(tls_certificate),
                dkg_dealing_encryption_pk: Some(dkg_dealing_encryption_pk),
            };
            public_key_store::store_node_public_keys(crypto_root, &node_pks)
                .unwrap_or_else(|_| panic!("Failed to store public key material"));
            // Re-check the generated keys.
            let stored_keys = check_keys_locally(crypto_root)
                .expect("Could not read generated keys.")
                .expect("Newly generated keys are inconsistent.");
            if stored_keys != node_pks {
                panic!("Generated keys differ from the stored ones.");
            }
            node_pks
        }
        Ok(Some(node_pks)) => node_pks,
        Err(e) => panic!(format!("Node contains inconsistent key material: {}", e)),
    }
}

/// Obtains the node keys or generates them if they are missing.
///
/// Please refer to the documentation of
/// `get_node_keys_or_generate_if_missing_for_node_id` for more details.
pub fn get_node_keys_or_generate_if_missing(crypto_root: &Path) -> (NodePublicKeys, NodeId) {
    match check_keys_locally(crypto_root) {
        Ok(None) => {
            // Generate new keys.
            let committee_signing_pk = generate_committee_signing_keys(crypto_root);
            let node_signing_pk = generate_node_signing_keys(crypto_root);
            let node_id = derive_node_id(&node_signing_pk);
            let dkg_dealing_encryption_pk =
                generate_dkg_dealing_encryption_keys(crypto_root, node_id);
            let tls_certificate = generate_tls_keys(crypto_root, node_id);
            let node_pks = NodePublicKeys {
                version: 0,
                node_signing_pk: Some(node_signing_pk),
                committee_signing_pk: Some(committee_signing_pk),
                tls_certificate: Some(tls_certificate),
                dkg_dealing_encryption_pk: Some(dkg_dealing_encryption_pk),
            };
            public_key_store::store_node_public_keys(crypto_root, &node_pks)
                .unwrap_or_else(|_| panic!("Failed to store public key material"));
            // Re-check the generated keys.
            let stored_keys = check_keys_locally(crypto_root)
                .expect("Could not read generated keys.")
                .expect("Newly generated keys are inconsistent.");
            if stored_keys != node_pks {
                panic!("Generated keys differ from the stored ones.");
            }
            (node_pks, node_id)
        }
        Ok(Some(node_pks)) => {
            let node_signing_pk = node_pks
                .node_signing_pk
                .as_ref()
                .expect("Missing node signing public key");
            let node_id = derive_node_id(node_signing_pk);
            (node_pks, node_id)
        }
        Err(e) => panic!("Node contains inconsistent key material: {}", e),
    }
}

pub(crate) fn derive_node_id(node_signing_pk: &PublicKeyProto) -> NodeId {
    let pk_bytes = ed25519::types::PublicKeyBytes::try_from(node_signing_pk)
        .expect("Corrupted node signing public key");
    let der_pk = ed25519::public_key_to_der(pk_bytes);
    NodeId::from(PrincipalId::new_self_authenticating(&der_pk))
}

fn generate_node_signing_keys(crypto_root: &Path) -> PublicKeyProto {
    let csp = csp_at_root(crypto_root);
    let generated = csp
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Could not generate node signing keys");
    match generated {
        (_key_id, CspPublicKey::Ed25519(pk)) => PublicKeyProto {
            algorithm: AlgorithmIdProto::Ed25519 as i32,
            key_value: pk.0.to_vec(),
            version: 0,
            proof_data: None,
        },
        _ => panic!("Unexpected types"),
    }
}

fn read_public_keys(crypto_root: &Path) -> CryptoResult<NodePublicKeys> {
    public_key_store::read_node_public_keys(crypto_root).map_err(|e| CryptoError::InvalidArgument {
        message: format!("Failed reading public keys: {:?}", e),
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
fn check_keys_locally(crypto_root: &Path) -> CryptoResult<Option<NodePublicKeys>> {
    let node_pks = match read_public_keys(crypto_root) {
        Ok(pks) => pks,
        Err(_) => return Ok(None),
    };
    if node_public_keys_are_empty(&node_pks) {
        return Ok(None);
    }
    let csp = csp_at_root(crypto_root);
    ensure_node_signing_key_is_set_up_locally(&node_pks.node_signing_pk, &csp)?;
    // TODO(CRP-622): add checks for other local keys.
    Ok(Some(node_pks))
}

fn node_public_keys_are_empty(node_pks: &NodePublicKeys) -> bool {
    node_pks.node_signing_pk.is_none()
        && node_pks.committee_signing_pk.is_none()
        && node_pks.dkg_dealing_encryption_pk.is_none()
        && node_pks.tls_certificate.is_none()
}

fn ensure_node_signing_key_is_set_up_locally(
    maybe_pk: &Option<PublicKeyProto>,
    csp: &dyn CryptoServiceProvider,
) -> CryptoResult<()> {
    let pk_proto = match maybe_pk {
        Some(pk) => Ok(pk.clone()),
        None => Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: None,
            internal_error: "No public key found.".to_string(),
        }),
    }?;
    if AlgorithmId::from(pk_proto.algorithm) != AlgorithmId::Ed25519 {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: None,
            internal_error: "Expected Ed25519 public key.".to_string(),
        });
    }
    let csp_key = CspPublicKey::try_from(pk_proto)?;
    let key_id = public_key_hash_as_key_id(&csp_key);
    if !csp.sks_contains(&key_id) {
        return Err(CryptoError::SecretKeyNotFound {
            algorithm: AlgorithmId::Ed25519,
            key_id,
        });
    }
    Ok(())
}

fn generate_committee_signing_keys(crypto_root: &Path) -> PublicKeyProto {
    let csp = csp_at_root(crypto_root);
    let generated = csp
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("Could not generate committee signing keys");
    match generated {
        (_key_id, CspPublicKey::MultiBls12_381(pk_bytes), CspPop::MultiBls12_381(pop_bytes)) => {
            PublicKeyProto {
                algorithm: AlgorithmIdProto::MultiBls12381 as i32,
                key_value: pk_bytes.0.to_vec(),
                version: 0,
                proof_data: Some(pop_bytes.0.to_vec()),
            }
        }
        _ => panic!("Unexpected types"),
    }
}

/// Generates TLS key material for a `node`.
///
/// Stores the secret key in the key store at `crypto_root` and uses it to
/// create a self-signed public key certificate. If there exists no key store
/// in `crypto_root` yet, a new key store is created.
///
///
/// The certificate's notAfter date indicates according to RFC5280 (section
/// 4.1.2.5; see https://tools.ietf.org/html/rfc5280#section-4.1.2.5) that the
/// certificate has no well-defined expiration date.
///
/// Returns the certificate.
fn generate_tls_keys(crypto_root: &Path, node: NodeId) -> X509PublicKeyCert {
    let mut csp = csp_at_root(crypto_root);
    csp.gen_tls_key_pair(node, "99991231235959Z")
}

pub(crate) fn csp_at_root(crypto_root: &Path) -> Csp<OsRng, ProtoSecretKeyStore> {
    let config = config_with_dir_and_permissions(crypto_root);
    // disable metrics
    Csp::new(&config, None, None)
}

fn config_with_dir_and_permissions(crypto_root: &Path) -> CryptoConfig {
    std::fs::create_dir_all(&crypto_root)
        .unwrap_or_else(|err| panic!("Failed to create crypto root directory: {}", err));
    let config = CryptoConfig::new(crypto_root.to_path_buf());
    CryptoConfig::set_dir_with_required_permission(&config.crypto_root)
        .expect("Could not setup crypto_root directory");
    config
}
