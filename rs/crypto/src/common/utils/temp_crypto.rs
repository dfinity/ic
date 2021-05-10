use crate::common::utils::generate_tls_keys;
use crate::common::utils::{
    generate_committee_signing_keys, generate_dkg_dealing_encryption_keys,
    generate_node_signing_keys,
};
use crate::{CryptoComponent, CryptoComponentFatClient};
use async_trait::async_trait;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::{public_key_store, CryptoServiceProvider, Csp};
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, Peer, TlsClientHandshakeError, TlsHandshake,
    TlsServerHandshakeError, TlsStream,
};
use ic_interfaces::crypto::{BasicSigVerifierByPublicKey, CanisterSigVerifier, Signable};
use ic_interfaces::registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::{BasicSigOf, CanisterSigOf, CryptoResult, UserPublicKey};
use ic_types::{NodeId, Randomness, RegistryVersion};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpStream;

#[cfg(test)]
mod tests;

/// A crypto component set up in a temporary directory. The directory is
/// automatically deleted when this component goes out of scope.
pub type TempCryptoComponent = TempCryptoComponentGeneric<Csp<OsRng, ProtoSecretKeyStore>>;

/// This struct combines the following two items:
/// * a crypto component whose state lives in a temporary directory
/// * a newly created temporary directory that contains the state
///
/// Combining these two items is useful for testing because the temporary
/// directory will exist for as long as the struct exists and is automatically
/// deleted once the struct goes out of scope.
pub struct TempCryptoComponentGeneric<C: CryptoServiceProvider> {
    crypto_component: CryptoComponentFatClient<C>,
    // the temp_dir is required even though it is never read, so the directory exists as long as
    // TempCryptoComponent exists.
    #[allow(dead_code)]
    temp_dir: TempDir,
}

impl<C: CryptoServiceProvider> Deref for TempCryptoComponentGeneric<C> {
    type Target = CryptoComponentFatClient<C>;

    fn deref(&self) -> &Self::Target {
        &self.crypto_component
    }
}

impl TempCryptoComponent {
    pub fn new(registry_client: Arc<dyn RegistryClient>, node_id: NodeId) -> Self {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_component = CryptoComponent::new_with_fake_node_id(
            &config,
            registry_client,
            node_id,
            no_op_logger(),
        );

        TempCryptoComponent {
            crypto_component,
            temp_dir,
        }
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_ni_dkg_dealing_encryption_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, PublicKeyProto) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_root = temp_dir.path().to_path_buf();
        let dkg_dealing_encryption_pubkey =
            generate_dkg_dealing_encryption_keys(&crypto_root, node_id);
        let node_pks = NodePublicKeys {
            version: 0,
            dkg_dealing_encryption_pk: Some(dkg_dealing_encryption_pubkey.to_owned()),
            ..Default::default()
        };
        public_key_store::store_node_public_keys(&crypto_root, &node_pks)
            .expect("Could not store node public keys.");
        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, dkg_dealing_encryption_pubkey)
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_tls_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, X509PublicKeyCert) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let tls_pubkey = generate_tls_keys(&temp_dir.path().to_path_buf(), node_id);

        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, tls_pubkey)
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_node_keys_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        selector: NodeKeysToGenerate,
    ) -> (Self, NodePublicKeys) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let temp_dir_path = std::path::PathBuf::from(
            temp_dir
                .path()
                .to_str()
                .expect("failed to convert path to string"),
        );

        let node_signing_pk = match selector.generate_node_signing_keys {
            true => Some(generate_node_signing_keys(&temp_dir_path)),
            false => None,
        };
        let committee_signing_pk = match selector.generate_committee_signing_keys {
            true => Some(generate_committee_signing_keys(&temp_dir_path)),
            false => None,
        };
        let dkg_dealing_encryption_pk = match selector.generate_dkg_dealing_encryption_keys {
            true => Some(generate_dkg_dealing_encryption_keys(
                &temp_dir_path,
                node_id,
            )),
            false => None,
        };
        let tls_certificate = match selector.generate_tls_keys_and_certificate {
            true => Some(generate_tls_keys(&temp_dir_path, node_id)),
            false => None,
        };

        let node_pubkeys = NodePublicKeys {
            version: 0,
            node_signing_pk,
            committee_signing_pk,
            dkg_dealing_encryption_pk,
            tls_certificate,
        };

        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, node_pubkeys)
    }

    fn new_with(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        config: &CryptoConfig,
        temp_dir: TempDir,
    ) -> Self {
        let crypto_component = CryptoComponent::new_with_fake_node_id(
            config,
            registry_client,
            node_id,
            no_op_logger(),
        );

        TempCryptoComponent {
            crypto_component,
            temp_dir,
        }
    }

    pub fn multiple_new(
        nodes: &[NodeId],
        registry: Arc<dyn RegistryClient>,
    ) -> BTreeMap<NodeId, TempCryptoComponent> {
        nodes
            .iter()
            .map(|node| {
                let temp_crypto = Self::new(Arc::clone(&registry), *node);
                (*node, temp_crypto)
            })
            .collect()
    }
}

/// Selects which keys should be generated for a `TempCryptoComponent`.
#[derive(Clone)]
pub struct NodeKeysToGenerate {
    pub generate_node_signing_keys: bool,
    pub generate_committee_signing_keys: bool,
    pub generate_dkg_dealing_encryption_keys: bool,
    pub generate_tls_keys_and_certificate: bool,
}

impl NodeKeysToGenerate {
    pub fn all() -> Self {
        NodeKeysToGenerate {
            generate_node_signing_keys: true,
            generate_committee_signing_keys: true,
            generate_dkg_dealing_encryption_keys: true,
            generate_tls_keys_and_certificate: true,
        }
    }

    pub fn none() -> Self {
        NodeKeysToGenerate {
            generate_node_signing_keys: false,
            generate_committee_signing_keys: false,
            generate_dkg_dealing_encryption_keys: false,
            generate_tls_keys_and_certificate: false,
        }
    }

    pub fn all_except_dkg_dealing_encryption_key() -> Self {
        NodeKeysToGenerate {
            generate_dkg_dealing_encryption_keys: false,
            ..Self::all()
        }
    }
}

impl TempCryptoComponentGeneric<Csp<ChaChaRng, ProtoSecretKeyStore>> {
    pub fn new_from_seed(
        seed: Randomness,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> Self {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let csprng = ChaChaRng::from_seed(seed.get());
        let crypto_component = CryptoComponentFatClient::new_with_rng_and_fake_node_id(
            csprng,
            &config,
            no_op_logger(),
            registry_client,
            node_id,
        );

        TempCryptoComponentGeneric {
            crypto_component,
            temp_dir,
        }
    }
}

impl<C: CryptoServiceProvider, T: Signable> BasicSigVerifierByPublicKey<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_basic_sig_by_public_key(signature, signed_bytes, public_key)
    }
}

impl<C: CryptoServiceProvider, T: Signable> CanisterSigVerifier<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component.verify_canister_sig(
            signature,
            signed_bytes,
            public_key,
            registry_version,
        )
    }
}

#[async_trait]
impl<C: CryptoServiceProvider + Send + Sync> TlsHandshake for TempCryptoComponentGeneric<C> {
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        allowed_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake(tcp_stream, allowed_clients, registry_version)
            .await
    }

    async fn perform_tls_server_handshake_temp_with_optional_client_auth(
        &self,
        tcp_stream: TcpStream,
        allowed_authenticating_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, Peer), TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake_temp_with_optional_client_auth(
                tcp_stream,
                allowed_authenticating_clients,
                registry_version,
            )
            .await
    }

    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsClientHandshakeError> {
        self.crypto_component
            .perform_tls_client_handshake(tcp_stream, server, registry_version)
            .await
    }
}
