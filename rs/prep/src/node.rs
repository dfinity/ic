use std::{
    fmt::Display,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use ic_interfaces::{
    certification::{Verifier, VerifierError},
    validation::ValidationResult,
};
use ic_state_manager::StateManagerImpl;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::{write_proto_to_file_raw, write_registry_entry};
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_interfaces_state_manager::{CertificationScope, StateHashError, StateManager};
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{ConnectionEndpoint as pbConnectionEndpoint, NodeRecord as pbNodeRecord},
};
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    consensus::certification::Certification, crypto::KeyPurpose, Height, NodeId, PrincipalId,
    RegistryVersion, SubnetId,
};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;

const CRYPTO_DIR: &str = "crypto";
const STATE_DIR: &str = "state";

pub type SubnetIndex = u64;
pub type NodeIndex = u64;

#[derive(Clone, Debug)]
pub struct InitializedNode {
    pub node_id: NodeId,

    /// The committee signing public key stored in the registry for this node.
    pub pk_committee_signing: PublicKey,

    /// The node signing public key that is stored in the registry.
    pub pk_node_signing: PublicKey,

    /// The TLS certificate of this node.
    pub tls_certificate: X509PublicKeyCert,

    /// Directory of the secret key store for this node.
    pub node_path: PathBuf,

    pub node_config: NodeConfiguration,

    /// The NIDKG dealing encryption public key for this node.
    pub dkg_dealing_encryption_pubkey: PublicKey,

    /// The IDKG MEGa encryption public key for this node.
    /// TODO(NNS1-1197): Remove option when nodes are provisioned for threshold ECDSA subnets
    pub idkg_mega_encryption_pubkey: Option<PublicKey>,
}

impl InitializedNode {
    pub fn crypto_path(&self) -> PathBuf {
        Self::build_crypto_path(&self.node_path)
    }

    pub fn build_crypto_path<P: AsRef<Path>>(node_path: P) -> PathBuf {
        PathBuf::from(node_path.as_ref()).join(CRYPTO_DIR)
    }

    pub fn state_path(&self) -> PathBuf {
        self.node_path.join(STATE_DIR)
    }

    pub fn write_registry_entries(
        &self,
        data_provider: &ProtoRegistryDataProvider,
        version: RegistryVersion,
    ) -> Result<(), InitializeNodeError> {
        let node_id = &self.node_id;
        let node_record = pbNodeRecord::from(self.node_config.clone());

        // add node transport information
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_node_record_key(*node_id).as_ref(),
            version,
            node_record,
        );

        // add committee signing key for this node
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_crypto_node_key(*node_id, KeyPurpose::CommitteeSigning).as_ref(),
            version,
            self.pk_committee_signing.clone(),
        );

        // add node signing key for this node
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_crypto_node_key(*node_id, KeyPurpose::NodeSigning).as_ref(),
            version,
            self.pk_node_signing.clone(),
        );

        // add NIDKG dealing encryption public key for this node
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_crypto_node_key(*node_id, KeyPurpose::DkgDealingEncryption).as_ref(),
            version,
            self.dkg_dealing_encryption_pubkey.clone(),
        );

        // TODO(NNS1-1197): Refactor this when nodes are provisioned for threshold ECDSA subnets
        // add IDKG MEGa encryption public key for this node
        if let Some(idkg_mega_encryption_pubkey) = self.idkg_mega_encryption_pubkey.as_ref() {
            write_registry_entry(
                data_provider,
                self.node_path.as_path(),
                make_crypto_node_key(*node_id, KeyPurpose::IDkgMEGaEncryption).as_ref(),
                version,
                idkg_mega_encryption_pubkey.clone(),
            );
        }

        // add TLS certificate for this node
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_crypto_tls_cert_key(*node_id).as_ref(),
            version,
            self.tls_certificate.clone(),
        );

        // In addition to the above, we write the keys once more,
        // this time with different names. It is so that ic-admin
        // could reference the right files when submitting a request
        // to add a node via the NNS node canister. Since we execute
        // that call from the command line, there we don't know KeyPurpose
        // values.

        // add committee signing key for this node
        write_proto_to_file_raw(
            "committee_signing_key",
            self.pk_committee_signing.clone(),
            self.node_path.as_path(),
        );

        // add node signing key for this node
        write_proto_to_file_raw(
            "node_signing_key",
            self.pk_node_signing.clone(),
            self.node_path.as_path(),
        );

        // add NIDKG dealing encryption public key for this node
        write_proto_to_file_raw(
            "ni_dkg_dealing_encryption_key",
            self.dkg_dealing_encryption_pubkey.clone(),
            self.node_path.as_path(),
        );

        // TODO(NNS1-1197): Refactor this when nodes are provisioned for threshold ECDSA subnets
        // add IDKG MEGa encryption public key for this node
        if let Some(idkg_mega_encryption_pubkey) = self.idkg_mega_encryption_pubkey.as_ref() {
            write_proto_to_file_raw(
                "idkg_mega_encryption_key",
                idkg_mega_encryption_pubkey.clone(),
                self.node_path.as_path(),
            )
        }

        // add TLS certificate for this node
        write_proto_to_file_raw(
            "transport_tls_certificate",
            self.tls_certificate.clone(),
            self.node_path.as_path(),
        );

        // Finally, output the derived node_id to a file.
        // This is helpful in the ansible scripts, where some actions need to know
        // nodes' ID, for example, to set up a subnet via NNS.
        let path = PathBuf::from(self.node_path.as_path()).join("derived_node_id");
        let output = format!("{}", node_id);
        std::fs::write(path, output).map_err(|source| InitializeNodeError::SavingNodeId { source })
    }

    /// Creates an empty initial state and returns state hash.
    /// This is needed if the subnet should start from a height other than 0.
    pub(crate) fn generate_initial_state(
        &self,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
    ) -> Vec<u8> {
        struct FakeVerifier;
        impl Verifier for FakeVerifier {
            fn validate(
                &self,
                _: SubnetId,
                _: &Certification,
                _: RegistryVersion,
            ) -> ValidationResult<VerifierError> {
                Ok(())
            }
        }

        let state_path = self.state_path();
        let config = ic_config::state_manager::Config::new(state_path);
        let state_manager = StateManagerImpl::new(
            Arc::new(FakeVerifier),
            subnet_id,
            subnet_type,
            ic_logger::replica_logger::no_op_logger(),
            &ic_metrics::MetricsRegistry::new(),
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, Height::new(1), CertificationScope::Full, None);

        loop {
            match state_manager.get_state_hash_at(Height::new(1)) {
                Ok(state_hash) => break state_hash.get().0,
                Err(StateHashError::Transient(_)) => (),
                Err(StateHashError::Permanent(err)) => {
                    panic!("Failed to generate initial state {:?}", err)
                }
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Node index
    pub idx: u64,

    /// Index of the subnet to add the node to. If the index is not set, the key
    /// material and registry entries for the node will be generated, but the
    /// node will not be added to a subnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_idx: Option<u64>,

    #[serde(flatten)]
    pub config: NodeConfiguration,
}

impl Node {
    pub fn from_json5_without_braces(s: &str) -> Result<Self, json5::Error> {
        json5::from_str(&format!("{{ {} }}", s))
    }
}

impl Display for Node {
    /// Displays the node in a format that will be accepted by the `--node`
    /// flag.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = json5::to_string(self).map_err(|_| std::fmt::Error)?;

        // Clear out the outermost braces.
        let stripped = &json[1..json.len() - 1];

        write!(f, "{}", stripped)
    }
}

/// Structured definition of a node provided by the `--node` flag.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfiguration {
    // Endpoints where the replica provides the Xnet interface
    pub xnet_api: SocketAddr,

    /// Endpoints where the replica serves the public API interface
    pub public_api: SocketAddr,

    /// The principal id of the node operator that operates this node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_operator_principal_id: Option<PrincipalId>,

    /// If set, the specified secret key store will be used. Otherwise, a new
    /// one will be created when initializing the internet computer.
    ///
    /// Creating the secret key store ahead of time allows for the node id to be
    /// set before all other configuration values must be specified (such as ip
    /// address, etc.)
    ///
    /// **Note**: The path of the secret key store will be *copied* to a new
    /// directory chosen by ic-prep.
    #[serde(skip_serializing, skip_deserializing)]
    pub secret_key_store: Option<NodeSecretKeyStore>,
}

impl From<NodeConfiguration> for pbNodeRecord {
    fn from(node_configuration: NodeConfiguration) -> Self {
        pbNodeRecord {
            http: Some(pbConnectionEndpoint {
                ip_addr: node_configuration.public_api.ip().to_string(),
                port: node_configuration.public_api.port() as u32,
            }),
            xnet: Some(pbConnectionEndpoint {
                ip_addr: node_configuration.xnet_api.ip().to_string(),
                port: node_configuration.xnet_api.port() as u32,
            }),
            node_operator_id: node_configuration
                .node_operator_principal_id
                .map(|id| id.to_vec())
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum InitializeNodeError {
    #[error("could not create node path: {path}: {source}")]
    CreateNodePathFailed { path: String, source: io::Error },
    #[error("saving node id failed: {source}")]
    SavingNodeId { source: io::Error },
    #[error("copying secret key store failed: {source}")]
    CouldNotCopySks {
        #[from]
        source: fs_extra::error::Error,
    },
}

impl NodeConfiguration {
    /// Instantiates the secret key store in `node_path` and generates key-pairs
    /// for this node.
    pub fn initialize<P: AsRef<Path>>(
        self,
        node_path: P,
    ) -> Result<InitializedNode, InitializeNodeError> {
        std::fs::create_dir_all(node_path.as_ref()).map_err(|source| {
            InitializeNodeError::CreateNodePathFailed {
                path: node_path.as_ref().to_string_lossy().to_string(),
                source,
            }
        })?;
        let crypto_path = InitializedNode::build_crypto_path(node_path.as_ref());
        let sks = if let Some(sks) = self.secret_key_store.clone() {
            let mut options = fs_extra::dir::CopyOptions::new();
            options.copy_inside = true;
            fs_extra::dir::copy(sks.path.as_path(), crypto_path.as_path(), &options)
                .map_err(|e| InitializeNodeError::CouldNotCopySks { source: e })?;
            NodeSecretKeyStore::set_permissions(&crypto_path)?;
            sks
        } else {
            NodeSecretKeyStore::new(crypto_path)?
        };

        let node_id = sks.node_id;
        Ok(InitializedNode {
            node_id,
            pk_committee_signing: sks.node_pks.committee_signing_key().clone(),
            pk_node_signing: sks.node_pks.node_signing_key().clone(),
            tls_certificate: sks.node_pks.tls_certificate().clone(),
            node_path: PathBuf::from(node_path.as_ref()),
            node_config: self,
            dkg_dealing_encryption_pubkey: sks.node_pks.dkg_dealing_encryption_key().clone(),
            idkg_mega_encryption_pubkey: Some(sks.node_pks.idkg_dealing_encryption_key().clone()),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
pub struct NodeSecretKeyStore {
    pub node_id: NodeId,
    pub node_pks: ValidNodePublicKeys,
    pub path: PathBuf,
}

impl NodeSecretKeyStore {
    /// Create a secret key store for a node at the path `path`.
    ///
    /// If `path` or any of its parent directories do not exist, they will be
    /// created.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, InitializeNodeError> {
        let path = PathBuf::from(path.as_ref());
        std::fs::create_dir_all(&path).map_err(|source| {
            InitializeNodeError::CreateNodePathFailed {
                path: path.to_string_lossy().to_string(),
                source,
            }
        })?;
        Self::set_permissions(&path)?;
        let config = CryptoConfig::new(path.clone());
        let node_pks =
            generate_node_keys_once(&config, None).expect("error generating node public keys");
        let node_id = node_pks.node_id();

        Ok(Self {
            node_id,
            node_pks,
            path,
        })
    }

    /// Sets the permission bits of the given path as expected by the crypto component.
    fn set_permissions<P: AsRef<Path>>(path: P) -> Result<(), InitializeNodeError> {
        // Set permissions required for `generate_node_keys_once`
        std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o750)).map_err(
            |source| InitializeNodeError::CreateNodePathFailed {
                path: path.as_ref().to_string_lossy().to_string(),
                source,
            },
        )
    }
}

#[cfg(test)]
mod node_configuration {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn into_proto_http() {
        let node_configuration = NodeConfiguration {
            xnet_api: SocketAddr::from_str("1.2.3.4:8080").unwrap(),
            public_api: SocketAddr::from_str("1.2.3.4:8081").unwrap(),
            node_operator_principal_id: None,
            secret_key_store: None,
        };

        let got = pbNodeRecord::from(node_configuration);

        let want = pbNodeRecord {
            node_operator_id: vec![],
            http: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8081,
            }),
            xnet: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8080,
            }),
            hostos_version_id: None,
            chip_id: None,
            public_ipv4_config: None,
            domain: None,
        };

        assert_eq!(got, want);
    }
}
