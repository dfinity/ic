use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Result;
use thiserror::Error;

use crate::util::{write_proto_to_file_raw, write_registry_entry};
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{
        ConnectionEndpoint as pbConnectionEndpoint, FlowEndpoint as pbFlowEndpoint,
        NodeRecord as pbNodeRecord,
    },
};
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::{crypto::KeyPurpose, NodeId, PrincipalId, RegistryVersion};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;

const CRYPTO_DIR: &str = "crypto";
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
}

/// Internal version of proto:registry.node.v1.NodeRecord
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeConfiguration {
    // Endpoints where the replica provides the Xnet interface
    pub xnet_api: SocketAddr,

    /// Endpoints where the replica serves the public API interface
    pub public_api: SocketAddr,

    /// The initial endpoint that P2P uses.
    pub p2p_addr: SocketAddr,

    /// The principal id of the node operator that operates this node.
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
    pub secret_key_store: Option<NodeSecretKeyStore>,

    /// The SEV-SNP chip_identifier for this node.
    pub chip_id: Vec<u8>,
}

impl From<NodeConfiguration> for pbNodeRecord {
    fn from(node_configuration: NodeConfiguration) -> Self {
        let mut pb_node_record = pbNodeRecord::default();

        // p2p
        let p2p_base_endpoint = pbConnectionEndpoint {
            ip_addr: node_configuration.p2p_addr.ip().to_string(),
            port: node_configuration.p2p_addr.port() as u32,
        };
        pb_node_record.p2p_flow_endpoints = vec![pbFlowEndpoint {
            endpoint: Some(p2p_base_endpoint),
        }];
        pb_node_record.http = Some(pbConnectionEndpoint {
            ip_addr: node_configuration.public_api.ip().to_string(),
            port: node_configuration.public_api.port() as u32,
        });
        pb_node_record.xnet = Some(pbConnectionEndpoint {
            ip_addr: node_configuration.xnet_api.ip().to_string(),
            port: node_configuration.xnet_api.port() as u32,
        });

        // node provider principal id
        pb_node_record.node_operator_id = node_configuration
            .node_operator_principal_id
            .map(|id| id.to_vec())
            .unwrap_or_else(Vec::new);

        pb_node_record
    }
}

#[derive(Error, Debug)]
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
            p2p_addr: SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            node_operator_principal_id: None,
            secret_key_store: None,
            chip_id: vec![],
        };

        let got = pbNodeRecord::try_from(node_configuration).unwrap();

        let want = pbNodeRecord {
            node_operator_id: vec![],
            p2p_flow_endpoints: vec![pbFlowEndpoint {
                endpoint: Some(pbConnectionEndpoint {
                    ip_addr: "1.2.3.4".to_string(),
                    port: 1234,
                }),
            }],
            http: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8081,
            }),
            xnet: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8080,
            }),
            chip_id: vec![],
            hostos_version_id: None,
        };

        assert_eq!(got, want);
    }
}
