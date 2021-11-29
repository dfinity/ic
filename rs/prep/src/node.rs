use std::{
    convert::TryFrom,
    io,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::{write_proto_to_file_raw, write_registry_entry};
use ic_crypto::utils::{
    generate_idkg_dealing_encryption_keys, get_node_keys_or_generate_if_missing,
};
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{
        connection_endpoint::Protocol, ConnectionEndpoint as pbConnectionEndpoint,
        FlowEndpoint as pbFlowEndpoint, NodeRecord as pbNodeRecord,
    },
};
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key};
use ic_types::{
    crypto::KeyPurpose,
    registry::connection_endpoint::{ConnectionEndpoint, ConnectionEndpointTryFromError},
    NodeId, PrincipalId, RegistryVersion,
};

const CRYPTO_DIR: &str = "crypto";
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
    pub idkg_mega_encryption_pubkey: PublicKey,
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
        let node_record = pbNodeRecord::try_from(self.node_config.clone())?;

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

        // add IDKG MEGa encryption public key for this node
        write_registry_entry(
            data_provider,
            self.node_path.as_path(),
            make_crypto_node_key(*node_id, KeyPurpose::IDkgMEGaEncryption).as_ref(),
            version,
            self.idkg_mega_encryption_pubkey.clone(),
        );

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

        // add IDKG MEGa encryption public key for this node
        write_proto_to_file_raw(
            "idkg_mega_encryption_key",
            self.idkg_mega_encryption_pubkey.clone(),
            self.node_path.as_path(),
        );

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
        std::fs::write(&path, output).map_err(|source| InitializeNodeError::SavingNodeId { source })
    }
}

/// Internal version of proto:registry.node.v1.NodeRecord
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeConfiguration {
    // Endpoints where the replica provides the Xnet interface
    pub xnet_api: Vec<ConnectionEndpoint>,

    /// Endpoints where the replica serves the public API interface
    pub public_api: Vec<ConnectionEndpoint>,

    /// Endpoints where the replica serves the private API interface
    pub private_api: Vec<ConnectionEndpoint>,

    /// Endpoint where the replica serves Prometheus-compatible metrics
    pub prometheus_metrics: Vec<ConnectionEndpoint>,

    /// The initial endpoint that P2P uses. The complete list of endpoints
    /// is generated by creating `p2p_num_flows` endpoints, and incrementing
    /// the port number by one for each.
    pub p2p_addr: ConnectionEndpoint,

    /// Number of flows to be setup for the node.
    pub p2p_num_flows: u32,

    /// The starting flow tag. This will determine flow tags for all the flows.
    /// The `flow_tag` values increase by one for each endpoint.
    pub p2p_start_flow_tag: u32,

    /// The principal id of the node operator that operates this node.
    pub node_operator_principal_id: Option<PrincipalId>,
}

#[derive(Error, Debug)]
pub enum NodeConfigurationTryFromError {
    #[error("could not parse connection endpoint: {source}")]
    ConnectionEndpointFailed {
        #[from]
        source: ConnectionEndpointTryFromError,
    },

    #[error("public_api endpoint has no entries")]
    EmptyPublicApiEndpoint,

    #[error("invalid protocol for P2P endpoint: {endpoint}")]
    InvalidP2pProtocol { endpoint: ConnectionEndpoint },
}

impl TryFrom<NodeConfiguration> for pbNodeRecord {
    type Error = NodeConfigurationTryFromError;

    fn try_from(node_configuration: NodeConfiguration) -> Result<Self, Self::Error> {
        let mut pb_node_record = pbNodeRecord::default();

        // p2p
        let p2p_base_endpoint = pbConnectionEndpoint::from(&node_configuration.p2p_addr);
        if p2p_base_endpoint.protocol() != Protocol::P2p1Tls13 {
            return Err(NodeConfigurationTryFromError::InvalidP2pProtocol {
                endpoint: node_configuration.p2p_addr,
            });
        }

        pb_node_record.p2p_flow_endpoints = (0..node_configuration.p2p_num_flows)
            .map(|i| pbFlowEndpoint {
                flow_tag: node_configuration.p2p_start_flow_tag + i,
                endpoint: Some(pbConnectionEndpoint {
                    port: p2p_base_endpoint.port + i,
                    ..p2p_base_endpoint.clone()
                }),
            })
            .collect();

        // public_api and related fields. This must have at least one value.
        // All values are used in the `public_api` field, and the first value
        // with `Protocol::Http1` is copied to the deprecated `http` field.
        let pb_public_api_endpoints = node_configuration
            .public_api
            .iter()
            .map(pbConnectionEndpoint::from)
            .collect::<Vec<_>>();

        if pb_public_api_endpoints.is_empty() {
            return Err(NodeConfigurationTryFromError::EmptyPublicApiEndpoint);
        }

        if let Some(endpoint) = pb_public_api_endpoints
            .iter()
            .find(|&endpoint| endpoint.protocol() == Protocol::Http1)
        {
            pb_node_record.http = Some(endpoint.clone());
        }

        pb_node_record.public_api = pb_public_api_endpoints;

        // private_api. This may be empty (in which case the replica would not
        // serve the private API on any address)
        pb_node_record.private_api = node_configuration
            .private_api
            .iter()
            .map(pbConnectionEndpoint::from)
            .collect::<Vec<_>>();

        // xnet and related field. All values are used in the `xnet_api`
        // field, and the first value is used, for backwards compatibility,
        // in the `xnet` field.
        pb_node_record.xnet_api = node_configuration
            .xnet_api
            .iter()
            .map(pbConnectionEndpoint::from)
            .collect::<Vec<_>>();
        if !node_configuration.xnet_api.is_empty() {
            pb_node_record.xnet = Some(pbConnectionEndpoint::from(&node_configuration.xnet_api[0]));
        }

        // prometheus_metrics and related fields. This may be empty. If it is
        // not then all values are used in the `prometheus_metrics` field and
        // the first value with `Protocol::Http1` is copied to the
        // deprecated `prometheus_metrics_http` field
        let pb_prometheus_metrics_endpoints = node_configuration
            .prometheus_metrics
            .iter()
            .map(pbConnectionEndpoint::from)
            .collect::<Vec<_>>();

        if let Some(endpoint) = pb_prometheus_metrics_endpoints
            .iter()
            .find(|&endpoint| endpoint.protocol() == Protocol::Http1)
        {
            pb_node_record.prometheus_metrics_http = Some(endpoint.clone());
        }

        pb_node_record.prometheus_metrics = pb_prometheus_metrics_endpoints;

        // node provider principal id
        pb_node_record.node_operator_id = node_configuration
            .node_operator_principal_id
            .map(|id| id.to_vec())
            .unwrap_or_else(Vec::new);

        // TODO: Check that none of the endpoints are listening on the same IP:port

        Ok(pb_node_record)
    }
}

#[derive(Error, Debug)]
pub enum InitializeNodeError {
    #[error("could not create node path: {path}: {source}")]
    CreateNodePathFailed { path: String, source: io::Error },
    #[error("saving node id failed: {source}")]
    SavingNodeId { source: io::Error },
    #[error("could not transform into pb struct: {source}")]
    CreatePbMessage {
        #[from]
        source: NodeConfigurationTryFromError,
    },
}

impl NodeConfiguration {
    /// Instantiates the secret key store in `node_path` and generates key-pairs
    /// for this node.
    pub fn initialize<P: AsRef<Path>>(
        self,
        node_path: P,
    ) -> Result<InitializedNode, InitializeNodeError> {
        let crypto_path = InitializedNode::build_crypto_path(node_path.as_ref());

        std::fs::create_dir_all(node_path.as_ref()).map_err(|source| {
            InitializeNodeError::CreateNodePathFailed {
                path: node_path.as_ref().to_string_lossy().to_string(),
                source,
            }
        })?;

        let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&crypto_path);
        // CRP-1273: Remove the following call when the encryption keys are generated
        // together with the rest of the node keys.
        let idkg_mega_encryption_pubkey = generate_idkg_dealing_encryption_keys(&crypto_path);

        Ok(InitializedNode {
            node_id,
            pk_committee_signing: node_pks.committee_signing_pk.unwrap(),
            pk_node_signing: node_pks.node_signing_pk.unwrap(),
            tls_certificate: node_pks.tls_certificate.unwrap(),
            node_path: PathBuf::from(node_path.as_ref()),
            node_config: self,
            dkg_dealing_encryption_pubkey: node_pks.dkg_dealing_encryption_pk.unwrap(),
            idkg_mega_encryption_pubkey,
        })
    }
}

#[cfg(test)]
mod node_configuration {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn into_proto_http() {
        let node_configuration = NodeConfiguration {
            xnet_api: vec!["http://1.2.3.4:8080".parse().unwrap()],
            public_api: vec!["http://1.2.3.4:8081".parse().unwrap()],
            private_api: vec!["http://1.2.3.4:8082".parse().unwrap()],
            prometheus_metrics: vec!["http://1.2.3.4:9090".parse().unwrap()],
            p2p_addr: "org.internetcomputer.p2p1://1.2.3.4:1234".parse().unwrap(),
            p2p_num_flows: 2,
            p2p_start_flow_tag: 12,
            node_operator_principal_id: None,
        };

        let got = pbNodeRecord::try_from(node_configuration).unwrap();

        let want = pbNodeRecord {
            node_operator_id: vec![],
            p2p_flow_endpoints: vec![
                pbFlowEndpoint {
                    flow_tag: 12, // Tag starts at 12
                    endpoint: Some(pbConnectionEndpoint {
                        ip_addr: "1.2.3.4".to_string(),
                        port: 1234,
                        protocol: Protocol::P2p1Tls13 as i32,
                    }),
                },
                pbFlowEndpoint {
                    flow_tag: 13, // And is incremented by one...
                    endpoint: Some(pbConnectionEndpoint {
                        ip_addr: "1.2.3.4".to_string(),
                        port: 1235, // ... as is the port number
                        protocol: Protocol::P2p1Tls13 as i32,
                    }),
                },
            ],
            public_api: vec![pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8081,
                protocol: Protocol::Http1 as i32,
            }],
            private_api: vec![pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8082,
                protocol: Protocol::Http1 as i32,
            }],
            prometheus_metrics: vec![pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 9090,
                protocol: Protocol::Http1 as i32,
            }],
            xnet_api: vec![pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8080,
                protocol: Protocol::Http1 as i32,
            }],
            // Deprecated fields should also have values
            http: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8081,
                protocol: Protocol::Http1 as i32,
            }),
            prometheus_metrics_http: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 9090,
                protocol: Protocol::Http1 as i32,
            }),
            xnet: Some(pbConnectionEndpoint {
                ip_addr: "1.2.3.4".to_string(),
                port: 8080,
                protocol: Protocol::Http1 as i32,
            }),
        };

        assert_eq!(got, want);
    }
}
