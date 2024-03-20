use crate::api::e2e::testnet::{Testnet, TestnetT};
use crate::api::handle::{Ic, Node, Subnet};
use canister_test::*;
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_crypto_ed25519::{PrivateKey, PublicKey};
use ic_types::{NodeId, SubnetId};
use std::sync::Arc;
use url::Url;

/// Handle for a testnet node.
pub struct NodeHandle {
    id: NodeId,
    ic_instance: Arc<IcInnerHandle>,
}

impl NodeHandle {
    pub(crate) fn new(id: NodeId, ic_instance: Arc<IcInnerHandle>) -> Self {
        Self { id, ic_instance }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }
}

impl Node for NodeHandle {
    fn api(&self) -> Runtime {
        // We use the anonymous user for now.
        Runtime::Remote(RemoteTestRuntime {
            agent: Agent::new_with_client(
                self.ic_instance.agent_client.clone(),
                self.ic_instance.node_api_url(self.id),
                Sender::from_keypair(&self.ic_instance.caller_principal.0),
            ),
            effective_canister_id: self.ic_instance.testnet.effective_canister_id(self.id),
        })
    }
}

/// Handle for a testnet subnet.
pub struct SubnetHandle {
    id: SubnetId,
    nodes: Vec<NodeId>,
    ic_instance: Arc<IcInnerHandle>,
}

impl SubnetHandle {
    pub(crate) fn new(id: SubnetId, nodes: Vec<NodeId>, ic_instance: Arc<IcInnerHandle>) -> Self {
        Self {
            id,
            nodes,
            ic_instance,
        }
    }

    pub fn id(&self) -> SubnetId {
        self.id
    }
}

impl Subnet for SubnetHandle {
    fn node_by_idx(&self, idx: usize) -> Box<dyn Node> {
        Box::new(NodeHandle::new(self.nodes[idx], self.ic_instance.clone()))
    }

    fn node(&self, id: NodeId) -> Box<dyn Node> {
        assert!(self.nodes.contains(&id));
        Box::new(NodeHandle::new(id, self.ic_instance.clone()))
    }
}

/// Handle for a testnet.
pub struct IcHandle {
    inner: Arc<IcInnerHandle>,
}

impl IcHandle {
    /// Creates an IC handle wrapping the given testnet configuration.
    pub fn from_testnet(testnet: Testnet) -> Self {
        let inner = Arc::new(IcInnerHandle::from_testnet(testnet));
        Self { inner }
    }

    /// Creates an IC handle wrapping the given testnet configuration and the
    /// keypair corresponding to the PEM encoded secret key file located at
    /// `key_file`.
    pub fn from_testnet_with_principal_from_file(testnet: Testnet, key_file: String) -> Self {
        let inner = Arc::new(IcInnerHandle::from_testnet_with_principal_from_file(
            testnet, key_file,
        ));
        Self { inner }
    }
}

impl Ic for IcHandle {
    fn subnet_ids(&self) -> Vec<SubnetId> {
        self.inner.testnet.subnet_ids()
    }

    fn subnet(&self, id: SubnetId) -> Box<dyn Subnet> {
        Box::new(SubnetHandle::new(
            id,
            self.inner.testnet.node_ids(id),
            self.inner.clone(),
        ))
    }

    fn route(&self, principal_id: PrincipalId) -> Option<SubnetId> {
        self.inner.testnet.route(principal_id)
    }

    fn get_principal(&self) -> Option<PrincipalId> {
        Some(self.inner.caller_principal.1)
    }
}

/// A testnet-based internet computer instance.
pub(crate) struct IcInnerHandle {
    pub(crate) testnet: Testnet,

    // Retain the same agent client for all http connections.
    agent_client: HttpClient,

    // The keypair corresponding to the principal that is used for calling into the IC
    caller_principal: (ic_canister_client::Ed25519KeyPair, PrincipalId),
}

impl IcInnerHandle {
    pub fn from_testnet(testnet: Testnet) -> Self {
        Self::from_testnet_with_principal(testnet, *ic_test_identity::TEST_IDENTITY_KEYPAIR)
    }

    fn from_testnet_with_principal(
        testnet: Testnet,
        caller_principal: ic_canister_client::Ed25519KeyPair,
    ) -> Self {
        let principal_id = PrincipalId::new_self_authenticating(
            &PublicKey::deserialize_raw(&caller_principal.public_key)
                .expect("Invalid public key")
                .serialize_rfc8410_der(),
        );
        Self {
            testnet,
            agent_client: HttpClient::new(),
            caller_principal: (caller_principal, principal_id),
        }
    }

    pub fn from_testnet_with_principal_from_file(testnet: Testnet, key_file: String) -> Self {
        let key_file = std::fs::read_to_string(key_file.clone())
            .unwrap_or_else(|_| panic!("Failed to load principal key from file {}", key_file));
        let secret_key = PrivateKey::deserialize_pkcs8_pem(&key_file).expect("Invalid secret key.");

        let public_key = secret_key.public_key();

        Self::from_testnet_with_principal(
            testnet,
            ic_canister_client::Ed25519KeyPair {
                secret_key: secret_key.serialize_raw(),
                public_key: public_key.serialize_raw(),
            },
        )
    }

    /// Url for the Public Api of node `node_id`.
    pub fn node_api_url(&self, node_id: NodeId) -> Url {
        self.testnet.node_api_url(node_id)
    }
}
