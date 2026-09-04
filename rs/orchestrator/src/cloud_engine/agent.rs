//! Construction of the `ic-agent`s used to reach the engine management canister
//! and the engine's own operator canister.

use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registration::NodeRegistrationCrypto,
    registry_helper::RegistryHelper,
    signer::NodeSender,
    utils::nns_root_key_der_from_registry,
};
use ic_agent::{Agent, Identity, export::reqwest, identity::AnonymousIdentity};
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::{api_boundary_node::ApiBoundaryNodeRegistry, node::NodeRegistry};
use ic_types::{RegistryVersion, messages::MessageId};
use rand::prelude::*;
use std::sync::Arc;
use url::Url;

/// Builds the agents that [`super::CloudEngineManager`] talks to canisters with.
///
/// Query signature verification is enabled on every agent, so all of them need
/// the NNS root key. Unlike [`crate::registration`], a missing root key is an
/// error here rather than a fallback to the key hard-coded in `ic-agent`:
/// falling back would make every call fail outside mainnet, which is harder to
/// diagnose than refusing to build the agent.
pub(super) struct AgentFactory {
    registry: Arc<RegistryHelper>,
    crypto: Arc<dyn NodeRegistrationCrypto>,
    replica_url: Url,
    operator_agent: Option<Agent>,
    logger: ReplicaLogger,
}

impl AgentFactory {
    pub(super) fn new(
        registry: Arc<RegistryHelper>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        replica_url: Url,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            crypto,
            replica_url,
            operator_agent: None,
            logger,
        }
    }

    /// An anonymous agent aimed at a randomly chosen API boundary node. Used
    /// for the engine management canister, whose lookup endpoint is a public
    /// query and lives on a regular subnet: a cloud engine node has to go
    /// through the public API as regular nodes do not whitelist them.
    pub(super) fn anonymous_via_api_boundary_node(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Agent> {
        let url = self.random_api_boundary_node_url(version)?;

        self.build(url, AnonymousIdentity, version, None)
    }

    fn random_api_boundary_node_url(&self, version: RegistryVersion) -> OrchestratorResult<Url> {
        let registry_client = self.registry.get_registry_client();
        let mut node_ids = registry_client
            .get_api_boundary_node_ids(version)
            .map_err(|err| {
                OrchestratorError::cloud_engine_error(format!(
                    "could not list the API boundary nodes: {err:?}"
                ))
            })?;

        node_ids.shuffle(&mut thread_rng());
        node_ids
            .iter()
            .find_map(|node_id| {
                let domain = registry_client
                    .get_node_record(*node_id, version)
                    .ok()??
                    .domain?;
                Url::parse(&format!("https://{domain}/"))
                    .inspect_err(|err| {
                        warn!(
                            self.logger,
                            "Ignoring the malformed API boundary node domain '{}': {}", domain, err
                        )
                    })
                    .ok()
            })
            .ok_or_else(|| {
                OrchestratorError::cloud_engine_error(
                    "no usable API boundary node found in the registry",
                )
            })
    }

    /// An agent aimed at this node's own replica and signing as this node. The
    /// operator canister only serves the nodes of its own engine, so the calls
    /// have to be authenticated with the node signing key.
    ///
    /// Built once and then reused: everything it depends on is stable.
    pub(super) fn node_signed_to_local_replica(
        &mut self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Agent> {
        if let Some(agent) = &self.operator_agent {
            return Ok(agent.clone());
        }

        // Reading the public keys is an RPC to the CSP vault that blocks
        // on `block_on` internally.
        let crypto = Arc::clone(&self.crypto);
        #[allow(clippy::disallowed_methods)]
        let public_keys = tokio::task::block_in_place(|| crypto.current_node_public_keys());
        let public_key = public_keys
            .map_err(|err| {
                OrchestratorError::cloud_engine_error(format!(
                    "could not read the current node public keys: {err}"
                ))
            })?
            .node_signing_public_key
            .ok_or_else(|| {
                OrchestratorError::cloud_engine_error("the node signing public key is missing")
            })?;

        let crypto = Arc::clone(&self.crypto);
        let sign = move |message: &MessageId| {
            // `sign_basic` blocks on an RPC to the crypto service, which panics
            // when called from an async context without this.
            #[allow(clippy::disallowed_methods)]
            tokio::task::block_in_place(|| {
                crypto
                    .sign_basic(message)
                    .map(|signature| signature.get().0)
                    .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
            })
        };
        let identity = NodeSender::new(public_key, Arc::new(sign))
            .map_err(OrchestratorError::cloud_engine_error)?;

        let agent = self.build(self.replica_url.clone(), identity, version, None)?;
        self.operator_agent = Some(agent.clone());

        Ok(agent)
    }

    fn build<I: Identity + 'static>(
        &self,
        url: Url,
        identity: I,
        version: RegistryVersion,
        client: Option<reqwest::Client>,
    ) -> OrchestratorResult<Agent> {
        let mut builder = Agent::builder()
            .with_url(url)
            .with_identity(identity)
            // On by default; set explicitly so the decision survives an
            // upstream default change.
            .with_verify_query_signatures(true);
        if let Some(client) = client {
            builder = builder.with_http_client(client);
        }

        let agent = builder.build().map_err(|err| {
            OrchestratorError::cloud_engine_error(format!("could not build an agent: {err}"))
        })?;
        let root_key = nns_root_key_der_from_registry(self.registry.get_registry_client(), version)
            .map_err(OrchestratorError::cloud_engine_error)?;
        agent.set_root_key(root_key);

        Ok(agent)
    }
}
