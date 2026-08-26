//! Construction of the `ic-agent`s used to reach the engine management canister
//! and the engine's own operator canister.

use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registration::NodeRegistrationCrypto,
    registry_helper::RegistryHelper,
    signer::NodeSender,
    utils::https_endpoint_to_url,
};
use ic_agent::{Agent, Identity, export::reqwest, identity::AnonymousIdentity};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::{crypto::CryptoRegistry, subnet::SubnetTransportRegistry};
use ic_types::{RegistryVersion, SubnetId, messages::MessageId};
use rand::prelude::*;
use std::{sync::Arc, time::Duration};
use url::Url;

/// Matches the default timeout of `ic-agent`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(360);

/// Builds the agents that [`super::CloudEngineManager`] talks to canisters with.
///
/// Query signature verification is enabled on every agent, so all of them need
/// the NNS root key. Unlike [`crate::registration`], a missing root key is an
/// error here rather than a fallback to the key hard-coded in `ic-agent`:
/// falling back would make every call fail outside mainnet, which is harder to
/// diagnose than refusing to build the agent.
pub(super) struct AgentFactory {
    registry: Arc<RegistryHelper>,
    tls_config: Arc<dyn TlsConfig>,
    crypto: Arc<dyn NodeRegistrationCrypto>,
    replica_url: Url,
    logger: ReplicaLogger,
}

impl AgentFactory {
    pub(super) fn new(
        registry: Arc<RegistryHelper>,
        tls_config: Arc<dyn TlsConfig>,
        crypto: Arc<dyn NodeRegistrationCrypto>,
        replica_url: Url,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            tls_config,
            crypto,
            replica_url,
            logger,
        }
    }

    /// An anonymous agent aimed at a randomly chosen node of `subnet_id`, using
    /// node-to-node TLS. Used for the engine management canister, whose lookup
    /// endpoint is a public query and lives on a different subnet.
    pub(super) fn anonymous_to_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> OrchestratorResult<Agent> {
        let (url, tls_config) = self.random_node_of_subnet(subnet_id, version)?;
        let client = reqwest::ClientBuilder::default()
            .use_preconfigured_tls(tls_config)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|err| {
                OrchestratorError::cloud_engine_error(format!(
                    "could not build an HTTP client for subnet {subnet_id}: {err}"
                ))
            })?;

        self.build(url, AnonymousIdentity, version, Some(client))
    }

    /// An agent aimed at this node's own replica and signing as this node. The
    /// operator canister only serves the nodes of its own engine, so the calls
    /// have to be authenticated with the node signing key.
    pub(super) fn node_signed_to_local_replica(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Agent> {
        let public_key = self
            .crypto
            .current_node_public_keys()
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

        self.build(self.replica_url.clone(), identity, version, None)
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
        agent.set_root_key(self.nns_root_key_der(version)?);

        Ok(agent)
    }

    /// The NNS root key, in DER, as recorded in the registry.
    fn nns_root_key_der(&self, version: RegistryVersion) -> OrchestratorResult<Vec<u8>> {
        let root_subnet_id = self.registry.get_root_subnet_id(version)?;
        let public_key = self
            .registry
            .get_registry_client()
            .get_threshold_signing_public_key_for_subnet(root_subnet_id, version)?
            .ok_or_else(|| {
                OrchestratorError::cloud_engine_error("the NNS public key is not in the registry")
            })?;

        threshold_sig_public_key_to_der(public_key).map_err(|err| {
            OrchestratorError::cloud_engine_error(format!(
                "could not DER-encode the NNS public key: {err:?}"
            ))
        })
    }

    /// Picks a random node of `subnet_id` and returns its URL together with a
    /// TLS configuration that authenticates it as that node.
    fn random_node_of_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> OrchestratorResult<(Url, rustls::ClientConfig)> {
        let node_records = self
            .registry
            .get_registry_client()
            .get_subnet_node_records(subnet_id, version)?
            .ok_or_else(|| OrchestratorError::SubnetMissingError(subnet_id, version))?;

        let mut candidates = node_records
            .iter()
            .filter_map(|(node_id, node_record)| {
                let url = https_endpoint_to_url(node_record.http.as_ref()?)
                    .inspect_err(|err| warn!(self.logger, "{}", err))
                    .ok()?;
                let tls_config = self
                    .tls_config
                    .client_config(*node_id, version)
                    .inspect_err(|err| warn!(self.logger, "{}", err))
                    .ok()?;

                Some((url, tls_config))
            })
            .collect::<Vec<_>>();

        candidates.shuffle(&mut thread_rng());
        candidates.pop().ok_or_else(|| {
            OrchestratorError::cloud_engine_error(format!(
                "no reachable node found on subnet {subnet_id}"
            ))
        })
    }
}
