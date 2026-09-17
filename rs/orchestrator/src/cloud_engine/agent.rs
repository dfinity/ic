//! Construction of the `ic-agent`s used to reach the engine management canister
//! and the engine's own operator canister.

use super::error::{CloudEngineError, CloudEngineResult};
use crate::{
    registration::NodeRegistrationCrypto, signer::NodeSender, utils::nns_root_key_der_from_registry,
};
use ic_agent::{Agent, Identity, identity::AnonymousIdentity};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::{api_boundary_node::ApiBoundaryNodeRegistry, node::NodeRegistry};
use ic_types::RegistryVersion;
use rand::prelude::*;
use std::sync::Arc;
use url::Url;

/// An anonymous agent aimed at a randomly chosen API boundary node. It is used
/// to interact with the engine management canister. It lives on a regular subnet,
/// so it is only reachable by a cloud engine node through an API BN.
pub(super) fn anonymous_via_api_boundary_node(
    registry: &dyn RegistryClient,
    version: RegistryVersion,
    logger: &ReplicaLogger,
) -> CloudEngineResult<Agent> {
    let url = random_api_boundary_node_url(registry, version, logger)?;

    build(registry, url, AnonymousIdentity, version)
}

/// An agent aimed at the local replica and signing as this node. It is used to
/// interact with the engine's operator canister.
pub(super) fn node_signed(
    registry: &dyn RegistryClient,
    crypto: Arc<dyn NodeRegistrationCrypto>,
    replica_url: Url,
    version: RegistryVersion,
) -> CloudEngineResult<Agent> {
    let identity = NodeSender::for_this_node(crypto).map_err(CloudEngineError::failed)?;

    build(registry, replica_url, identity, version)
}

fn random_api_boundary_node_url(
    registry: &dyn RegistryClient,
    version: RegistryVersion,
    logger: &ReplicaLogger,
) -> CloudEngineResult<Url> {
    let mut node_ids = registry.get_api_boundary_node_ids(version).map_err(|err| {
        CloudEngineError::failed(format!("could not list the API boundary nodes: {err:?}"))
    })?;

    node_ids.shuffle(&mut thread_rng());
    node_ids
        .iter()
        .find_map(|node_id| {
            let domain = registry.get_node_record(*node_id, version).ok()??.domain?;
            Url::parse(&format!("https://{domain}/"))
                .inspect_err(|err| {
                    warn!(
                        logger,
                        "Ignoring the malformed API boundary node domain '{}': {}", domain, err
                    )
                })
                .ok()
        })
        .ok_or_else(|| {
            CloudEngineError::failed("no usable API boundary node found in the registry")
        })
}

fn build<I: Identity + 'static>(
    registry: &dyn RegistryClient,
    url: Url,
    identity: I,
    version: RegistryVersion,
) -> CloudEngineResult<Agent> {
    let agent = Agent::builder()
        .with_url(url)
        .with_identity(identity)
        .with_verify_query_signatures(true)
        .build()
        .map_err(|err| CloudEngineError::failed(format!("could not build an agent: {err}")))?;
    let root_key =
        nns_root_key_der_from_registry(registry, version).map_err(CloudEngineError::failed)?;
    agent.set_root_key(root_key);

    Ok(agent)
}
