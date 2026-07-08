//! A subset of the [`dfx-core`] crate (derived from `dfx-core 0.4.0`), covering
//! only what SNS tooling needs: resolving a dfx identity + network into an
//! [`ic_agent::Agent`], and resolving a dfx identity name to its principal.
//!
//! `dfx` is deprecated. See the crate `README.md` for why this exists, what was
//! kept vs. dropped, and the maintenance policy (no new dependents).
//!
//! Most modules are copied from `dfx-core` at the same relative path so they can
//! be diffed against upstream; only [`network`] and this crate root are compact
//! reimplementations rather than trimmed copies.
//!
//! [`dfx-core`]: https://crates.io/crates/dfx-core

pub mod config;
pub mod error;
pub mod foundation;
pub mod fs;
pub mod identity;
pub mod json;
pub mod network;

use crate::error::identity::{InstantiateIdentityFromNameError, NewIdentityManagerError};
use crate::identity::identity_manager::{IdentityManager, InitializeIdentity};
use crate::network::{NetworkResolutionError, resolve_network};
use candid::Principal;
use ic_agent::agent::route_provider::RoundRobinRouteProvider;
use ic_agent::{Agent, Identity};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BuildIdentityError {
    #[error("Failed to create identity manager")]
    NewIdentityManager(#[from] NewIdentityManagerError),

    #[error("Failed to instantiate the selected identity")]
    InstantiateSelectedIdentity(#[from] InstantiateIdentityFromNameError),
}

#[derive(Error, Debug)]
pub enum GetAgentError {
    #[error("Failed to resolve network")]
    ResolveNetwork(#[from] NetworkResolutionError),

    #[error("Failed to build identity")]
    BuildIdentity(#[from] BuildIdentityError),

    #[error("Failed to create route provider")]
    CreateRouteProvider(#[source] ic_agent::AgentError),

    #[error("Failed to create HTTP client")]
    CreateHttpClient(#[source] reqwest::Error),

    #[error("Failed to create agent")]
    CreateAgent(#[source] ic_agent::AgentError),

    #[error("Failed to fetch root key from network")]
    FetchRootKey(#[source] ic_agent::AgentError),
}

#[derive(Error, Debug)]
pub enum GetIdentityPrincipalError {
    #[error("Failed to create identity manager")]
    NewIdentityManager(#[from] NewIdentityManagerError),

    #[error("Failed to instantiate identity")]
    InstantiateIdentity(#[from] InstantiateIdentityFromNameError),

    #[error("Failed to get principal for identity '{0}'")]
    NoPrincipal(String),
}

/// Builds an [`ic_agent::Agent`] for the given dfx network and identity.
///
/// This is the behavioural equivalent of dfx building its interface and then
/// fetching the root key on non-mainnet networks. If `identity` is `None` the
/// identity currently selected in the dfx CLI is used; otherwise the named
/// identity is used.
pub async fn get_agent(
    network_name: &str,
    identity: Option<String>,
) -> Result<Agent, GetAgentError> {
    let resolved = resolve_network(network_name)?;
    let identity = build_identity(identity)?;
    let agent = build_agent(identity, &resolved.providers)?;
    if !resolved.is_ic {
        agent
            .fetch_root_key()
            .await
            .map_err(GetAgentError::FetchRootKey)?;
    }
    Ok(agent)
}

/// Resolves a dfx identity name to its principal, without building an agent.
pub fn get_identity_principal(identity_name: &str) -> Result<Principal, GetIdentityPrincipalError> {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mut identity_manager = IdentityManager::new(&logger, None, InitializeIdentity::Disallow)?;
    identity_manager.instantiate_identity_from_name(identity_name, &logger)?;
    identity_manager
        .get_selected_identity_principal()
        .ok_or_else(|| GetIdentityPrincipalError::NoPrincipal(identity_name.to_string()))
}

/// Instantiates the selected (or named) dfx identity.
/// Mirrors `DfxInterfaceBuilder::build_identity` for the non-anonymous case.
fn build_identity(
    identity_override: Option<String>,
) -> Result<Arc<dyn Identity>, BuildIdentityError> {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mut identity_manager = IdentityManager::new(
        &logger,
        identity_override.as_deref(),
        InitializeIdentity::Disallow,
    )?;
    let identity: Box<dyn Identity> = identity_manager.instantiate_selected_identity(&logger)?;
    Ok(Arc::from(identity))
}

/// Builds an agent from a resolved identity and provider list.
/// Mirrors `DfxInterfaceBuilder::build_agent`.
fn build_agent(identity: Arc<dyn Identity>, providers: &[String]) -> Result<Agent, GetAgentError> {
    let route_provider = RoundRobinRouteProvider::new(providers.to_vec())
        .map_err(GetAgentError::CreateRouteProvider)?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .map_err(GetAgentError::CreateHttpClient)?;
    let agent = Agent::builder()
        .with_http_client(client)
        .with_route_provider(route_provider)
        .with_arc_identity(identity)
        .build()
        .map_err(GetAgentError::CreateAgent)?;
    Ok(agent)
}
