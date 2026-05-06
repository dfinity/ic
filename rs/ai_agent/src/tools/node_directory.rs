//! Shared helper: resolve `NodeId -> Ipv6Addr` from the local registry
//! store.
//!
//! `ic_metrics` (and, when implemented, `ic_logs`) needs to talk to a
//! peer node in the subnet that this AiNode is shadowing. The LLM
//! passes a textual node id (which it discovered via `ic_state`); we
//! look it up in the registry the orchestrator-managed state-sync
//! replica keeps on disk and return the IPv6 published in the node's
//! `NodeRecord.http`.
//!
//! Single instance per process. Holds a `RegistryClientImpl` backed by
//! a `LocalStoreImpl`. We never spawn the background polling thread —
//! the AiNode's orchestrator is the only writer, and the local store is
//! cheap to re-poll on every lookup.

use std::{
    net::Ipv6Addr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use ic_config::{Config, ConfigSource};
use ic_interfaces_registry::RegistryClient;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_local_store::LocalStoreImpl;
use ic_types::{NodeId, PrincipalId};

#[derive(Debug, thiserror::Error)]
pub enum NodeDirectoryError {
    #[error("failed to load replica config from {path}: {message}")]
    Config { path: PathBuf, message: String },

    #[error("registry local store not configured in {path}")]
    NoLocalStore { path: PathBuf },

    #[error("registry client error: {0:?}")]
    Registry(ic_types::registry::RegistryClientError),

    #[error("invalid node id '{0}': {1}")]
    InvalidNodeId(String, String),

    #[error("node {0} not found in registry at version {1}")]
    NodeNotFound(NodeId, u64),

    #[error("node {0} has no http endpoint in its NodeRecord")]
    NoHttpEndpoint(NodeId),

    #[error("node {0} http endpoint ip '{1}' is not a valid IPv6 address: {2}")]
    BadIpv6(NodeId, String, std::net::AddrParseError),
}

impl From<ic_types::registry::RegistryClientError> for NodeDirectoryError {
    fn from(e: ic_types::registry::RegistryClientError) -> Self {
        NodeDirectoryError::Registry(e)
    }
}

/// Wraps a `RegistryClientImpl` driven by a local store on disk.
pub struct NodeDirectory {
    client: Arc<RegistryClientImpl>,
}

impl NodeDirectory {
    /// Build a directory backed by the registry local store referenced
    /// by the given replica config.
    pub fn from_ic_config(ic_config_path: &Path) -> Result<Self, NodeDirectoryError> {
        let local_store_path = local_store_from_ic_config(ic_config_path)?;
        let data_provider: Arc<dyn ic_interfaces_registry::RegistryDataProvider> =
            Arc::new(LocalStoreImpl::new(local_store_path));
        let client = Arc::new(RegistryClientImpl::new(data_provider, None));
        // One synchronous poll so the cache is non-empty for the very
        // first lookup. Failures here are non-fatal: subsequent
        // `lookup` calls will re-poll and may succeed once the
        // orchestrator has populated the store.
        let _ = client.poll_once();
        Ok(Self { client })
    }

    /// Resolve a textual `NodeId` to its IPv6 address.
    ///
    /// Re-polls the registry on every call so we pick up new nodes
    /// without having to restart the agent.
    pub fn resolve_ipv6(&self, node_id_str: &str) -> Result<Ipv6Addr, NodeDirectoryError> {
        let principal = PrincipalId::from_str(node_id_str).map_err(|e| {
            NodeDirectoryError::InvalidNodeId(node_id_str.to_string(), e.to_string())
        })?;
        let node_id = NodeId::from(principal);

        // Best-effort refresh; ignore transient failures and use
        // whatever's cached.
        let _ = self.client.poll_once();

        let version = self.client.get_latest_version();
        let record = self
            .client
            .get_node_record(node_id, version)?
            .ok_or(NodeDirectoryError::NodeNotFound(node_id, version.get()))?;
        let http = record
            .http
            .ok_or(NodeDirectoryError::NoHttpEndpoint(node_id))?;
        let ip = http.ip_addr;
        Ipv6Addr::from_str(&ip).map_err(|e| NodeDirectoryError::BadIpv6(node_id, ip, e))
    }
}

/// Parse `ic.json5` and return the registry local store path.
///
/// `Config::load_with_tmpdir` materialises some derived paths but the
/// `registry_client.local_store` field is taken verbatim from the
/// config file.
fn local_store_from_ic_config(cfg_path: &Path) -> Result<PathBuf, NodeDirectoryError> {
    if !cfg_path.exists() {
        return Err(NodeDirectoryError::Config {
            path: cfg_path.to_path_buf(),
            message: "file not found".to_string(),
        });
    }
    let tmpdir = tempfile::Builder::new()
        .prefix("ic-ai-agent-cfg")
        .tempdir()
        .map_err(|e| NodeDirectoryError::Config {
            path: cfg_path.to_path_buf(),
            message: format!("failed to create tmpdir: {e}"),
        })?;
    let config = Config::load_with_tmpdir(
        ConfigSource::File(cfg_path.to_path_buf()),
        tmpdir.path().to_path_buf(),
    );
    let path = config.registry_client.local_store;
    if path.as_os_str().is_empty() {
        return Err(NodeDirectoryError::NoLocalStore {
            path: cfg_path.to_path_buf(),
        });
    }
    Ok(path)
}
