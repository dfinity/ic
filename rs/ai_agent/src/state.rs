//! Per-process shared state.
//!
//! Holds the active provider client (set by `POST /v1/config`) plus static
//! defaults. Wrapped in `Arc<RwLock<...>>` so `/v1/config` can update it
//! at runtime without recreating the router.

use crate::{
    config::AppConfig,
    providers::AiProvider,
    sessions::SessionStore,
    tools::node_directory::{NodeDirectory, NodeDirectoryError},
};
use slog::Logger;
use std::sync::{Arc, RwLock};
use tokio::sync::OnceCell;

/// Mutable runtime state shared across handlers.
pub struct AppState {
    pub config: AppConfig,
    pub log: Logger,
    /// `None` until `POST /v1/config` populates it.
    ///
    /// `std::sync::RwLock` (not the tokio variant): every call site
    /// only holds the guard long enough to clone an `AiProvider` (a
    /// cheap struct of `String` + `GeminiClient`) or to write a new
    /// one in. None of them `.await` while the guard is alive, which
    /// is the criterion for using a blocking lock under tokio.
    pub provider: RwLock<Option<AiProvider>>,
    /// Tools wired into the agent when a request omits the `tools`
    /// field. Starts empty — many open-weight models (including some
    /// gemma3 variants served via ollama) reject tool-augmented prompts
    /// outright, so tools are opt-in by default. Mutable at runtime via
    /// `POST /v1/tools`.
    pub default_tools: RwLock<Vec<String>>,
    /// Lazily constructed registry-backed node lookup. Built on first
    /// use because (a) it touches the filesystem and we want
    /// `AppState::new` to stay infallible, and (b) on a fresh AiNode
    /// the registry local store may not exist yet on startup.
    node_directory: OnceCell<Result<Arc<NodeDirectory>, NodeDirectoryError>>,
    /// In-memory chat-session cache for `/v1/agent/chat`. See
    /// [`crate::sessions`] for bounding rules.
    pub sessions: SessionStore,
}

impl AppState {
    pub fn new(config: AppConfig, log: Logger) -> Self {
        let sessions = SessionStore::new(config.max_sessions, config.session_idle_ttl);
        Self {
            config,
            log,
            provider: RwLock::new(None),
            default_tools: RwLock::new(Vec::new()),
            node_directory: OnceCell::new(),
            sessions,
        }
    }

    /// Returns the shared node directory, constructing it on first
    /// call. Errors are cached: if the registry local store is
    /// misconfigured we don't keep retrying on every tool call. Restart
    /// the service to retry.
    pub async fn node_directory(&self) -> Result<Arc<NodeDirectory>, NodeDirectoryError> {
        let cfg_path = self.config.ic_config_path.clone();
        let res = self
            .node_directory
            .get_or_init(|| async move {
                tokio::task::spawn_blocking(move || NodeDirectory::from_ic_config(&cfg_path))
                    .await
                    .map_err(|e| NodeDirectoryError::Config {
                        path: std::path::PathBuf::new(),
                        message: format!("join error: {e}"),
                    })?
                    .map(Arc::new)
            })
            .await;
        match res {
            Ok(d) => Ok(Arc::clone(d)),
            Err(e) => Err(clone_node_directory_error(e)),
        }
    }
}

/// `NodeDirectoryError` doesn't implement `Clone` (the underlying
/// `RegistryClientError` carries a non-cloneable source). For caching
/// purposes we render it through a string round-trip; the lossy
/// display is acceptable here because the cached error is only ever
/// surfaced to the LLM as a one-shot "couldn't reach the registry"
/// message.
fn clone_node_directory_error(e: &NodeDirectoryError) -> NodeDirectoryError {
    NodeDirectoryError::Config {
        path: std::path::PathBuf::new(),
        message: e.to_string(),
    }
}
