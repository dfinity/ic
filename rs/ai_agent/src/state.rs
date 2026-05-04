//! Per-process shared state.
//!
//! Holds the active provider client (set by `POST /v1/config`) plus static
//! defaults. Wrapped in `Arc<RwLock<...>>` so `/v1/config` can update it
//! at runtime without recreating the router.

use crate::{config::AppConfig, providers::AiProvider};
use slog::Logger;
use tokio::sync::RwLock;

/// Mutable runtime state shared across handlers.
pub struct AppState {
    pub config: AppConfig,
    pub log: Logger,
    /// `None` until `POST /v1/config` populates it.
    pub provider: RwLock<Option<AiProvider>>,
}

impl AppState {
    pub fn new(config: AppConfig, log: Logger) -> Self {
        Self {
            config,
            log,
            provider: RwLock::new(None),
        }
    }
}
