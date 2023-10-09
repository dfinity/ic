use common::storage::storage_client::StorageClient;
use ic_base_types::CanisterId;
use std::sync::Arc;

pub mod common;

pub mod ledger_blocks_synchronization;

pub struct AppState {
    pub ledger_id: CanisterId,
    pub storage: Arc<StorageClient>,
}
