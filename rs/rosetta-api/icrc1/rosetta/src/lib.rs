use common::storage::storage_client::StorageClient;
use ic_base_types::CanisterId;

pub mod common;
pub struct AppState {
    pub ledger_id: CanisterId,
    pub _storage: StorageClient,
}
