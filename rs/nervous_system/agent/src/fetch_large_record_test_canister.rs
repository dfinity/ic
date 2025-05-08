use super::Request;
use candid::Encode;
use ic_registry_fetch_large_record_test_canister::{CallRegistryGetChangesSinceRequest, ContentSummary};

impl Request for CallRegistryGetChangesSinceRequest {
    fn method(&self) -> &'static str {
        "call_registry_get_changes_since"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = Option<ContentSummary>;
}
