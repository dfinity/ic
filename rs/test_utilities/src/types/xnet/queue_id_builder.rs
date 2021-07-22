use crate::types::ids::canister_test_id;
use ic_types::xnet::{QueueId, SessionId};
use ic_types::CanisterId;

pub struct QueueIdBuilder {
    queue_id: QueueId,
}

impl Default for QueueIdBuilder {
    /// Creates a dummy `QueueId` with default values.
    fn default() -> Self {
        Self {
            queue_id: QueueId {
                dst_canister: canister_test_id(0),
                src_canister: canister_test_id(0),
                session_id: SessionId::from(0),
            },
        }
    }
}

impl QueueIdBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn src_canister(mut self, can_id: CanisterId) -> Self {
        self.queue_id.src_canister = can_id;
        self
    }

    pub fn dst_canister(mut self, can_id: CanisterId) -> Self {
        self.queue_id.dst_canister = can_id;
        self
    }

    pub fn session_id(mut self, session_id: SessionId) -> Self {
        self.queue_id.session_id = session_id;
        self
    }

    // Returns the built QueueId
    pub fn build(&self) -> QueueId {
        self.queue_id.clone()
    }
}
