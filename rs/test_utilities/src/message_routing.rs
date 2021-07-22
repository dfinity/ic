// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]

use ic_interfaces::messaging::{
    MessageRouting, MessageRoutingError, XNetPayloadBuilder, XNetPayloadError,
    XNetPayloadValidationError,
};
use ic_interfaces::state_manager::{CertificationScope, StateManager};
use ic_interfaces::validation::ValidationResult;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{Batch, ValidationContext, XNetPayload},
    Height, NumBytes,
};
use std::sync::{Arc, RwLock};

use mockall::*;

pub struct FakeMessageRouting {
    pub batches: RwLock<Vec<Batch>>,
    pub next_batch_height: RwLock<Height>,
    // In real code there is a tight dependency between the message routing and the state manager:
    // whenever the message routing delivers a batch and it get's executed, state manager commits
    // the execution state. For all tests, which require this dependency, we introduce an optional
    // state manager.
    state_manager: Option<Arc<dyn StateManager<State = ReplicatedState>>>,
}

impl FakeMessageRouting {
    pub fn new() -> FakeMessageRouting {
        let batches = RwLock::new(Vec::new());
        let next_batch_height = RwLock::new(Height::from(1));
        FakeMessageRouting {
            batches,
            next_batch_height,
            state_manager: None,
        }
    }

    pub fn with_state_manager(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    ) -> Self {
        let mut message_routing = Self::new();
        message_routing.state_manager = Some(state_manager);
        message_routing
    }
}

impl Default for FakeMessageRouting {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageRouting for FakeMessageRouting {
    fn deliver_batch(&self, batch: Batch) -> Result<(), MessageRoutingError> {
        let mut next_batch_height = self.next_batch_height.write().unwrap();

        let expected_height = *next_batch_height;
        let scope = if batch.requires_full_state_hash {
            CertificationScope::Full
        } else {
            CertificationScope::Metadata
        };
        if batch.batch_number == expected_height {
            *next_batch_height = batch.batch_number.increment();
            self.batches.write().unwrap().push(batch);
            if let Some(state_manager) = &self.state_manager {
                let (_height, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, expected_height, scope);
            }
            return Ok(());
        }
        Err(MessageRoutingError::Ignored {
            expected_height,
            actual_height: batch.batch_number,
        })
    }
    fn expected_batch_height(&self) -> Height {
        *self.next_batch_height.read().unwrap()
    }
}

mock! {
    pub MessageRouting {}

    trait MessageRouting {
        fn deliver_batch(& self, b: Batch) -> Result<(), MessageRoutingError>;
        fn expected_batch_height(&self) -> Height;
    }
}

mock! {
    pub XNetPayloadBuilder {}

    trait XNetPayloadBuilder{
        fn get_xnet_payload<'a>(
            &self,
            height: Height,
            validation_context: &ValidationContext,
            past_payloads: &[&'a XNetPayload],
            byte_limit : NumBytes,
        ) -> Result<XNetPayload, XNetPayloadError>;

        fn validate_xnet_payload<'a>(
            &self,
            payload: &XNetPayload,
            validation_context: &ValidationContext,
            past_payloads: &[&'a XNetPayload],
            byte_limit : NumBytes
        ) -> ValidationResult<XNetPayloadValidationError>;
    }
}
