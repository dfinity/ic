use crate::{
    pb::v1::{audit_event::reset_aging::NeuronDissolveState, neuron::DissolveState, AuditEvent},
    storage::AUDIT_EVENTS_LOG,
};

use ic_stable_structures::Storable;
use prost::Message;
use std::borrow::Cow;

impl From<DissolveState> for NeuronDissolveState {
    fn from(dissolve_state: DissolveState) -> Self {
        match dissolve_state {
            DissolveState::WhenDissolvedTimestampSeconds(timestamp) => {
                NeuronDissolveState::WhenDissolvedTimestampSeconds(timestamp)
            }
            DissolveState::DissolveDelaySeconds(delay) => {
                NeuronDissolveState::DissolveDelaySeconds(delay)
            }
        }
    }
}

impl Storable for AuditEvent {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.encode_to_vec().into()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Cannot decode audit event")
    }
}

pub fn add_audit_event(event: AuditEvent) {
    AUDIT_EVENTS_LOG.with(|log| {
        log.borrow()
            .append(&event)
            .expect("failed to append an event");
    });
}
