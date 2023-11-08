use crate::{
    pb::v1::{audit_event::reset_aging::NeuronDissolveState, neuron::DissolveState, AuditEvent},
    storage::with_audit_events_log,
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

#[allow(dead_code)]
pub fn add_audit_event(event: AuditEvent) {
    with_audit_events_log(|log| {
        log.append(&event).expect("failed to append an event");
    });
}
