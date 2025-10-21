use crate::{pb::v1::AuditEvent, storage::with_audit_events_log};

use ic_stable_structures::{Storable, storable::Bound};
use prost::Message;
use std::borrow::Cow;

impl Storable for AuditEvent {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.encode_to_vec().into()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Cannot decode audit event")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[allow(dead_code)]
pub fn add_audit_event(event: AuditEvent) {
    with_audit_events_log(|log| {
        log.append(&event).expect("failed to append an event");
    });
}
