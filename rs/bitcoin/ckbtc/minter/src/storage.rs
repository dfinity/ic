#[cfg(test)]
mod tests;

use crate::state::eventlog::{Event, EventType};
use crate::CanisterRuntime;
use ic_stable_structures::{
    log::{Log as StableLog, NoSuchEntry},
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
};
use serde::Deserialize;
use std::cell::RefCell;

const OLD_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const OLD_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);

const LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(2);
const LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(3);

type VMem = VirtualMemory<DefaultMemoryImpl>;
type EventLog = StableLog<Vec<u8>, VMem, VMem>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    /// The log of the ckBTC state modifications.
    static OLD_EVENTS: RefCell<EventLog> = MEMORY_MANAGER
        .with(|m|
              RefCell::new(
                  StableLog::init(
                      m.borrow().get(OLD_LOG_INDEX_MEMORY_ID),
                      m.borrow().get(OLD_LOG_DATA_MEMORY_ID)
                  ).expect("failed to initialize stable log")
              )
        );

    /// The log of the ckBTC state modifications.
    static EVENTS: RefCell<EventLog> = MEMORY_MANAGER
        .with(|m|
              RefCell::new(
                  StableLog::init(
                      m.borrow().get(LOG_INDEX_MEMORY_ID),
                      m.borrow().get(LOG_DATA_MEMORY_ID)
                  ).expect("failed to initialize stable log")
              )
        );
}

pub struct EventIterator {
    buf: Vec<u8>,
    pos: u64,
}

impl Iterator for EventIterator {
    type Item = Event;

    fn next(&mut self) -> Option<Event> {
        EVENTS.with(|events| {
            let events = events.borrow();

            match events.read_entry(self.pos, &mut self.buf) {
                Ok(()) => {
                    self.pos = self.pos.saturating_add(1);
                    Some(decode_event(&self.buf))
                }
                Err(NoSuchEntry) => None,
            }
        })
    }

    fn nth(&mut self, n: usize) -> Option<Event> {
        self.pos = self.pos.saturating_add(n as u64);
        self.next()
    }
}

/// Encodes an event into a byte array.
pub fn encode_event(event: &Event) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(event, &mut buf).expect("failed to encode a minter event");
    buf
}

/// # Panics
///
/// This function panics if the event decoding fails.
pub fn decode_event(buf: &[u8]) -> Event {
    // For backwards compatibility, we have to handle two cases:
    //  1. Legacy events: raw instances of the event type enum
    //  2. New events: a struct containing a timestamp and an event type
    // To differentiate the two, we use a dummy intermediate enum whose variants
    // correspond to the two cases above. The `untagged` attribute tells serde
    // that instances of each variant are not labeled, and that it should tell
    // the two apart based on their contents (e.g. presence of timestamp attribute
    // suggests a new event).
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SerializedEvent {
        Legacy(EventType),
        Event(Event),
    }
    match ciborium::de::from_reader(buf).expect("failed to decode a minter event") {
        SerializedEvent::Legacy(payload) => Event::from(payload),
        SerializedEvent::Event(event) => event,
    }
}

/// Returns an iterator over all minter events.
pub fn events() -> impl Iterator<Item = Event> {
    EventIterator {
        buf: vec![],
        pos: 0,
    }
}

pub fn migrate_old_events_if_not_empty() -> Option<u64> {
    let mut num_events_removed = None;
    OLD_EVENTS.with(|old_events| {
        let mut old = old_events.borrow_mut();
        if old.len() > 0 {
            EVENTS.with(|new| {
                num_events_removed = Some(migrate_events(&old, &new.borrow()));
            });
            *old = MEMORY_MANAGER.with(|m| {
                StableLog::new(
                    m.borrow().get(OLD_LOG_INDEX_MEMORY_ID),
                    m.borrow().get(OLD_LOG_DATA_MEMORY_ID),
                )
            });
        }
    });
    assert_eq!(
        OLD_EVENTS.with(|events| events.borrow().len()),
        0,
        "Old events is not emptied after data migration"
    );
    num_events_removed
}

pub fn migrate_events(old_events: &EventLog, new_events: &EventLog) -> u64 {
    let mut removed = 0;
    for bytes in old_events.iter() {
        let event = decode_event(&bytes);
        match event.payload {
            EventType::ReceivedUtxos { utxos, .. } if utxos.is_empty() => removed += 1,
            _ => {
                new_events
                    .append(&bytes)
                    .expect("failed to append an entry to the new event log");
            }
        }
    }
    removed
}

/// Returns the current number of events in the log.
pub fn count_events() -> u64 {
    EVENTS.with(|events| events.borrow().len())
}

/// Records a new minter event.
pub fn record_event<R: CanisterRuntime>(payload: EventType, runtime: &R) {
    let bytes = encode_event(&Event {
        timestamp: Some(runtime.time()),
        payload,
    });
    EVENTS.with(|events| {
        events
            .borrow()
            .append(&bytes)
            .expect("failed to append an entry to the event log");
    })
}
