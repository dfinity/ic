use crate::state::event::{Event, EventType};
use crate::state::State;
use ic_stable_structures::{
    log::Log as StableLog,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    reader::Reader,
    storable::Storable,
    writer::Writer,
    DefaultMemoryImpl,
};
use std::borrow::Cow;
use std::cell::RefCell;

const LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);
const UPGRADE_BUFFER_MEMORY_ID: MemoryId = MemoryId::new(2);

type VMem = VirtualMemory<DefaultMemoryImpl>;
type EventLog = StableLog<Event, VMem, VMem>;

impl Storable for Event {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("event encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref())
            .unwrap_or_else(|e| panic!("failed to decode event bytes {}: {e}", hex::encode(bytes)))
    }
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    /// The log of the ckETH state modifications.
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

/// Appends the event to the event log.
pub fn record_event(payload: EventType) {
    EVENTS
        .with(|events| {
            events.borrow().append(&Event {
                timestamp: ic_cdk::api::time(),
                payload,
            })
        })
        .expect("recording an event should succeed");
}

/// Returns the total number of events in the audit log.
pub fn total_event_count() -> u64 {
    EVENTS.with(|events| events.borrow().len())
}

pub fn with_event_iter<F, R>(f: F) -> R
where
    F: for<'a> FnOnce(Box<dyn Iterator<Item = Event> + 'a>) -> R,
{
    EVENTS.with(|events| f(Box::new(events.borrow().iter())))
}

pub fn encode_state(s: &State) {
    MEMORY_MANAGER.with(|m| {
        ciborium::ser::into_writer(
            s,
            Writer::new(
                &mut m.borrow().get(UPGRADE_BUFFER_MEMORY_ID),
                /*offset =*/ 0,
            ),
        )
        .expect("CBOR serialization should succeed")
    })
}

pub fn decode_state() -> State {
    MEMORY_MANAGER.with(|m| {
        ciborium::de::from_reader(Reader::new(
            &m.borrow().get(UPGRADE_BUFFER_MEMORY_ID),
            /*offset =*/ 0,
        ))
        .expect("CBOR deserialization should succeed")
    })
}
