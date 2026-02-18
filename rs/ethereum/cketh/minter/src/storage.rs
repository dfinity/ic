use crate::state::event::{Event, EventType};
use ic_stable_structures::{
    DefaultMemoryImpl,
    log::Log as StableLog,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::{Bound, Storable},
};
use std::borrow::Cow;
use std::cell::RefCell;

const LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);

type VMem = VirtualMemory<DefaultMemoryImpl>;
type EventLog = StableLog<Event, VMem, VMem>;

impl Storable for Event {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        minicbor::encode(self, &mut buf).expect("event encoding should always succeed");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        minicbor::decode(bytes.as_ref())
            .unwrap_or_else(|e| panic!("failed to decode event bytes {}: {e}", hex::encode(bytes)))
    }

    const BOUND: Bound = Bound::Unbounded;
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

#[cfg(feature = "canbench-rs")]
mod benches {
    use super::*;
    use canbench_rs::bench;

    #[bench(raw)]
    fn bench_post_upgrade() -> canbench_rs::BenchResult {
        // Re-initialize thread locals from stable memory loaded by canbench.
        // This is necessary because thread locals are lazily initialized and may
        // have been initialized before canbench loaded the stable memory file.
        MEMORY_MANAGER
            .with(|x| *x.borrow_mut() = MemoryManager::init(DefaultMemoryImpl::default()));
        EVENTS.with(|x| {
            *x.borrow_mut() = MEMORY_MANAGER.with(|m| {
                StableLog::init(
                    m.borrow().get(LOG_INDEX_MEMORY_ID),
                    m.borrow().get(LOG_DATA_MEMORY_ID),
                )
                .expect("failed to initialize stable log")
            })
        });

        let event_count = total_event_count();
        assert!(event_count > 0, "expected events in stable memory");

        canbench_rs::bench_fn(|| {
            use crate::state::STATE;
            use crate::state::audit::replay_events;
            STATE.with(|cell| {
                *cell.borrow_mut() = Some(replay_events());
            });
        })
    }
}
