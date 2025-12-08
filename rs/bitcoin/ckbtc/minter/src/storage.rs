#[cfg(test)]
mod tests;

use crate::CanisterRuntime;
use crate::state::eventlog::{CkBtcMinterEvent, Event, EventType};
use ic_stable_structures::{
    DefaultMemoryImpl,
    log::{Log as StableLog, NoSuchEntry},
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};
use serde::Deserialize;
use std::borrow::Cow;
use std::cell::RefCell;
use std::marker::PhantomData;

const V0_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(0);
const V0_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(1);

const V1_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(2);
const V1_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(3);

type VMem = VirtualMemory<DefaultMemoryImpl>;
type EventLog = StableLog<Vec<u8>, VMem, VMem>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    /// The v0 log of the ckBTC state modifications that should be migrated to v1 and then set to empty.
    static V0_EVENTS: RefCell<EventLog> = MEMORY_MANAGER
        .with(|m|
              RefCell::new(
                  StableLog::init(
                      m.borrow().get(V0_LOG_INDEX_MEMORY_ID),
                      m.borrow().get(V0_LOG_DATA_MEMORY_ID)
                  ).expect("failed to initialize stable log")
              )
        );

    /// The latest log of the ckBTC state modifications.
    static V1_EVENTS: RefCell<EventLog> = MEMORY_MANAGER
        .with(|m|
              RefCell::new(
                  StableLog::init(
                      m.borrow().get(V1_LOG_INDEX_MEMORY_ID),
                      m.borrow().get(V1_LOG_DATA_MEMORY_ID)
                  ).expect("failed to initialize stable log")
              )
        );
}

pub struct EventIterator<Event> {
    buf: Vec<u8>,
    pos: u64,
    marker: PhantomData<Event>,
}

impl<Event: StorableEvent> Iterator for EventIterator<Event> {
    type Item = Event;

    fn next(&mut self) -> Option<Event> {
        V1_EVENTS.with(|events| {
            let events = events.borrow();

            match events.read_entry(self.pos, &mut self.buf) {
                Ok(()) => {
                    self.pos = self.pos.saturating_add(1);
                    Some(Event::from_bytes(Cow::Borrowed(&self.buf)))
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

pub trait StorableEvent {
    fn to_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
    fn from_bytes<'a>(bytes: Cow<'a, [u8]>) -> Self;
}

impl StorableEvent for CkBtcMinterEvent {
    fn to_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode a minter event");
        Cow::Owned(buf)
    }

    fn from_bytes<'a>(bytes: Cow<'a, [u8]>) -> Self {
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
            Event(Event<EventType>),
        }
        match ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode a minter event") {
            SerializedEvent::Legacy(payload) => Event {
                payload,
                timestamp: None,
            },
            SerializedEvent::Event(event) => event,
        }
    }
}

/// Returns an iterator over all minter events.
pub fn events<T>() -> impl Iterator<Item = Event<T>>
where
    Event<T>: StorableEvent,
{
    EventIterator {
        buf: vec![],
        pos: 0,
        marker: PhantomData,
    }
}

pub fn migrate_old_events_if_not_empty() -> Option<u64> {
    let mut num_events_removed = None;
    V0_EVENTS.with(|old_events| {
        let mut old = old_events.borrow_mut();
        if !old.is_empty() {
            V1_EVENTS.with(|new| {
                num_events_removed = Some(migrate_events(&old, &new.borrow()));
            });
            *old = MEMORY_MANAGER.with(|m| {
                StableLog::new(
                    m.borrow().get(V0_LOG_INDEX_MEMORY_ID),
                    m.borrow().get(V0_LOG_DATA_MEMORY_ID),
                )
            });
        }
    });
    assert_eq!(
        V0_EVENTS.with(|events| events.borrow().len()),
        0,
        "Old events is not emptied after data migration"
    );
    num_events_removed
}

pub fn migrate_events(old_events: &EventLog, new_events: &EventLog) -> u64 {
    let mut removed = 0;
    for bytes in old_events.iter() {
        let event = CkBtcMinterEvent::from_bytes(Cow::Borrowed(&bytes));
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
    V1_EVENTS.with(|events| events.borrow().len())
}

/// Records a new minter event.
pub fn record_event<R: CanisterRuntime, T>(payload: T, runtime: &R)
where
    Event<T>: StorableEvent,
{
    let event = Event {
        timestamp: Some(runtime.time()),
        payload,
    };
    let bytes = event.to_bytes().to_vec();
    V1_EVENTS.with(|events| {
        events
            .borrow()
            .append(&bytes)
            .expect("failed to append an entry to the event log");
    })
}

/// This function is only called by update_events when the canister
/// is compiled with the `self_check` feature (only used by debug build).
pub fn record_event_v0<R: CanisterRuntime>(payload: EventType, runtime: &R) {
    // The timestamp below could be a source of non-reprodicibilty.
    // However, this function is only used for the purpose of dumping
    // stable memory after uploading v0 events from local file to the
    // canister, and the memory dump is used in a canbench to measure
    // instruction counts. So the actual value of timestamps shouldn't
    // matter.
    let event = Event {
        timestamp: Some(runtime.time()),
        payload,
    };
    let bytes = event.to_bytes().as_ref().to_vec();
    V0_EVENTS.with(|events| {
        events
            .borrow()
            .append(&bytes)
            .expect("failed to append an entry to the event log");
    })
}

#[cfg(feature = "canbench-rs")]
mod benches {
    use super::*;
    use crate::state::eventlog::replay;
    use crate::state::replace_state;
    use crate::state::{CkBtcMinterState, invariants::CheckInvariants};
    use crate::{IC_CANISTER_RUNTIME, state};
    use canbench_rs::bench;

    #[bench(raw)]
    fn build_unsigned_transaction_1_50k_sats() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(50_000) // minimum withdrawal amount
    }

    #[bench(raw)]
    fn build_unsigned_transaction_2_100k_sats() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(100_000)
    }

    #[bench(raw)]
    fn build_unsigned_transaction_3_1m_sats() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(1_000_000)
    }

    #[bench(raw)]
    fn build_unsigned_transaction_4_10m_sats() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(10_000_000)
    }

    #[bench(raw)]
    fn build_unsigned_transaction_5_1_btc() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(100_000_000)
    }

    #[bench(raw)]
    fn build_unsigned_transaction_6_10_btc() -> canbench_rs::BenchResult {
        bench_build_unsigned_transaction(1_000_000_000)
    }

    fn bench_build_unsigned_transaction(withdrawal_amount: u64) -> canbench_rs::BenchResult {
        rebuild_mainnet_state();
        state::read_state(|s| {
            // The distribution of UTXOs is a key factor in the complexity of building a transaction,
            // the more UTXOs with small values there are, the more instructions will be required to build a transaction for a large amount
            // because more UTXOs are needed to cover that amount.
            // NOTE: Those benchmarks reflect the performance of the minter on **mainnet**.
            // Changing the number of available of UTXOs is unavoidable when updating the retrieved mainnet events used for testing,
            // so that fluctuations in performance is acceptable, but large degradation would indicate a regression.
            assert_eq!(s.available_utxos.len(), 66_212);
        });

        let dummy_minter_address = crate::BitcoinAddress::P2wpkhV0([u8::MAX; 20]);
        let dummy_recipient_address = crate::BitcoinAddress::P2wpkhV0([42_u8; 20]);
        let median_fee_millisatoshi_per_vbyte = 1_000; //1 sat/vbyte
        let fee_estimator = state::read_state(|s| IC_CANISTER_RUNTIME.fee_estimator(s));

        canbench_rs::bench_fn(|| {
            state::mutate_state(|s| {
                crate::build_unsigned_transaction(
                    &mut s.available_utxos,
                    vec![(dummy_recipient_address, withdrawal_amount)],
                    dummy_minter_address,
                    median_fee_millisatoshi_per_vbyte,
                    &fee_estimator,
                )
                .unwrap()
            });
        })
    }

    fn rebuild_mainnet_state() {
        // These thread local state must be re-initialized after
        // canbench loads the stable memory from a file.
        MEMORY_MANAGER
            .with(|x| *x.borrow_mut() = MemoryManager::init(DefaultMemoryImpl::default()));
        V1_EVENTS.with(|x| {
            *x.borrow_mut() = MEMORY_MANAGER.with(|m| {
                StableLog::init(
                    m.borrow().get(V1_LOG_INDEX_MEMORY_ID),
                    m.borrow().get(V1_LOG_DATA_MEMORY_ID),
                )
                .expect("failed to initialize stable log")
            })
        });
        assert_eq!(count_events(), 768_723);

        let state = replay::<DoNotCheckInvariants>(events()).unwrap_or_else(|e| {
            ic_cdk::trap(format!("[upgrade]: failed to replay the event log: {e:?}"))
        });
        state.validate_config();
        replace_state(state);
    }

    pub enum DoNotCheckInvariants {}

    impl CheckInvariants for DoNotCheckInvariants {
        fn check_invariants(_state: &CkBtcMinterState) -> Result<(), String> {
            Ok(())
        }
    }
}
