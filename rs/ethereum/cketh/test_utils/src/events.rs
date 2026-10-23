use crate::CkEthSetup;
use ic_cketh_minter::endpoints::events::{Event, EventPayload};
use std::collections::BTreeMap;
use std::fmt;

pub struct MinterEventAssert<T> {
    setup: T,
    events: Vec<Event>,
}

impl<T: AsRef<CkEthSetup>> MinterEventAssert<T> {
    pub fn from_fetching_all_events(setup: T) -> Self {
        let events = setup.as_ref().get_all_events();
        Self { setup, events }
    }

    pub fn assert_has_unique_events_in_order(mut self, expected_events: &[EventPayload]) -> T {
        const MAX_ATTEMPTS: usize = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match check_unique_events_in_order(&self.events, expected_events) {
                Ok(()) => return self.setup,
                Err(err) => {
                    let retry =
                        matches!(*err, CheckError::MissingEvent { .. }) && attempt < MAX_ATTEMPTS;
                    if !retry {
                        panic!("{err}");
                    }
                    self.setup.as_ref().env.tick();
                    self.events = self.setup.as_ref().get_all_events();
                }
            }
        }
        unreachable!()
    }
}

impl<T> MinterEventAssert<T> {
    pub fn skip(self, count: usize) -> Self {
        let events = self.events.into_iter().skip(count).collect();
        Self {
            setup: self.setup,
            events,
        }
    }

    pub fn assert_has_no_event_satisfying<P: Fn(&EventPayload) -> bool>(self, predicate: P) -> T {
        if let Some(unexpected_event) = self
            .events
            .into_iter()
            .find(|event| predicate(&event.payload))
        {
            panic!("Found an event satisfying the predicate: {unexpected_event:?}")
        }
        self.setup
    }
}

enum CheckError {
    MissingEvent {
        expected: EventPayload,
        all_events: Vec<Event>,
    },
    DuplicateEvent {
        event: EventPayload,
    },
    OutOfOrder {
        all_events: Vec<Event>,
    },
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEvent {
                expected,
                all_events,
            } => write!(
                f,
                "Missing event {:?}. All events: {:?}",
                expected, all_events
            ),
            Self::DuplicateEvent { event } => {
                write!(f, "Event {event:?} occurs multiple times")
            }
            Self::OutOfOrder { all_events } => write!(
                f,
                "Events were found in unexpected order. All events: {:?}",
                all_events
            ),
        }
    }
}

fn check_unique_events_in_order(
    events: &[Event],
    expected_events: &[EventPayload],
) -> Result<(), Box<CheckError>> {
    let mut found_event_indexes = BTreeMap::new();
    for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
        for (index_audit_event, audit_event) in events.iter().enumerate() {
            if &audit_event.payload == expected_event
                && found_event_indexes
                    .insert(index_expected_event, index_audit_event)
                    .is_some()
            {
                return Err(Box::new(CheckError::DuplicateEvent {
                    event: expected_event.clone(),
                }));
            }
        }
        if !found_event_indexes.contains_key(&index_expected_event) {
            return Err(Box::new(CheckError::MissingEvent {
                expected: expected_event.clone(),
                all_events: events.to_vec(),
            }));
        }
    }
    let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
    let sorted_audit_event_indexes = {
        let mut indexes = audit_event_indexes.clone();
        indexes.sort_unstable();
        indexes
    };
    if audit_event_indexes != sorted_audit_event_indexes {
        return Err(Box::new(CheckError::OutOfOrder {
            all_events: events.to_vec(),
        }));
    }
    Ok(())
}
