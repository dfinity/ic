use crate::CkEthSetup;
use ic_cketh_minter::endpoints::events::{Event, EventPayload};
use std::collections::BTreeMap;

pub struct MinterEventAssert<T> {
    setup: T,
    events: Vec<Event>,
}

impl<T: AsRef<CkEthSetup>> MinterEventAssert<T> {
    pub fn from_fetching_all_events(setup: T) -> Self {
        let events = setup.as_ref().get_all_events();
        Self { setup, events }
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

    pub fn assert_has_unique_events_in_order(self, expected_events: &[EventPayload]) -> T {
        let mut found_event_indexes = BTreeMap::new();
        for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
            for (index_audit_event, audit_event) in self.events.iter().enumerate() {
                if &audit_event.payload == expected_event {
                    assert_eq!(
                        found_event_indexes.insert(index_expected_event, index_audit_event),
                        None,
                        "Event {:?} occurs multiple times",
                        expected_event
                    );
                }
            }
            assert!(
                found_event_indexes.contains_key(&index_expected_event),
                "Missing event {:?}. All events: {:?}",
                expected_event,
                self.events
            )
        }
        let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
        let sorted_audit_event_indexes = {
            let mut indexes = audit_event_indexes.clone();
            indexes.sort_unstable();
            indexes
        };
        assert_eq!(
            audit_event_indexes, sorted_audit_event_indexes,
            "Events were found in unexpected order"
        );
        self.setup
    }

    pub fn assert_has_no_event_satisfying<P: Fn(&EventPayload) -> bool>(self, predicate: P) -> T {
        if let Some(unexpected_event) = self
            .events
            .into_iter()
            .find(|event| predicate(&event.payload))
        {
            panic!(
                "Found an event satisfying the predicate: {:?}",
                unexpected_event
            )
        }
        self.setup
    }
}
