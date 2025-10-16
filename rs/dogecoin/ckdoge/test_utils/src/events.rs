use ic_ckdoge_minter::{Event, EventType};
use std::collections::BTreeMap;

pub struct MinterEventAssert {
    pub(crate) events: Vec<Event>,
}

impl MinterEventAssert {
    pub fn contains_only_once_in_order(self, expected_events: &[EventType]) -> Self {
        let mut found_event_indexes = BTreeMap::new();
        for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
            for (index_audit_event, audit_event) in self.events.iter().enumerate() {
                if &audit_event.payload == expected_event {
                    assert_eq!(
                        found_event_indexes.insert(index_expected_event, index_audit_event),
                        None,
                        "Event {expected_event:?} occurs multiple times"
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
            "Events were found in unexpected order. All events: {:?}",
            self.events
        );
        self
    }
}
