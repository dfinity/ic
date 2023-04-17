use ic_base_types::CanisterId;
use std::{cell::RefCell, collections::BTreeMap};

pub mod canister_management;
pub mod init;
pub mod pb;
pub mod root_proposals;

thread_local! {
    /// The map of CanisterId to count of open `CanisterStatus` calls to that canister. This serve
    /// as a data source for the metrics endpoint. This is stored in a local RefCell and is not persisted
    /// across upgrades. This state need not be persisted because the canister will not upgrade if
    /// there are any open call contexts, which is tracked by this map.
    pub static OPEN_CANISTER_STATUS_CALLS: RefCell<BTreeMap<CanisterId, u64>> = RefCell::new(BTreeMap::new());
}

pub fn increment_open_canister_status_calls(canister_id: CanisterId) {
    OPEN_CANISTER_STATUS_CALLS.with(|open_calls| {
        open_calls.borrow_mut().entry(canister_id).or_insert(0);
        if let Some(counter) = open_calls.borrow_mut().get_mut(&canister_id) {
            *counter = counter.saturating_add(1_u64);
        }
    });
}

pub fn decrement_open_canister_status_calls(canister_id: CanisterId) {
    // TODO - remove entries in the map once their counter is decremented to
    // zero.
    OPEN_CANISTER_STATUS_CALLS.with(|open_calls| {
        open_calls.borrow_mut().entry(canister_id).or_insert(0);
        if let Some(counter) = open_calls.borrow_mut().get_mut(&canister_id) {
            *counter = counter.saturating_sub(1_u64);
        }
    });
}

/// Encode the metrics in a format that can be understood by Prometheus.
pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let open_canister_status_calls = OPEN_CANISTER_STATUS_CALLS
        .with(|open_canister_status_calls| open_canister_status_calls.borrow().clone());

    let open_canister_status_calls_count: u64 = open_canister_status_calls.values().sum();

    w.encode_gauge(
        "nns_root_open_canister_status_calls_count",
        open_canister_status_calls_count as f64,
        "Count of open CanisterStatusCalls.",
    )?;

    let mut metrics = w.gauge_vec(
        "nns_root_open_canister_status_calls",
        "The list of counters and canister_ids with open canister_status calls.",
    )?;

    for (canister_id, call_count) in open_canister_status_calls.iter() {
        metrics = metrics.value(
            &[("canister_id", &format!("{}", canister_id))],
            (*call_count) as f64,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        decrement_open_canister_status_calls, increment_open_canister_status_calls,
        OPEN_CANISTER_STATUS_CALLS,
    };
    use ic_base_types::{CanisterId, PrincipalId};

    fn get_canister_open_canister_status_calls(canister_id: CanisterId) -> Option<u64> {
        OPEN_CANISTER_STATUS_CALLS.with(|open_calls| open_calls.borrow().get(&canister_id).cloned())
    }

    #[test]
    pub fn test_increment_open_canister_status_calls() {
        // Set up some test data
        let canister_id_1 = CanisterId::try_from(PrincipalId::new_user_test_id(1)).unwrap();
        let canister_id_2 = CanisterId::try_from(PrincipalId::new_user_test_id(2)).unwrap();

        // Assert that the value is None if a canister has never been incremented
        assert_eq!(get_canister_open_canister_status_calls(canister_id_1), None);

        // Increment and check the value has increased
        increment_open_canister_status_calls(canister_id_1);
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_1),
            Some(1)
        );

        // Assert that the value is None if a canister has never been incremented.
        assert_eq!(get_canister_open_canister_status_calls(canister_id_2), None);

        // Increment a different canister and make sure it's count is incremented
        increment_open_canister_status_calls(canister_id_2);
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_2),
            Some(1)
        );

        // Increment both keys
        increment_open_canister_status_calls(canister_id_1);
        increment_open_canister_status_calls(canister_id_2);

        // Assert the values have both been incremented again.
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_1),
            Some(2)
        );
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_2),
            Some(2)
        );
    }

    #[test]
    pub fn test_decrement_open_canister_status_calls() {
        // Set up some test data
        let canister_id_1 = CanisterId::try_from(PrincipalId::new_user_test_id(1)).unwrap();
        let canister_id_2 = CanisterId::try_from(PrincipalId::new_user_test_id(2)).unwrap();
        let canister_id_3 = CanisterId::try_from(PrincipalId::new_user_test_id(3)).unwrap();

        // Populate some keys with counts by incrementing
        for _ in 0..3 {
            increment_open_canister_status_calls(canister_id_1);
            increment_open_canister_status_calls(canister_id_2);
        }

        // Assert that both keys have expected values
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_1),
            Some(3)
        );
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_2),
            Some(3)
        );

        // Decrement a key and check its value and the other value in the map
        decrement_open_canister_status_calls(canister_id_1);
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_1),
            Some(2)
        );
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_2),
            Some(3)
        );

        // Decrement a different key past zero. This should result in 0 instead of a panic
        for _ in 0..4 {
            decrement_open_canister_status_calls(canister_id_2);
        }
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_1),
            Some(2)
        );
        assert_eq!(
            get_canister_open_canister_status_calls(canister_id_2),
            Some(0)
        );

        // Decrement a non-existent key. This should result in 0 and not a panic.
        assert_eq!(get_canister_open_canister_status_calls(canister_id_3), None);
        decrement_open_canister_status_calls(canister_id_3);
        assert_eq!(get_canister_open_canister_status_calls(canister_id_3), None);
    }
}
