use crate::timestamp::TimeStamp;
use ic_stable_structures::Storable;
use proptest::prelude::{any, prop_assert_eq, proptest};

#[test]
fn timestamp_serialization() {
    proptest!(|(ts_u64 in any::<u64>())| {
        let timestamp = TimeStamp::from_nanos_since_unix_epoch(ts_u64);
        let new_timestamp  = TimeStamp::from_bytes(timestamp.to_bytes());
        prop_assert_eq!(new_timestamp, timestamp);
    })
}
