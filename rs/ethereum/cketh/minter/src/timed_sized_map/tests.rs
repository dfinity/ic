use super::*;
use std::num::NonZeroUsize;
use std::time::Duration;

fn ts(nanos: u64) -> Timestamp {
    Timestamp::from_nanos(nanos)
}

fn cap(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

fn assert_consistent<K: Ord + Clone + std::fmt::Debug, V>(map: &TimedSizedMap<K, V>) {
    let indexed: Vec<K> = map.by_time.values().flatten().cloned().collect();
    assert_eq!(
        indexed.len(),
        map.entries.len(),
        "index and entry counts disagree"
    );
    for (key, entry) in &map.entries {
        let bucket = map
            .by_time
            .get(&entry.expires_at)
            .expect("entry timestamp missing from time index");
        assert!(
            bucket.contains(key),
            "entry {key:?} not in its timestamp bucket"
        );
    }
}

#[test]
fn should_be_empty_on_creation() {
    let map: TimedSizedMap<&str, u32> = TimedSizedMap::new(Duration::from_nanos(10), cap(4));
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    assert_eq!(map.capacity(), cap(4));
    assert_eq!(map.get(ts(0), &"absent"), None);
}

#[test]
fn should_reject_new_key_when_full_of_live_entries() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(3));
    map.insert(ts(1), "a", 1).unwrap();
    map.insert(ts(2), "b", 2).unwrap();
    map.insert(ts(3), "c", 3).unwrap();
    let before = map.clone();

    let rejected = map.insert(ts(4), "d", 4);

    assert_eq!(
        rejected,
        Err(InsertError::AtCapacity { key: "d", value: 4 })
    );
    assert_eq!(map, before);
    assert_consistent(&map);
}

#[test]
fn should_reject_refresh_of_live_key() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(5));
    map.insert(ts(1), "a", 1).unwrap();
    let before = map.clone();

    let rejected = map.insert(ts(2), "a", 2);

    assert_eq!(
        rejected,
        Err(InsertError::AlreadyPresent { key: "a", value: 2 })
    );
    assert_eq!(map, before);
    assert_eq!(map.get(ts(2), &"a"), Some(&1));
    assert_consistent(&map);
}

#[test]
fn should_not_evict_expired_entries_when_rejecting_a_live_refresh() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));
    map.insert(ts(0), "dormant", 1).unwrap();
    map.insert(ts(5), "live", 2).unwrap();
    let before = map.clone();

    let rejected = map.insert(ts(12), "live", 3);

    assert!(matches!(rejected, Err(InsertError::AlreadyPresent { .. })));
    assert_eq!(map, before);
    assert_eq!(map.len(), 2);
    assert_consistent(&map);
}

#[test]
fn should_admit_new_key_after_expired_entries_free_room() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(2));
    map.insert(ts(0), "a", 1).unwrap();
    map.insert(ts(1), "b", 2).unwrap();

    let mut evicted = map.insert(ts(12), "c", 3).unwrap();
    evicted.sort();

    assert_eq!(evicted, vec![("a", 1), ("b", 2)]);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(ts(12), &"c"), Some(&3));
    assert_consistent(&map);
}

#[test]
fn should_readmit_expired_key_as_fresh_entry() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));
    map.insert(ts(0), "a", 1).unwrap();

    let evicted = map.insert(ts(20), "a", 2).unwrap();

    assert_eq!(evicted, vec![("a", 1)]);
    assert_eq!(map.get(ts(20), &"a"), Some(&2));
    assert_eq!(map.len(), 1);
    assert_consistent(&map);
}

#[test]
fn should_expire_entries_after_ttl() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(10));
    map.insert(ts(0), "a", 1).unwrap();

    assert_eq!(map.get(ts(10), &"a"), Some(&1));
    assert_eq!(map.get(ts(11), &"a"), None);
    assert_eq!(map.len(), 1);

    let evicted = map.evict_expired(ts(11));

    assert_eq!(evicted, vec![("a", 1)]);
    assert!(map.is_empty());
    assert_consistent(&map);
}

#[test]
fn should_clamp_insert_entry_expiry_to_ttl() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));

    // The entry claims to live until ts(100), but the cache ttl caps it at ts(10).
    map.insert_entry(
        ts(0),
        "a",
        Entry {
            value: 1,
            expires_at: ts(100),
        },
    )
    .unwrap();

    assert_eq!(map.get(ts(10), &"a"), Some(&1));
    assert_eq!(map.get(ts(11), &"a"), None);
    assert_consistent(&map);
}

#[test]
fn should_keep_insert_entry_expiry_shorter_than_ttl() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));

    map.insert_entry(
        ts(0),
        "a",
        Entry {
            value: 1,
            expires_at: ts(5),
        },
    )
    .unwrap();

    assert_eq!(map.get(ts(5), &"a"), Some(&1));
    assert_eq!(map.get(ts(6), &"a"), None);
    assert_consistent(&map);
}

#[test]
fn should_ignore_already_expired_insert_entry() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));

    let evicted = map
        .insert_entry(
            ts(20),
            "a",
            Entry {
                value: 1,
                expires_at: ts(5),
            },
        )
        .unwrap();

    assert!(evicted.is_empty());
    assert!(map.is_empty());
    assert_eq!(map.get(ts(20), &"a"), None);
    assert_consistent(&map);
}

#[test]
fn should_reject_insert_entry_when_full_of_live_entries() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(1));
    map.insert(ts(1), "a", 1).unwrap();
    let before = map.clone();

    let rejected = map.insert_entry(
        ts(2),
        "b",
        Entry {
            value: 2,
            expires_at: ts(500),
        },
    );

    assert_eq!(
        rejected,
        Err(InsertError::AtCapacity { key: "b", value: 2 })
    );
    assert_eq!(map, before);
    assert_consistent(&map);
}

#[test]
fn should_keep_indices_consistent_through_churn() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(100), cap(4));
    for (i, key) in ["a", "b", "c", "d"].into_iter().enumerate() {
        map.insert(ts(i as u64 + 1), key, i).unwrap();
    }
    assert_eq!(map.len(), 4);
    assert_consistent(&map);

    assert!(matches!(
        map.insert(ts(5), "e", 4),
        Err(InsertError::AtCapacity { .. })
    ));
    assert!(matches!(
        map.insert(ts(6), "a", 99),
        Err(InsertError::AlreadyPresent { .. })
    ));
    assert_eq!(map.len(), 4);
    assert_consistent(&map);

    let evicted = map.evict_expired(ts(1000));
    assert_eq!(evicted.len(), 4);
    assert!(map.is_empty());
    assert_consistent(&map);
}

#[test]
fn should_round_trip_through_from_ordered_entries() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(100), cap(5));
    // "b" and "a" share an expiry, so their by_time bucket order (insertion order)
    // differs from key order; a faithful round-trip must preserve it.
    map.insert(ts(0), "b", 2).unwrap();
    map.insert(ts(0), "a", 1).unwrap();
    map.insert(ts(10), "c", 3).unwrap();

    let entries: Vec<_> = map
        .iter_by_expiry()
        .map(|(key, entry)| (*key, entry.clone()))
        .collect();
    let restored = TimedSizedMap::from_ordered_entries(map.ttl(), map.capacity(), entries);

    assert_eq!(restored, map);
    assert_consistent(&restored);
}

#[test]
fn should_preserve_expired_entries_when_rebuilding() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));
    map.insert(ts(0), "a", 1).unwrap();
    let entries: Vec<_> = map
        .iter_by_expiry()
        .map(|(key, entry)| (*key, entry.clone()))
        .collect();

    let restored = TimedSizedMap::from_ordered_entries(map.ttl(), map.capacity(), entries);

    assert_eq!(restored, map);
    assert_eq!(restored.len(), 1);
    // The entry is expired as of ts(20) but still physically held, exactly like
    // the live map that produced the snapshot.
    assert_eq!(restored.get(ts(20), &"a"), None);
    assert_consistent(&restored);
}

#[test]
#[should_panic(expected = "duplicate key")]
fn should_panic_on_duplicate_key_in_from_ordered_entries() {
    let entry = Entry {
        value: 1,
        expires_at: ts(10),
    };
    let _ = TimedSizedMap::from_ordered_entries(
        Duration::from_nanos(10),
        cap(5),
        vec![("a", entry.clone()), ("a", entry)],
    );
}
