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
            .get(&entry.inserted_at)
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
