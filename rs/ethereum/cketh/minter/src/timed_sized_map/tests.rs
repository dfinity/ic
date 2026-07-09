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
fn should_evict_oldest_when_over_capacity() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(3));
    assert!(map.insert(ts(1), "a", 1).is_empty());
    assert!(map.insert(ts(2), "b", 2).is_empty());
    assert!(map.insert(ts(3), "c", 3).is_empty());
    assert_eq!(map.len(), 3);

    let evicted = map.insert(ts(4), "d", 4);

    assert_eq!(evicted, vec![("a", 1)]);
    assert_eq!(map.len(), 3);
    assert_eq!(map.get(ts(4), &"a"), None);
    assert_eq!(map.get(ts(4), &"d"), Some(&4));
    assert_consistent(&map);
}

#[test]
fn should_expire_entries_after_ttl() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(10));
    map.insert(ts(0), "a", 1);

    assert_eq!(map.get(ts(9), &"a"), Some(&1));
    assert_eq!(map.get(ts(10), &"a"), None);
    assert_eq!(map.len(), 1);

    let evicted = map.evict_expired(ts(10));

    assert_eq!(evicted, vec![("a", 1)]);
    assert!(map.is_empty());
    assert_consistent(&map);
}

#[test]
fn should_evict_expired_before_applying_capacity() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(2));
    map.insert(ts(0), "a", 1);
    map.insert(ts(1), "b", 2);

    let mut evicted = map.insert(ts(11), "c", 3);
    evicted.sort();

    assert_eq!(evicted, vec![("a", 1), ("b", 2)]);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(ts(11), &"c"), Some(&3));
    assert_consistent(&map);
}

#[test]
fn should_refresh_existing_key_without_growing_or_evicting() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(2));
    map.insert(ts(1), "a", 1);
    map.insert(ts(2), "b", 2);

    let evicted = map.insert(ts(3), "a", 11);

    assert!(evicted.is_empty());
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(ts(3), &"a"), Some(&11));

    let evicted = map.insert(ts(4), "c", 3);
    assert_eq!(evicted, vec![("b", 2)]);
    assert_eq!(map.get(ts(4), &"a"), Some(&11));
    assert_consistent(&map);
}

#[test]
fn should_extend_lifetime_on_refresh() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));
    map.insert(ts(0), "a", 1);
    map.insert(ts(5), "a", 2);

    assert_eq!(map.get(ts(12), &"a"), Some(&2));
    assert_eq!(map.get(ts(15), &"a"), None);
}

#[test]
fn should_not_report_refresh_of_expired_key_as_eviction() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(5));
    map.insert(ts(0), "a", 1);

    let evicted = map.insert(ts(20), "a", 2);

    assert!(evicted.is_empty());
    assert_eq!(map.get(ts(20), &"a"), Some(&2));
    assert_eq!(map.len(), 1);
    assert_consistent(&map);
}

#[test]
fn should_evict_expired_then_oldest_under_both_pressures() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(10), cap(2));
    map.insert(ts(0), "a", 1);
    map.insert(ts(3), "b", 2);

    let evicted = map.insert(ts(11), "c", 3);
    assert_eq!(evicted, vec![("a", 1)]);
    assert_eq!(map.len(), 2);

    let evicted = map.insert(ts(12), "d", 4);
    assert_eq!(evicted, vec![("b", 2)]);
    assert_eq!(map.get(ts(12), &"c"), Some(&3));
    assert_eq!(map.get(ts(12), &"d"), Some(&4));
    assert_consistent(&map);
}

#[test]
fn should_evict_fifo_within_equal_timestamps() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(1000), cap(2));
    map.insert(ts(5), "a", 1);
    map.insert(ts(5), "b", 2);

    let evicted = map.insert(ts(6), "c", 3);

    assert_eq!(evicted, vec![("a", 1)]);
    assert_eq!(map.get(ts(6), &"b"), Some(&2));
    assert_eq!(map.get(ts(6), &"c"), Some(&3));
    assert_consistent(&map);
}

#[test]
fn should_keep_indices_consistent_through_churn() {
    let mut map = TimedSizedMap::new(Duration::from_nanos(100), cap(4));
    for (i, key) in ["a", "b", "c", "d", "e", "f"].into_iter().enumerate() {
        map.insert(ts(i as u64 + 1), key, i);
    }
    assert_eq!(map.len(), 4);
    let mut live: Vec<&str> = map.iter().map(|(k, _)| *k).collect();
    live.sort();
    assert_eq!(live, vec!["c", "d", "e", "f"]);
    assert_consistent(&map);

    map.insert(ts(10), "c", 99);
    let evicted = map.evict_expired(ts(1000));
    assert_eq!(evicted.len(), 4);
    assert!(map.is_empty());
    assert_consistent(&map);
}
