use super::IntMap;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[test]
fn test_int_map_consecutive_inserts() {
    let m: IntMap<u64, u64, _> = (0..100u64).map(|x| (x, x + 100)).collect();

    for i in 0..100u64 {
        assert_eq!(
            m.get(&i).cloned(),
            Some(i + 100),
            "failed to find inserted values, map: {:?}",
            m
        );
    }
}

#[test]
fn test_int_map_sparse_inserts() {
    let m: IntMap<u64, u64, _> = (0..100u64)
        .filter(|x| x % 2 == 0)
        .map(|x| (x, x + 100))
        .collect();

    for i in 0..100u64 {
        if i % 2 == 0 {
            assert_eq!(m.get(&i).cloned(), Some(i + 100));
        } else {
            assert_eq!(m.get(&i).cloned(), None);
        }
    }
}

#[test]
fn test_int_map_union() {
    let lmap: IntMap<u64, u64, _> = (1..101u64).map(|x| (x, x)).collect();
    let rmap: IntMap<u64, u64, _> = (50..150u64).map(|x| (x, x + 100)).collect();
    let m = rmap.union(lmap);

    assert!(m.get(&0).is_none());
    for i in 1..50u64 {
        assert_eq!(m.get(&i).cloned(), Some(i));
    }
    for i in 50..150u64 {
        assert_eq!(m.get(&i).cloned(), Some(i + 100), "Map: {:?}", m);
    }
    assert!(m.get(&150).is_none());
}

#[test]
fn test_iter() {
    let int_map: IntMap<u64, _, _> = (1..100u64).map(|x| (x, x)).collect();
    let btree_map: BTreeMap<_, _> = (1..100u64).map(|x| (x, x)).collect();

    assert!(int_map.iter().eq(btree_map.iter()));
}

#[test]
fn test_int_map_bounds() {
    let m: IntMap<u64, u64, _> = (10..=100u64).map(|x| (7 * x, 0)).collect();
    for i in 0..800 {
        let (start, end) = m.bounds(&i);
        if (70..=700).contains(&i) {
            assert_eq!(start, Some((&((i / 7) * 7), &0)));
            assert_eq!(end, Some((&(((i + 6) / 7) * 7), &0)));
        } else if i < 70 {
            assert_eq!(start, None);
            assert_eq!(end, Some((&70, &0)));
        } else {
            assert_eq!(start, Some((&700, &0)));
            assert_eq!(end, None)
        }
    }
}

#[test]
fn test_max_key() {
    let m = IntMap::<u64, u64, _>::new();
    assert_eq!(m.max_key(), None);
    let m = m.insert(100, 101).0;
    assert_eq!(m.max_key(), Some(&100));
    let m = m.insert(10, 101).0;
    assert_eq!(m.max_key(), Some(&100));
    let m = m.insert(1000, 101).0;
    assert_eq!(m.max_key(), Some(&1000));
    let m = m.insert(1000000, 101).0;
    assert_eq!(m.max_key(), Some(&1000000));
}

#[test]
fn test_max_key_range() {
    let mut m = IntMap::<u64, u64, _>::new();
    for i in 0..1000u64 {
        m = m.insert(i, i + 100).0;
        assert_eq!(m.max_key(), Some(&i));
    }
}

#[test_strategy::proptest]
fn test_insert(#[strategy(proptest::collection::vec(0u64..20u64, 10))] keys: Vec<u64>) {
    let mut btree_map = BTreeMap::new();
    let mut int_map = IntMap::new();
    for (value, key) in keys.into_iter().enumerate() {
        let expected = btree_map.insert(key, value);
        let previous;
        (int_map, previous) = int_map.insert(key, value);
        prop_assert_eq!(expected, previous);

        prop_assert_eq!(btree_map.len(), int_map.len());
        prop_assert!(btree_map.iter().eq(int_map.iter()));
    }
}

#[test_strategy::proptest]
fn test_remove(
    #[strategy(proptest::collection::vec(0u64..20u64, 10))] inserts: Vec<u64>,
    #[strategy(proptest::collection::vec(0u64..20u64, 10))] removes: Vec<u64>,
) {
    let mut btree_map = BTreeMap::new();
    let mut int_map = IntMap::new();
    for (value, key) in inserts.into_iter().enumerate() {
        btree_map.insert(key, value);
        int_map = int_map.insert(key, value).0;
    }

    for key in removes {
        let expected = btree_map.remove(&key);
        let removed;
        (int_map, removed) = int_map.remove(&key);
        prop_assert_eq!(expected, removed);

        prop_assert_eq!(btree_map.len(), int_map.len());
        prop_assert!(btree_map.iter().eq(int_map.iter()));
    }
}
