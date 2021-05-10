use super::IntMap;

#[test]
fn test_int_map_consecutive_inserts() {
    let m: IntMap<u64> = (0..100u64).map(|x| (x, x + 100)).collect();

    for i in 0..100u64 {
        assert_eq!(
            m.get(i).cloned(),
            Some(i + 100),
            "failed to find inserted values, map: {:?}",
            m
        );
    }
}

#[test]
fn test_int_map_sparse_inserts() {
    let m: IntMap<u64> = (0..100u64)
        .filter(|x| x % 2 == 0)
        .map(|x| (x, x + 100))
        .collect();

    for i in 0..100u64 {
        if i % 2 == 0 {
            assert_eq!(m.get(i).cloned(), Some(i + 100));
        } else {
            assert_eq!(m.get(i).cloned(), None);
        }
    }
}

#[test]
fn test_int_map_union() {
    let lmap: IntMap<u64> = (1..101u64).map(|x| (x, x)).collect();
    let rmap: IntMap<u64> = (50..150u64).map(|x| (x, x + 100)).collect();
    let m = rmap.union(lmap);

    assert!(m.get(0).is_none());
    for i in 1..50u64 {
        assert_eq!(m.get(i).cloned(), Some(i));
    }
    for i in 50..150u64 {
        assert_eq!(m.get(i).cloned(), Some(i + 100), "Map: {:?}", m);
    }
    assert!(m.get(150).is_none());
}

#[test]
fn test_iter() {
    use std::collections::BTreeMap;

    let int_map: IntMap<_> = (1..100u64).map(|x| (x, x)).collect();
    let btree_map: BTreeMap<_, _> = (1..100u64).map(|x| (x, x)).collect();

    assert!(int_map.iter().eq(btree_map.iter().map(|(k, v)| (*k, v))));
}
