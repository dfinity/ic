use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[test]
fn test_int_map_consecutive_inserts() {
    let m: IntMap<u64, u64> = (0..100u64).map(|x| (x, x + 100)).collect();

    for i in 0..100u64 {
        assert_eq!(
            m.get(&i).cloned(),
            Some(i + 100),
            "failed to find inserted values, map: {m:?}"
        );
    }
}

#[test]
fn test_int_map_sparse_inserts() {
    let m: IntMap<u64, u64> = (0..100u64)
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
    let lmap: IntMap<u64, u64> = (1..101u64).map(|x| (x, x)).collect();
    let rmap: IntMap<u64, u64> = (50..150u64).map(|x| (x, x + 100)).collect();
    let m = rmap.union(lmap);

    assert!(m.get(&0).is_none());
    for i in 1..50u64 {
        assert_eq!(m.get(&i).cloned(), Some(i));
    }
    for i in 50..150u64 {
        assert_eq!(m.get(&i).cloned(), Some(i + 100), "Map: {m:?}");
    }
    assert!(m.get(&150).is_none());
}

#[test]
fn test_iter() {
    let int_map: IntMap<u64, _> = (1..100u64).map(|x| (x, x)).collect();
    let btree_map: BTreeMap<_, _> = (1..100u64).map(|x| (x, x)).collect();

    assert!(int_map.iter().eq(btree_map.iter()));
}

#[test]
fn test_int_map_bounds() {
    let m: IntMap<u64, u64> = (10..=100u64).map(|x| (7 * x, 0)).collect();
    for i in 0..800 {
        let (start, end) = m.bounds(&i);
        if (70..=700).contains(&i) {
            assert_eq!(start, Some((&((i / 7) * 7), &0)));
            assert_eq!(end, Some((&(i.div_ceil(7) * 7), &0)));
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
    let m = IntMap::<u64, u64>::new();
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
    let mut m = IntMap::<u64, u64>::new();
    for i in 0..1000u64 {
        m = m.insert(i, i + 100).0;
        assert_eq!(m.max_key(), Some(&i));
    }
}

#[test_strategy::proptest]
fn test_insert(#[strategy(proptest::collection::vec(0u64..20u64, 10))] keys: Vec<u64>) {
    let mut btree_map = BTreeMap::new();
    let mut int_map = IntMap::new();
    let mut mutable_int_map = MutableIntMap::new();
    for (value, key) in keys.into_iter().enumerate() {
        let expected = btree_map.insert(key, value);

        let previous;
        (int_map, previous) = int_map.insert(key, value);
        prop_assert!(is_well_formed(&int_map.0));
        prop_assert_eq!(expected, previous);
        prop_assert_eq!(btree_map.len(), int_map.len());
        prop_assert!(btree_map.iter().eq(int_map.iter()));

        prop_assert!(is_well_formed(&mutable_int_map.tree));
        prop_assert_eq!(expected, mutable_int_map.insert(key, value));
        prop_assert_eq!(btree_map.len(), mutable_int_map.len());
        prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));
    }
}

/// Creates 3 maps with identical contents, from the given keys.
#[allow(clippy::type_complexity)]
fn make_maps(
    keys: Vec<u64>,
) -> (
    BTreeMap<u64, usize>,
    IntMap<u64, usize>,
    MutableIntMap<u64, usize>,
) {
    let mut btree_map = BTreeMap::new();
    let mut int_map = IntMap::new();
    let mut mutable_int_map = MutableIntMap::new();
    for (value, key) in keys.into_iter().enumerate() {
        btree_map.insert(key, value);
        int_map = int_map.insert(key, value).0;
        mutable_int_map.insert(key, value);
    }
    assert!(is_well_formed(&int_map.0));
    assert!(is_well_formed(&mutable_int_map.tree));
    (btree_map, int_map, mutable_int_map)
}

#[test_strategy::proptest]
fn test_lookup(
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>,
    #[strategy(proptest::collection::vec(0u64..20u64, 10))] lookups: Vec<u64>,
) {
    let (btree_map, int_map, mutable_int_map) = make_maps(keys);

    for key in lookups {
        prop_assert_eq!(btree_map.get(&key), int_map.get(&key));
        prop_assert_eq!(btree_map.get(&key), mutable_int_map.get(&key));

        prop_assert_eq!(btree_map.contains_key(&key), int_map.contains_key(&key));
        prop_assert_eq!(
            btree_map.contains_key(&key),
            mutable_int_map.contains_key(&key)
        );
    }
}

#[test_strategy::proptest]
fn test_bounds(
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>,
    #[strategy(proptest::collection::vec(0u64..20u64, 10))] lookups: Vec<u64>,
) {
    let (btree_map, int_map, mutable_int_map) = make_maps(keys);

    for key in lookups {
        let (lower, upper) = int_map.bounds(&key);
        prop_assert_eq!((lower, upper), mutable_int_map.bounds(&key));

        if lower == upper {
            if let Some((k, v)) = lower {
                // Exact match.
                prop_assert_eq!(k, &key);
                prop_assert_eq!(btree_map.get(&key), Some(v));
            } else {
                // Empty map.
                prop_assert!(int_map.is_empty());
            }
            continue;
        }

        prop_assert_eq!(btree_map.range(..key).next_back(), lower);
        prop_assert_eq!(btree_map.range(key..).next(), upper);
    }

    prop_assert_eq!(
        btree_map.last_key_value().map(|(k, _)| k),
        int_map.max_key()
    );
    prop_assert_eq!(
        btree_map.first_key_value().map(|(k, _)| k),
        mutable_int_map.min_key()
    );
    prop_assert_eq!(
        btree_map.last_key_value().map(|(k, _)| k),
        mutable_int_map.max_key()
    );
}

#[test_strategy::proptest]
fn test_remove(
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] inserts: Vec<u64>,
    #[strategy(proptest::collection::vec(0u64..20u64, 10))] removes: Vec<u64>,
) {
    let (mut btree_map, mut int_map, mut mutable_int_map) = make_maps(inserts);

    for key in removes {
        let expected = btree_map.remove(&key);

        let removed;
        (int_map, removed) = int_map.remove(&key);
        prop_assert!(is_well_formed(&int_map.0));
        prop_assert_eq!(expected, removed);
        prop_assert_eq!(btree_map.len(), int_map.len());
        prop_assert!(btree_map.iter().eq(int_map.iter()));

        prop_assert!(is_well_formed(&mutable_int_map.tree));
        prop_assert_eq!(expected, mutable_int_map.remove(&key));
        prop_assert_eq!(btree_map.len(), mutable_int_map.len());
        prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));
    }
}

#[test_strategy::proptest]
fn test_union(
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] first: Vec<u64>,
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] second: Vec<u64>,
) {
    let (mut first_btree_map, first_int_map, mut mutable_int_map) = make_maps(first);
    let (mut btree_map, second_int_map, second_mutable_int_map) = make_maps(second);

    btree_map.append(&mut first_btree_map);
    let int_map = first_int_map.union(second_int_map);
    mutable_int_map.union(second_mutable_int_map);

    prop_assert!(is_well_formed(&int_map.0));
    prop_assert_eq!(btree_map.len(), int_map.len());
    prop_assert!(btree_map.iter().eq(int_map.iter()));

    prop_assert!(is_well_formed(&mutable_int_map.tree));
    prop_assert_eq!(btree_map.len(), mutable_int_map.len());
    prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));
}

#[test_strategy::proptest]
fn test_split_off(
    #[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>,
    #[strategy(0u64..20u64)] split_key: u64,
) {
    let (mut btree_map, _, mut mutable_int_map) = make_maps(keys);

    let btree_right = btree_map.split_off(&split_key);
    let mutable_int_right = mutable_int_map.split_off(&split_key);

    prop_assert!(is_well_formed(&mutable_int_map.tree));
    prop_assert_eq!(btree_map.len(), mutable_int_map.len());
    prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));

    prop_assert!(is_well_formed(&mutable_int_right.tree));
    prop_assert_eq!(btree_right.len(), mutable_int_right.len());
    prop_assert!(btree_right.iter().eq(mutable_int_right.iter()));
}

#[test_strategy::proptest]
fn test_len(#[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>) {
    let (btree_map, int_map, mutable_int_map) = make_maps(keys);

    prop_assert_eq!(btree_map.len(), int_map.len());
    prop_assert_eq!(btree_map.len(), mutable_int_map.len());

    prop_assert_eq!(btree_map.is_empty(), int_map.is_empty());
    prop_assert_eq!(btree_map.is_empty(), mutable_int_map.is_empty());
}

#[test_strategy::proptest]
fn test_iterators(#[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>) {
    let (btree_map, int_map, mutable_int_map) = make_maps(keys);

    prop_assert!(btree_map.iter().eq(int_map.iter()));
    prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));

    prop_assert!(btree_map.keys().eq(int_map.keys()));
    prop_assert!(btree_map.keys().eq(mutable_int_map.keys()));

    prop_assert!(btree_map.values().eq(mutable_int_map.values()));

    prop_assert!(btree_map.into_iter().eq(mutable_int_map.into_iter()));
}

#[test_strategy::proptest]
fn test_from_iter(#[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>) {
    let (btree_map, _, mutable_int_map) = make_maps(keys);

    let int_map = btree_map.clone().into_iter().collect::<IntMap<_, _>>();
    prop_assert!(is_well_formed(&int_map.0));
    prop_assert_eq!(btree_map.len(), int_map.len());
    prop_assert!(btree_map.iter().eq(int_map.iter()));

    let mutable_int_map = mutable_int_map.into_iter().collect::<MutableIntMap<_, _>>();
    prop_assert!(is_well_formed(&mutable_int_map.tree));
    prop_assert_eq!(btree_map.len(), mutable_int_map.len());
    prop_assert!(btree_map.iter().eq(mutable_int_map.iter()));
}

#[test_strategy::proptest]
fn test_eq(#[strategy(proptest::collection::vec(0u64..20u64, 0..10))] keys: Vec<u64>) {
    use ic_validate_eq::ValidateEq;
    use std::fmt::Debug;

    #[derive(Clone, Debug, PartialEq)]
    struct Foo(usize);
    impl ValidateEq for Foo {
        fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
            if self.0 != rhs.0 {
                return Err(format!("lhs = {self:#?}, rhs = {rhs:#?}"));
            }
            Ok(())
        }
    }

    fn assert_eq<M>(lhs: &M, rhs: &M) -> Result<(), TestCaseError>
    where
        M: Debug + PartialEq + ValidateEq,
    {
        prop_assert_eq!(lhs, rhs);
        prop_assert_eq!(Ok(()), lhs.validate_eq(rhs));
        Ok(())
    }
    fn assert_ne<M>(lhs: &M, rhs: &M) -> Result<(), TestCaseError>
    where
        M: Debug + PartialEq + ValidateEq,
    {
        prop_assert_ne!(lhs, rhs);
        prop_assert_ne!(Ok(()), lhs.validate_eq(rhs));
        Ok(())
    }

    let mut int_map = IntMap::new();
    let mut mutable_int_map = MutableIntMap::new();
    for (value, key) in keys.into_iter().enumerate() {
        int_map = int_map.insert(key, Foo(value)).0;
        mutable_int_map.insert(key, Foo(value));
    }

    let initial_int_map = int_map.clone();
    let initial_mutable_int_map = mutable_int_map.clone();
    assert_eq(&initial_int_map, &int_map)?;
    assert_eq(&initial_mutable_int_map, &mutable_int_map)?;

    // No longer equal after an insert.
    let int_map = int_map.insert(99, Foo(13)).0;
    prop_assert!(mutable_int_map.insert(99, Foo(13)).is_none());
    assert_ne(&initial_int_map, &int_map)?;
    assert_ne(&initial_mutable_int_map, &mutable_int_map)?;

    // Need a non-empty map to test equality after remove.
    if !initial_int_map.is_empty() {
        let key = initial_int_map.max_key().unwrap();

        // No longer equal after a remove.
        let int_map = initial_int_map.clone().remove(key).0;
        let mut mutable_int_map = initial_mutable_int_map.clone();
        prop_assert!(mutable_int_map.remove(key).is_some());
        assert_ne(&initial_int_map, &int_map)?;
        assert_ne(&initial_mutable_int_map, &mutable_int_map)?;
    }
}

#[test_strategy::proptest]
fn test_u64_values(
    #[strategy(proptest::collection::vec(any::<u64>(), 0..10))] keys: Vec<u64>,
    #[strategy(proptest::collection::vec(any::<u64>(), 10))] lookups: Vec<u64>,
) {
    let (btree_map, int_map, mutable_int_map) = make_maps(keys);

    for key in lookups {
        prop_assert_eq!(btree_map.get(&key), int_map.get(&key));
        prop_assert_eq!(btree_map.get(&key), mutable_int_map.get(&key));
    }
}

#[test_strategy::proptest]
fn test_u128_values(
    #[strategy(proptest::collection::vec(any::<u128>(), 0..10))] keys: Vec<u128>,
    #[strategy(proptest::collection::vec(any::<u128>(), 10))] lookups: Vec<u128>,
) {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct Key128(u64, u64);
    impl Key128 {
        fn new(value: u128) -> Self {
            Key128((value >> 64) as u64, value as u64)
        }
    }
    impl AsInt for Key128 {
        type Repr = u128;

        #[inline]
        fn as_int(&self) -> u128 {
            ((self.0 as u128) << 64) | self.1 as u128
        }
    }

    let mut btree_map = BTreeMap::new();
    let mut int_map = IntMap::new();
    let mut mutable_int_map = MutableIntMap::new();
    for (value, key) in keys.into_iter().enumerate() {
        let key = Key128::new(key);
        btree_map.insert(key, value);
        int_map = int_map.insert(key, value).0;
        mutable_int_map.insert(key, value);
    }
    prop_assert!(is_well_formed(&int_map.0));
    prop_assert!(is_well_formed(&mutable_int_map.tree));

    for key in lookups {
        let key = Key128::new(key);
        prop_assert_eq!(btree_map.get(&key), int_map.get(&key));
        prop_assert_eq!(btree_map.get(&key), mutable_int_map.get(&key));
    }
}

#[test]
fn test_validate_eq() {
    use ic_validate_eq::ValidateEq;

    #[derive(Clone, Debug, PartialEq)]
    struct MyU64(u64);
    impl ValidateEq for MyU64 {
        fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
            if self.0 != rhs.0 {
                return Err(format!("{} != {}", self.0, rhs.0));
            }
            Ok(())
        }
    }

    fn do_validate_eq(lhs: &[(u64, u64)], rhs: &[(u64, u64)]) -> Result<(), String> {
        let left: IntMap<u64, MyU64> = lhs.iter().map(|(k, v)| (*k, MyU64(*v))).collect();
        let right: IntMap<u64, MyU64> = rhs.iter().map(|(k, v)| (*k, MyU64(*v))).collect();
        left.validate_eq(&right)
    }

    assert!(do_validate_eq(&[], &[]).is_ok());
    assert!(do_validate_eq(&[(1, 2)], &[(1, 2)]).is_ok());
    assert!(do_validate_eq(&[(1, 2), (7, 8)], &[(1, 2), (7, 8)]).is_ok());

    assert_eq!(
        Err("Length divergence: 0 != 1".to_string()),
        do_validate_eq(&[], &[(1, 2)])
    );
    assert_eq!(
        Err("Length divergence: 2 != 1".to_string()),
        do_validate_eq(&[(1, 2), (7, 8)], &[(1, 2)])
    );
    assert_eq!(
        Err("Key divergence: 7 != 8".to_string()),
        do_validate_eq(&[(1, 2), (7, 8)], &[(1, 2), (8, 8)])
    );
    assert_eq!(
        Err("Value divergence @7: 8 != 7".to_string()),
        do_validate_eq(&[(1, 2), (7, 8)], &[(1, 2), (7, 7)])
    );
}

/// Returns `true` iff the tree is well formed.
fn is_well_formed<K: AsInt, V: Clone>(tree: &Tree<K, V>) -> bool {
    match tree {
        Tree::Empty => true,

        Tree::Leaf(_, _) => true,

        Tree::Branch {
            prefix,
            branching_bit,
            left,
            right,
        } => {
            let valid_left = match left.as_ref() {
                Tree::Leaf(k, _) => {
                    matches_prefix(k.as_int(), *prefix, *branching_bit)
                        && k.as_int() & (K::Repr::one() << *branching_bit) == K::Repr::zero()
                }
                Tree::Branch {
                    prefix: p,
                    branching_bit: b,
                    ..
                } => {
                    b < branching_bit
                        && matches_prefix(*p, *prefix, *branching_bit)
                        && *p & (K::Repr::one() << *branching_bit) == K::Repr::zero()
                        && is_well_formed(left.as_ref())
                }
                Tree::Empty => false,
            };
            let valid_right = match right.as_ref() {
                Tree::Leaf(k, _) => {
                    matches_prefix(k.as_int(), *prefix, *branching_bit)
                        && k.as_int() & (K::Repr::one() << *branching_bit) != K::Repr::zero()
                }
                Tree::Branch {
                    prefix: p,
                    branching_bit: b,
                    ..
                } => {
                    b < branching_bit
                        && matches_prefix(*p, *prefix, *branching_bit)
                        && *p & (K::Repr::one() << *branching_bit) != K::Repr::zero()
                        && is_well_formed(right.as_ref())
                }
                Tree::Empty => false,
            };
            valid_left && valid_right
        }
    }
}
