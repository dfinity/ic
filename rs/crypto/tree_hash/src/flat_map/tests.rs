#![allow(clippy::unwrap_used)]
use super::*;
use crate::flatmap;
use maplit::*;
use std::collections::BTreeMap;

#[test]
fn new() {
    let map: FlatMap<i32, i32> = FlatMap::new();

    assert!(map.is_empty());
    assert_eq!(0, map.len());
    assert!(map.keys.is_empty());
    assert!(map.values.is_empty());
}

#[test]
fn default() {
    let map: FlatMap<i32, i32> = FlatMap::default();

    assert!(map.is_empty());
    assert_eq!(0, map.len());
    assert!(map.keys.is_empty());
    assert!(map.values.is_empty());
}

#[test]
fn with_capacity() {
    let map: FlatMap<i32, i32> = FlatMap::with_capacity(13);

    assert!(map.is_empty());
    assert_eq!(0, map.len());
    assert!(map.keys.is_empty());
    assert!(map.values.is_empty());
    assert_eq!(13, map.keys.capacity());
    assert_eq!(13, map.values.capacity());
}

#[test]
fn from_key_values() {
    let map = FlatMap::from_key_values(vec![(1, 10), (3, 30), (2, 20), (1, 11)]);

    assert!(!map.is_empty());
    assert_eq!(3, map.len());

    let mut iter = map.iter();
    match iter.next() {
        Some((1, 10)) | Some((1, 11)) => {}
        other => panic!("Expecting `Ok((1, 10))` or `Ok((1, 11)`, got {:?})", other),
    }
    assert_eq!(Some((&2, &20)), iter.next());
    assert_eq!(Some((&3, &30)), iter.next());
    assert_eq!(None, iter.next());
}

#[test]
fn flatmap_macro() {
    let map = flatmap!(1 => 10, 3 => 30, 2 => 20, 1 => 11);

    assert!(!map.is_empty());
    assert_eq!(3, map.len());

    let mut iter = map.iter();
    match iter.next() {
        Some((1, 10)) | Some((1, 11)) => {}
        other => panic!("Expecting `Ok((1, 10))` or `Ok((1, 11)`, got {:?})", other),
    }
    assert_eq!(Some((&2, &20)), iter.next());
    assert_eq!(Some((&3, &30)), iter.next());
    assert_eq!(None, iter.next());
}

#[test]
fn eq() {
    assert_eq!(
        flatmap!(2 => 20, 1 => 10, 3 => 30),
        FlatMap::from_key_values(vec![(1, 10), (3, 30), (2, 20)])
    )
}

#[test]
fn get() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(Some(&10), map.get(&1));
    assert_eq!(Some(&20), map.get(&2));
    assert_eq!(Some(&30), map.get(&3));
    assert_eq!(None, map.get(&4));
}

#[test]
fn get_mut() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(Some(&mut 10), map.get_mut(&1));
    assert_eq!(Some(&mut 20), map.get_mut(&2));
    assert_eq!(Some(&mut 30), map.get_mut(&3));
    assert_eq!(None, map.get_mut(&4));

    map.get_mut(&1).map(|v| *v = 11).unwrap();

    assert_eq!(Some(&11), map.get(&1));
    assert_eq!(Some(&mut 11), map.get_mut(&1));
    assert_eq!(flatmap!(1 => 11, 2 => 20, 3 => 30), map);
}

#[test]
fn remove() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(Some(20), map.remove(&2));
    assert_eq!(None, map.remove(&2));
    assert_eq!(None, map.remove(&4));

    assert_eq!(flatmap!(1 => 10, 3 => 30), map);
}

#[test]
fn contains_key() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert!(map.contains_key(&1));
    assert!(map.contains_key(&2));
    assert!(map.contains_key(&3));
    assert!(!map.contains_key(&4));
}

#[test]
fn last_key() {
    let empty_map: FlatMap<i32, i32> = FlatMap::new();
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(None, empty_map.last_key());
    assert_eq!(Some(&3), map.last_key());
}

#[test]
fn try_append() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(Err((0, 1)), map.try_append(0, 1));
    assert_eq!(Err((3, 31)), map.try_append(3, 31));
    assert_eq!(Ok(()), map.try_append(4, 40));
    assert_eq!(Err((4, 41)), map.try_append(4, 41));

    assert_eq!(flatmap!(1 => 10, 2 => 20, 3 => 30, 4 => 40), map);
}

#[test]
fn iter() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(
        vec![(&1, &10), (&2, &20), (&3, &30)],
        map.iter().collect::<Vec<_>>()
    );
}

#[test]
fn double_ended_iterator() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let mut iter = map.iter();
    assert_eq!(Some((&1, &10)), iter.next());
    assert_eq!(Some((&3, &30)), iter.next_back());
    assert_eq!(Some((&2, &20)), iter.next());
    assert_eq!(None, iter.next_back());
    assert_eq!(None, iter.next());
}

#[test]
fn into_iter() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let mut iter = map.into_iter();
    assert_eq!(Some((1, 10)), iter.next());
    assert_eq!(Some((3, 30)), iter.next_back());
    assert_eq!(Some((2, 20)), iter.next());
    assert_eq!(None, iter.next_back());
    assert_eq!(None, iter.next());
}

#[test]
fn keys() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(&[1, 2, 3], map.keys());
}

#[test]
fn values() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    assert_eq!(&[10, 20, 30], map.values());
}

#[test]
fn split_off_before() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let postfix = map.split_off(&0);

    assert!(map.is_empty());
    assert_eq!(flatmap!(1 => 10, 2 => 20, 3 => 30), postfix);
}

#[test]
fn split_off_at_key() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let postfix = map.split_off(&2);

    assert_eq!(flatmap!(1 => 10), map);
    assert_eq!(flatmap!(2 => 20, 3 => 30), postfix);
}

#[test]
fn split_off_between_keys() {
    let mut map = flatmap!(2 => 20, 4 => 40, 6 => 60);

    let postfix = map.split_off(&5);

    assert_eq!(flatmap!(2 => 20, 4 => 40), map);
    assert_eq!(flatmap!(6 => 60), postfix);
}

#[test]
fn split_off_after() {
    let mut map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let postfix = map.split_off(&4);

    assert_eq!(flatmap!(1 => 10, 2 => 20, 3 => 30), map);
    assert!(postfix.is_empty());
}

#[test]
fn serialization_roundtrip() {
    let map = flatmap!(2 => 20, 1 => 10, 3 => 30);

    let bytes = serde_cbor::to_vec(&map).unwrap();
    let btree: BTreeMap<i32, i32> = serde_cbor::from_slice(bytes.as_slice()).unwrap();

    assert_eq!(btreemap!(1 => 10, 2 => 20, 3 => 30), btree);

    let bytes = serde_cbor::to_vec(&btree).unwrap();
    let out: FlatMap<i32, i32> = serde_cbor::from_slice(bytes.as_slice()).unwrap();

    assert_eq!(map, out);
}

#[test]
#[should_panic(expected = "flat map keys are not sorted")]
fn deserialize_out_of_order_keys() {
    // A map with out-of-order keys. Not a valid `FlatMap`, but the easiest way to
    // get a serialized map with out-of-order keys.
    let map = FlatMap {
        keys: vec![2, 1, 3],
        values: vec![20, 10, 30],
    };
    let bytes = serde_cbor::to_vec(&map).unwrap();

    serde_cbor::from_slice::<FlatMap<i32, i32>>(bytes.as_slice()).unwrap();
}
