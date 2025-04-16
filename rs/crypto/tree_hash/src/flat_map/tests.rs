use super::*;

#[test]
fn with_capacity() {
    let map: FlatMap<i32, i32> = FlatMap::with_capacity(13);

    assert!(map.is_empty());
    assert_eq!(0, map.len());
    assert!(map.keys().is_empty());
    assert!(map.values().is_empty());
    assert_eq!(13, map.keys.capacity());
    assert_eq!(13, map.values.capacity());
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
