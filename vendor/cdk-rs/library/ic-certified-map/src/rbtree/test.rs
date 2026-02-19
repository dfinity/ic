use super::*;
use std::convert::AsRef;

type TreeOfBytes = RbTree<Vec<u8>, Vec<u8>>;

fn insert(t: &mut TreeOfBytes, k: impl AsRef<[u8]>, v: impl AsRef<[u8]>) {
    t.insert(k.as_ref().to_vec(), v.as_ref().to_vec())
}

fn get_labels<'a>(ht: &HashTree<'a>) -> Vec<&'a [u8]> {
    fn go<'a>(t: &HashTree<'a>, keys: &mut Vec<&'a [u8]>) {
        match t {
            HashTree::Labeled(key, _) => {
                keys.push(key);
            }
            HashTree::Fork(lr) => {
                go(&lr.0, keys);
                go(&lr.1, keys);
            }
            _ => (),
        }
    }
    let mut keys = vec![];
    go(ht, &mut keys);
    keys
}

fn get_leaf_values<'a>(ht: &'a HashTree<'a>) -> Vec<&'a [u8]> {
    fn go<'a>(t: &'a HashTree<'a>, values: &mut Vec<&'a [u8]>) {
        match t {
            HashTree::Leaf(value) => {
                values.push(value);
            }
            HashTree::Fork(lr) => {
                go(&lr.0, values);
                go(&lr.1, values);
            }
            HashTree::Labeled(_, t) => {
                go(t, values);
            }
            _ => (),
        }
    }
    let mut values = vec![];
    go(ht, &mut values);
    values
}

#[test]
fn test_witness() {
    let mut t = TreeOfBytes::new();
    for i in 0u64..10 {
        let key = (1 + 2 * i).to_be_bytes();
        let val = (1 + 2 * i).to_le_bytes();
        insert(&mut t, key, val);
        assert_eq!(t.get(&key[..]).map(|v| &v[..]), Some(&val[..]));
    }

    for i in 0u64..10 {
        let key = (1 + 2 * i).to_be_bytes();
        let ht = t.witness(&key[..]);
        assert_eq!(
            ht.reconstruct(),
            t.root_hash(),
            "key: {}, witness {:?}",
            hex::encode(key),
            ht
        );

        let ht = t.keys_with_prefix(&key[..]);
        assert_eq!(
            ht.reconstruct(),
            t.root_hash(),
            "key: {}, lower bound: {:?}, upper_bound: {:?}, witness {:?}",
            hex::encode(key),
            t.lower_bound(&key[..]).map(hex::encode),
            t.right_prefix_neighbor(&key[..]).map(hex::encode),
            ht
        );
    }

    for i in 0u64..10 {
        for j in i..10 {
            let start = (2 * i).to_be_bytes();
            let end = (2 * j).to_be_bytes();
            let ht = t.key_range(&start[..], &end[..]);
            assert_eq!(
                ht.reconstruct(),
                t.root_hash(),
                "key range: [{}, {}], witness {:?}",
                hex::encode(&start[..]),
                hex::encode(&end[..]),
                ht
            );

            let ht = t.value_range(&start[..], &end[..]);
            assert_eq!(
                ht.reconstruct(),
                t.root_hash(),
                "key range: [{}, {}], witness {:?}",
                hex::encode(&start[..]),
                hex::encode(&end[..]),
                ht
            );
        }
    }

    for i in 0u64..11 {
        let key = (2 * i).to_be_bytes();
        let ht = t.witness(&key[..]);
        assert_eq!(
            ht.reconstruct(),
            t.root_hash(),
            "key: {}, witness {:?}",
            hex::encode(&key[..]),
            ht
        );
    }

    for i in 0u64..10 {
        let key = (1 + 2 * i).to_be_bytes();
        let val = (1 + 2 * i).to_le_bytes();

        assert_eq!(t.get(&key[..]).map(|v| &v[..]), Some(&val[..]));

        t.delete(&key[..]);
        for j in 0u64..10 {
            let witness_key = (1 + 2 * j).to_be_bytes();
            let ht = t.witness(&witness_key[..]);
            assert_eq!(
                ht.reconstruct(),
                t.root_hash(),
                "key: {}, witness {:?}",
                hex::encode(&key[..]),
                ht
            );
        }
        assert_eq!(t.get(&key[..]), None);
    }
}

#[test]
fn test_key_bounds() {
    let mut t = TreeOfBytes::new();
    t.insert(vec![1], vec![10]);
    t.insert(vec![3], vec![30]);

    assert_eq!(t.lower_bound(&[0u8][..]), None);
    assert_eq!(t.lower_bound(&[1u8][..]), Some(KeyBound::Exact(&[1u8])));
    assert_eq!(t.lower_bound(&[2u8][..]), Some(KeyBound::Neighbor(&[1u8])));
    assert_eq!(t.lower_bound(&[3u8][..]), Some(KeyBound::Exact(&[3u8])));
    assert_eq!(t.lower_bound(&[4u8][..]), Some(KeyBound::Neighbor(&[3u8])));

    assert_eq!(t.upper_bound(&[0u8][..]), Some(KeyBound::Neighbor(&[1u8])));
    assert_eq!(t.upper_bound(&[1u8][..]), Some(KeyBound::Exact(&[1u8])));
    assert_eq!(t.upper_bound(&[2u8][..]), Some(KeyBound::Neighbor(&[3u8])));
    assert_eq!(t.upper_bound(&[3u8][..]), Some(KeyBound::Exact(&[3u8])));
    assert_eq!(t.upper_bound(&[4u8][..]), None);
}

#[test]
fn test_prefix_neighbor() {
    let mut t = TreeOfBytes::new();
    insert(&mut t, b"a/b", vec![0]);
    insert(&mut t, b"a/b/c", vec![1]);
    insert(&mut t, b"a/b/d", vec![2]);
    insert(&mut t, b"a/c/d", vec![3]);

    assert_eq!(
        t.right_prefix_neighbor(b"a/b/c"),
        Some(KeyBound::Neighbor(&b"a/b/d"[..]))
    );
    assert_eq!(
        t.right_prefix_neighbor(b"a/b"),
        Some(KeyBound::Neighbor(&b"a/c/d"[..]))
    );
    assert_eq!(t.right_prefix_neighbor(b"a/c/d"), None);
    assert_eq!(t.right_prefix_neighbor(b"a"), None);
}

#[test]
fn simple_delete_test() {
    let mut t = TreeOfBytes::new();
    insert(&mut t, b"x", b"a");
    insert(&mut t, b"y", b"b");
    insert(&mut t, b"z", b"c");

    t.delete(b"x");
    assert_eq!(t.get(b"x"), None);
    assert_eq!(t.get(b"y").map(|v| &v[..]), Some(&b"b"[..]));
    assert_eq!(t.get(b"z").map(|v| &v[..]), Some(&b"c"[..]));

    t.delete(b"y");
    assert_eq!(t.get(b"y").map(|v| &v[..]), None);
    assert_eq!(t.get(b"z").map(|v| &v[..]), Some(&b"c"[..]));

    t.delete(b"z");
    assert_eq!(t.get(b"z").map(|v| &v[..]), None);
}

#[test]
fn simple_delete_test_2() {
    let mut t = TreeOfBytes::new();
    insert(&mut t, b"x", b"y");
    insert(&mut t, b"z", b"w");

    t.delete(b"z");
    assert_eq!(t.get(b"z"), None);
    assert_eq!(t.get(b"x").map(|v| &v[..]), Some(&b"y"[..]));
}

#[test]
fn map_model_test() {
    use std::collections::HashMap;

    let mut hm: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut rb = TreeOfBytes::new();

    for i in 0..100u64 {
        hm.insert(i.to_be_bytes().to_vec(), i.to_be_bytes().to_vec());
        insert(&mut rb, i.to_be_bytes(), i.to_be_bytes());

        for k in hm.keys() {
            assert_eq!(hm.get(k), rb.get(k));
        }
    }
    let keys: Vec<_> = hm.keys().cloned().collect();

    for k in keys {
        hm.remove(&k);

        assert!(rb.get(&k).is_some());
        rb.delete(&k);
        assert!(rb.get(&k).is_none());

        for k in hm.keys() {
            assert_eq!(hm.get(k), rb.get(k));
        }
    }
}

#[test]
fn test_nested_witness() {
    let mut rb: RbTree<Vec<u8>, TreeOfBytes> = RbTree::new();
    let mut nested = RbTree::new();
    nested.insert(b"bottom".to_vec(), b"data".to_vec());
    rb.insert(b"top".to_vec(), nested);

    let ht = rb.nested_witness(&b"top"[..], |v| v.witness(&b"bottom"[..]));

    assert_eq!(ht.reconstruct(), rb.root_hash());
    match ht {
        HashTree::Labeled(lt, tt) => {
            assert_eq!(lt, b"top");
            match &(*tt) {
                HashTree::Labeled(lb, _) => {
                    assert_eq!(lb, b"bottom");
                }
                other => panic!("unexpected nested tree: {other:?}"),
            }
        }
        other => panic!("expected a labeled tree, got {other:?}"),
    }

    rb.modify(b"top", |m| m.delete(b"bottom"));
    let ht = rb.nested_witness(&b"top"[..], |v| v.witness(&b"bottom"[..]));
    assert_eq!(ht.reconstruct(), rb.root_hash());
}

#[test]
fn test_witness_key_range() {
    let mut t = TreeOfBytes::new();
    insert(&mut t, b"b", b"x");
    insert(&mut t, b"d", b"y");
    insert(&mut t, b"f", b"z");

    assert_eq!(get_labels(&t.key_range(b"a", b"a")), vec![b"b"]);
    assert_eq!(get_labels(&t.key_range(b"a", b"b")), vec![b"b"]);
    assert_eq!(get_labels(&t.key_range(b"a", b"c")), vec![b"b", b"d"]);
    assert_eq!(get_labels(&t.key_range(b"a", b"f")), vec![b"b", b"d", b"f"]);
    assert_eq!(get_labels(&t.key_range(b"a", b"z")), vec![b"b", b"d", b"f"]);

    assert_eq!(get_labels(&t.key_range(b"b", b"b")), vec![b"b"]);
    assert_eq!(get_labels(&t.key_range(b"b", b"c")), vec![b"b", b"d"]);
    assert_eq!(get_labels(&t.key_range(b"b", b"f")), vec![b"b", b"d", b"f"]);
    assert_eq!(get_labels(&t.key_range(b"b", b"z")), vec![b"b", b"d", b"f"]);

    assert_eq!(get_labels(&t.key_range(b"d", b"e")), vec![b"d", b"f"]);
    assert_eq!(get_labels(&t.key_range(b"d", b"f")), vec![b"d", b"f"]);
    assert_eq!(get_labels(&t.key_range(b"d", b"z")), vec![b"d", b"f"]);
    assert_eq!(get_labels(&t.key_range(b"y", b"z")), vec![b"f"]);

    assert!(get_leaf_values(&t.key_range(b"a", b"z")).is_empty());
}

#[test]
fn test_witness_value_range() {
    let mut t = TreeOfBytes::new();
    insert(&mut t, b"b", b"x");
    insert(&mut t, b"d", b"y");
    insert(&mut t, b"f", b"z");

    assert_eq!(get_labels(&t.value_range(b"a", b"a")), vec![b"b"]);
    assert!(get_leaf_values(&t.value_range(b"a", b"a")).is_empty());

    assert_eq!(get_labels(&t.value_range(b"a", b"b")), vec![b"b"]);
    assert_eq!(get_leaf_values(&t.value_range(b"a", b"b")), vec![b"x"]);

    assert_eq!(get_labels(&t.value_range(b"f", b"z")), vec![b"f"]);
    assert_eq!(get_leaf_values(&t.value_range(b"f", b"z")), vec![b"z"]);

    assert_eq!(get_labels(&t.value_range(b"g", b"z")), vec![b"f"]);
    assert!(get_leaf_values(&t.value_range(b"g", b"z")).is_empty());

    assert_eq!(
        get_labels(&t.value_range(b"a", b"z")),
        vec![b"b", b"d", b"f"]
    );
    assert_eq!(
        get_leaf_values(&t.value_range(b"a", b"z")),
        vec![b"x", b"y", b"z"]
    );
}

#[test]
#[allow(clippy::map_identity)]
fn test_iter() {
    let mut t = TreeOfBytes::new();
    let mut v = vec![];
    for k in 0..100u64 {
        insert(&mut t, k.to_be_bytes(), (k + 10).to_be_bytes());
        v.push((k.to_be_bytes().to_vec(), (k + 10).to_be_bytes().to_vec()));
        assert!(
            t.iter().eq(v.iter().map(|(k, v)| (k, v))),
            "iterators aren't equal {:?} vs {:?}",
            &t.iter().collect::<Vec<_>>(),
            v
        );
    }
}

#[test]
fn test_equality() {
    let mut t1 = TreeOfBytes::new();
    for k in (0..100u64).rev() {
        insert(&mut t1, k.to_be_bytes(), (k + 10).to_be_bytes());
    }
    let t2 = (0..100u64)
        .map(|k| (k.to_be_bytes().to_vec(), (k + 10).to_be_bytes().to_vec()))
        .collect();

    assert_eq!(t1, t2);
    assert_eq!(t1.cmp(&t2), Equal);

    insert(&mut t1, 200u64.to_be_bytes(), 210u64.to_be_bytes());
    assert_ne!(t1, t2);
    assert_ne!(t1.cmp(&t2), Equal);
}

#[test]
fn test_ordering() {
    let t1: TreeOfBytes = (0..10u64)
        .map(|k| (k.to_be_bytes().to_vec(), k.to_be_bytes().to_vec()))
        .collect();
    let t2: TreeOfBytes = (0..10u64)
        .map(|k| (k.to_be_bytes().to_vec(), (k + 1).to_be_bytes().to_vec()))
        .collect();
    let t3: TreeOfBytes = (0..5u64)
        .map(|k| (k.to_be_bytes().to_vec(), k.to_be_bytes().to_vec()))
        .collect();
    let t4: TreeOfBytes = (1..5u64)
        .map(|k| (k.to_be_bytes().to_vec(), k.to_be_bytes().to_vec()))
        .collect();

    assert_eq!(t1.cmp(&t2), Less);
    assert_eq!(t1.cmp(&t3), Greater);
    assert_eq!(t1.cmp(&t4), Less);
}

#[test]
fn test_serde_serialize_and_deserialize() {
    type Tree<'a> = RbTree<&'a str, Hash>;
    let t1: Tree<'_> = Tree::from_iter([("hi", [1; 32]), ("hello", [2; 32]), ("world", [3; 32])]);

    // cbor test
    let mut b: Vec<u8> = Vec::new();
    serde_cbor::to_writer(&mut b, &t1).unwrap();
    let t2: Tree<'_> = serde_cbor::from_slice(&b[..]).unwrap();
    assert_eq!(t1, t2);

    // bincode test
    use bincode::Options;
    let b = bincode::options().serialize(&t1).unwrap();
    let t3: Tree<'_> = bincode::options().deserialize(&b).unwrap();
    assert_eq!(t1, t3);

    // candid test
    let b = candid::encode_one(&t1).unwrap();
    let t4: Tree<'_> = candid::decode_one(&b).unwrap();
    assert_eq!(t1, t4);
}
