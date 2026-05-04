use crate::map::{MultiKeyMap, OccupiedError, OccupiedKey};
use phantom_newtype::Id;

#[test]
fn should_insert_and_retrieve_by_key_and_alt_key() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    map.try_insert(PrimaryKey::new(1), AltKey::new('a'), 1)
        .unwrap();
    map.try_insert(PrimaryKey::new(2), AltKey::new('b'), 2)
        .unwrap();

    assert_eq!(map.get(&PrimaryKey::new(1)), Some(&1));
    assert_eq!(
        map.get_entry(&PrimaryKey::new(1)),
        Some((&AltKey::new('a'), &1))
    );
    assert_eq!(map.get_alt(&AltKey::new('a')), Some(&1));

    assert_eq!(map.get(&PrimaryKey::new(2)), Some(&2));
    assert_eq!(
        map.get_entry(&PrimaryKey::new(2)),
        Some((&AltKey::new('b'), &2))
    );
    assert_eq!(map.get_alt(&AltKey::new('b')), Some(&2));
}

#[test]
fn should_fail_to_insert_when_either_key_collide() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    let key = PrimaryKey::new(1);
    let alt_key = AltKey::new('a');
    map.try_insert(key, alt_key, 1).unwrap();

    let map_before = map.clone();
    let new_alt_key = AltKey::new('b');
    assert_eq!(
        map.try_insert(key, new_alt_key, 2),
        Err(OccupiedError {
            occupied_key: OccupiedKey::Key(key),
            value: 2
        })
    );
    assert_eq!(map, map_before);

    let map_before = map.clone();
    let new_key = PrimaryKey::new(2);
    assert_eq!(
        map.try_insert(new_key, alt_key, 2),
        Err(OccupiedError {
            occupied_key: OccupiedKey::AltKey(alt_key),
            value: 2
        })
    );
    assert_eq!(map, map_before);
}

#[test]
fn should_iterate_in_order_of_primary_key() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    map.try_insert(PrimaryKey::new(2), AltKey::new('a'), 2)
        .unwrap();
    map.try_insert(PrimaryKey::new(1), AltKey::new('b'), 1)
        .unwrap();
    map.try_insert(PrimaryKey::new(4), AltKey::new('c'), 4)
        .unwrap();

    let mut iter = map.iter();
    assert_eq!(
        iter.next(),
        Some((&PrimaryKey::new(1), &AltKey::new('b'), &1))
    );
    assert_eq!(
        iter.next(),
        Some((&PrimaryKey::new(2), &AltKey::new('a'), &2))
    );
    assert_eq!(
        iter.next(),
        Some((&PrimaryKey::new(4), &AltKey::new('c'), &4))
    );
    assert_eq!(iter.next(), None);
}

#[test]
fn should_remove_entry() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    for i in 0..10 {
        map.try_insert(PrimaryKey::new(i), AltKey::new((b'a' + i as u8) as char), i)
            .unwrap();
    }

    let key_to_remove = PrimaryKey::new(5);
    assert_eq!(
        map.remove_entry(&key_to_remove),
        Some((key_to_remove, AltKey::new('f'), 5))
    );
    assert!(!map.contains(&key_to_remove));
    assert!(!map.contains_alt(&AltKey::new('f')));

    assert_eq!(map.remove_entry(&PrimaryKey::new(200)), None);
}

#[test]
fn should_insert_after_removal() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    map.try_insert(PrimaryKey::new(1), AltKey::new('a'), 1)
        .unwrap();
    assert!(
        map.try_insert(PrimaryKey::new(1), AltKey::new('a'), 1)
            .is_err()
    );

    assert_eq!(
        map.remove_entry(&PrimaryKey::new(1)),
        Some((PrimaryKey::new(1), AltKey::new('a'), 1))
    );

    assert_eq!(
        map.try_insert(PrimaryKey::new(1), AltKey::new('a'), 1),
        Ok(())
    );
}

#[test]
fn should_remove_all_elements_whose_primary_key_is_less_than_some_bound() {
    let mut map = MultiKeyMap::<PrimaryKey, AltKey, u32>::default();
    for i in 0..10 {
        map.try_insert(PrimaryKey::new(i), AltKey::new((b'a' + i as u8) as char), i)
            .unwrap();
    }

    let drained = map.drain(|key| key.get_ref() < &5);
    assert_eq!(
        drained,
        vec![
            (PrimaryKey::new(0), AltKey::new('a'), 0),
            (PrimaryKey::new(1), AltKey::new('b'), 1),
            (PrimaryKey::new(2), AltKey::new('c'), 2),
            (PrimaryKey::new(3), AltKey::new('d'), 3),
            (PrimaryKey::new(4), AltKey::new('e'), 4),
        ]
    );

    let mut remaining = map.iter();
    assert_eq!(
        remaining.next(),
        Some((&PrimaryKey::new(5), &AltKey::new('f'), &5))
    );
    assert_eq!(
        remaining.next(),
        Some((&PrimaryKey::new(6), &AltKey::new('g'), &6))
    );
    assert_eq!(
        remaining.next(),
        Some((&PrimaryKey::new(7), &AltKey::new('h'), &7))
    );
    assert_eq!(
        remaining.next(),
        Some((&PrimaryKey::new(8), &AltKey::new('i'), &8))
    );
    assert_eq!(
        remaining.next(),
        Some((&PrimaryKey::new(9), &AltKey::new('j'), &9))
    );
    assert_eq!(remaining.next(), None);
}

#[derive(Debug)]
enum PrimaryKeyTag {}
type PrimaryKey = Id<PrimaryKeyTag, u32>;

#[derive(Debug)]
enum ForeignKeyTag {}
type AltKey = Id<ForeignKeyTag, char>;
