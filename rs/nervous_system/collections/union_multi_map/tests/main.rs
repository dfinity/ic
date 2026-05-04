use ic_nervous_system_collections_union_multi_map::UnionMultiMap;
use maplit::hashmap;

#[test]
fn test_union_multi_map() {
    let map1 = hashmap! {
        1_u64 => vec!["hi".to_string()],
        3_u64 => vec![
            "what".to_string(),
            "the".to_string(),
            "actual".to_string(),
            "hack".to_string(),
        ],
    };
    let map2 = hashmap! {
        1_u64 => vec!["herp".to_string(), "derp".to_string()],
        2_u64 => vec!["burp".to_string()],
    };
    let union_multi_map = UnionMultiMap::new(vec![&map1, &map2]);
    let get = |key| union_multi_map.get(&key).unwrap().collect::<Vec<&String>>();

    match union_multi_map.get(&0) {
        None => (), // ok
        Some(iter) => panic!("{:#?}", iter.collect::<Vec<&String>>()),
    }

    assert_eq!(get(1), vec!["hi", "herp", "derp"]);
    assert_eq!(get(2), vec!["burp"]);
    assert_eq!(get(3), vec!["what", "the", "actual", "hack"]);
}

#[test]
fn test_union_multi_map_duplicate_values() {
    let map1 = hashmap! {
        42_u64 => vec!["unique".to_string(), "collide".to_string()],
        84_u64 => vec!["plagerism".to_string(), "evil".to_string()],
    };
    let map2 = hashmap! {
        42_u64 => vec!["collide".to_string(), "what the actual hack".to_string()],
        84_u64 => vec!["plagerism".to_string(), "evil".to_string()],
    };
    let union_multi_map = UnionMultiMap::new(vec![&map1, &map2]);
    let get = |key| union_multi_map.get(&key).unwrap().collect::<Vec<&String>>();

    assert_eq!(
        get(42),
        vec!["unique", "collide", "collide", "what the actual hack"]
    );
    assert_eq!(get(84), vec!["plagerism", "evil", "plagerism", "evil"]);
}
