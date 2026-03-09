use ic_stable_hash::StableHash;
use ic_stable_hash_derive::StableHash;
use std::hash::Hash;

struct SpyHasher {
    bytes: Vec<u8>,
}

impl SpyHasher {
    fn new() -> Self {
        SpyHasher { bytes: Vec::new() }
    }
}

impl std::hash::Hasher for SpyHasher {
    fn finish(&self) -> u64 {
        unimplemented!()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
}

fn hash_bytes<T: Hash>(val: &T) -> Vec<u8> {
    let mut h = SpyHasher::new();
    val.hash(&mut h);
    h.bytes
}

fn stable_hash_bytes<T: StableHash>(val: &T) -> Vec<u8> {
    let mut h = SpyHasher::new();
    val.stable_hash(&mut h);
    h.bytes
}

// --- Structs ---

#[derive(Hash, StableHash)]
struct UnitStruct;

#[derive(Hash, StableHash)]
struct TupleStruct(u64, Vec<u8>, String);

#[derive(Hash, StableHash)]
struct NamedStruct {
    a: u64,
    b: Vec<u8>,
    c: Option<String>,
}

#[derive(Hash, StableHash)]
struct NestedStruct {
    inner: NamedStruct,
    flag: bool,
}

#[test]
fn unit_struct_matches() {
    let val = UnitStruct;
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn tuple_struct_matches() {
    let val = TupleStruct(42, vec![1, 2, 3], "hello".into());
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn named_struct_matches() {
    let val = NamedStruct {
        a: 0xDEAD,
        b: vec![0xFF; 10],
        c: Some("test".into()),
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn named_struct_none_matches() {
    let val = NamedStruct {
        a: 0,
        b: vec![],
        c: None,
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn nested_struct_matches() {
    let val = NestedStruct {
        inner: NamedStruct {
            a: 1,
            b: vec![2],
            c: Some("x".into()),
        },
        flag: true,
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

// --- Enums ---

#[derive(Hash, StableHash)]
enum MultiVariant {
    A,
    B(u64),
    C { x: u32, y: String },
}

#[test]
fn enum_unit_variant_matches() {
    let val = MultiVariant::A;
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn enum_tuple_variant_matches() {
    let val = MultiVariant::B(42);
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

#[test]
fn enum_named_variant_matches() {
    let val = MultiVariant::C {
        x: 7,
        y: "hello".into(),
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

// --- Single-variant enum ---

#[derive(Hash, StableHash)]
enum SingleVariant {
    Only(u64, Vec<u8>),
}

#[test]
fn single_variant_enum_matches() {
    let val = SingleVariant::Only(99, vec![1, 2]);
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

// --- Repr enum (C-like) ---

#[derive(Hash, StableHash)]
#[repr(u8)]
enum ReprEnum {
    X = 5,
    Y = 10,
    Z = 20,
}

#[test]
fn repr_enum_matches() {
    assert_eq!(stable_hash_bytes(&ReprEnum::X), hash_bytes(&ReprEnum::X));
    assert_eq!(stable_hash_bytes(&ReprEnum::Y), hash_bytes(&ReprEnum::Y));
    assert_eq!(stable_hash_bytes(&ReprEnum::Z), hash_bytes(&ReprEnum::Z));
}

// --- Repr enum with auto-increment ---

#[derive(Hash, StableHash)]
#[repr(i32)]
enum ReprAutoIncrement {
    A = 3,
    B, // = 4
    C, // = 5
    D = 100,
    E, // = 101
}

#[test]
fn repr_auto_increment_matches() {
    assert_eq!(
        stable_hash_bytes(&ReprAutoIncrement::A),
        hash_bytes(&ReprAutoIncrement::A)
    );
    assert_eq!(
        stable_hash_bytes(&ReprAutoIncrement::B),
        hash_bytes(&ReprAutoIncrement::B)
    );
    assert_eq!(
        stable_hash_bytes(&ReprAutoIncrement::C),
        hash_bytes(&ReprAutoIncrement::C)
    );
    assert_eq!(
        stable_hash_bytes(&ReprAutoIncrement::D),
        hash_bytes(&ReprAutoIncrement::D)
    );
    assert_eq!(
        stable_hash_bytes(&ReprAutoIncrement::E),
        hash_bytes(&ReprAutoIncrement::E)
    );
}

// --- Enum without repr but with explicit discriminants ---

#[derive(Hash, StableHash)]
enum ExplicitDisc {
    A = 5,
    B = 10,
}

#[test]
fn explicit_disc_matches() {
    assert_eq!(
        stable_hash_bytes(&ExplicitDisc::A),
        hash_bytes(&ExplicitDisc::A)
    );
    assert_eq!(
        stable_hash_bytes(&ExplicitDisc::B),
        hash_bytes(&ExplicitDisc::B)
    );
}

// --- Generic struct ---

#[derive(Hash, StableHash)]
struct GenericStruct<T> {
    val: T,
    count: u32,
}

#[test]
fn generic_struct_matches() {
    let val = GenericStruct {
        val: vec![1u8, 2, 3],
        count: 42,
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}

// --- Deeply nested ---

#[derive(Hash, StableHash)]
struct Deep {
    a: Vec<Option<NamedStruct>>,
    b: std::collections::BTreeMap<u64, String>,
}

#[test]
fn deep_nesting_matches() {
    let mut m = std::collections::BTreeMap::new();
    m.insert(1u64, "one".to_string());
    m.insert(2, "two".to_string());
    let val = Deep {
        a: vec![
            Some(NamedStruct {
                a: 1,
                b: vec![2, 3],
                c: None,
            }),
            None,
        ],
        b: m,
    };
    assert_eq!(stable_hash_bytes(&val), hash_bytes(&val));
}
