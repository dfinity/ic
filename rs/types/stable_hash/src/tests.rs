use super::*;
use std::hash::Hash;

/// A spy hasher that records all bytes written to it.
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

macro_rules! assert_matches_hash {
    ($val:expr) => {
        assert_eq!(
            stable_hash_bytes(&$val),
            hash_bytes(&$val),
            "StableHash diverges from Hash for {:?}",
            $val
        );
    };
}

#[test]
fn primitives_match_hash() {
    assert_matches_hash!(0u8);
    assert_matches_hash!(255u8);
    assert_matches_hash!(0u16);
    assert_matches_hash!(12345u16);
    assert_matches_hash!(0u32);
    assert_matches_hash!(0xDEAD_BEEFu32);
    assert_matches_hash!(0u64);
    assert_matches_hash!(0xDEAD_BEEF_CAFE_BABEu64);
    assert_matches_hash!(0u128);
    assert_matches_hash!(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0u128);
    assert_matches_hash!(0i8);
    assert_matches_hash!(-1i8);
    assert_matches_hash!(0i16);
    assert_matches_hash!(-12345i16);
    assert_matches_hash!(0i32);
    assert_matches_hash!(0i64);
    assert_matches_hash!(-1i64);
    assert_matches_hash!(0i128);
    assert_matches_hash!(true);
    assert_matches_hash!(false);
}

#[test]
fn usize_isize_match_hash() {
    // These match Hash on x86_64 (8 bytes LE).
    assert_matches_hash!(0usize);
    assert_matches_hash!(42usize);
    assert_matches_hash!(usize::MAX);
    assert_matches_hash!(0isize);
    assert_matches_hash!(-1isize);
    assert_matches_hash!(isize::MAX);
}

#[test]
fn vec_matches_hash() {
    assert_matches_hash!(Vec::<u8>::new());
    assert_matches_hash!(vec![1u8, 2, 3]);
    assert_matches_hash!(vec![0u64, 1, 2, 3]);
    assert_matches_hash!(vec![vec![1u8, 2], vec![3u8]]);
}

#[test]
fn array_matches_hash() {
    assert_matches_hash!([0u8; 0]);
    assert_matches_hash!([1u8, 2, 3]);
    assert_matches_hash!([0u64; 4]);
    assert_matches_hash!([0x42u8; 32]);
}

#[test]
fn string_matches_hash() {
    assert_matches_hash!(String::new());
    assert_matches_hash!(String::from("hello"));
    assert_matches_hash!(String::from("hello\x00world"));
}

#[test]
fn option_matches_hash() {
    assert_matches_hash!(None::<u64>);
    assert_matches_hash!(Some(42u64));
    assert_matches_hash!(None::<String>);
    assert_matches_hash!(Some(String::from("test")));
}

#[test]
fn box_matches_hash() {
    assert_matches_hash!(Box::new(42u64));
    assert_matches_hash!(Box::new(vec![1u8, 2, 3]));
}

#[test]
fn arc_matches_hash() {
    assert_matches_hash!(Arc::new(42u64));
    assert_matches_hash!(Arc::new(vec![1u8, 2, 3]));
}

#[test]
fn btreemap_matches_hash() {
    let mut m = BTreeMap::new();
    m.insert(1u64, 2u64);
    m.insert(3, 4);
    assert_matches_hash!(m);

    assert_matches_hash!(BTreeMap::<u32, u32>::new());
}

#[test]
fn btreeset_matches_hash() {
    let mut s = BTreeSet::new();
    s.insert(3u64);
    s.insert(1);
    s.insert(2);
    assert_matches_hash!(s);

    assert_matches_hash!(BTreeSet::<u32>::new());
}

#[test]
fn tuple_matches_hash() {
    assert_matches_hash!((1u64, 2u64));
    assert_matches_hash!(());
    assert_matches_hash!((1u64, 2u32, 3u8));
    assert_matches_hash!((String::from("a"), 42u64, true));
}

#[test]
fn result_matches_hash() {
    assert_matches_hash!(Ok::<u64, String>(42));
    assert_matches_hash!(Err::<u64, String>(String::from("error")));
    assert_matches_hash!(Ok::<Vec<u8>, u32>(vec![1, 2, 3]));
    assert_matches_hash!(Err::<Vec<u8>, u32>(99));
}

#[test]
fn vecdeque_matches_hash() {
    assert_matches_hash!(VecDeque::<u8>::new());
    let mut vd = VecDeque::new();
    vd.push_back(1u64);
    vd.push_back(2);
    vd.push_back(3);
    assert_matches_hash!(vd);
}

#[test]
fn reference_matches_hash() {
    let val = 42u64;
    assert_eq!(stable_hash_bytes(&&val), hash_bytes(&&val));
}
