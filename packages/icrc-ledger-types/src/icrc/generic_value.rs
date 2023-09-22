use candid::{CandidType, Deserialize, Int, Nat};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The number of bytes required to represent a 128-bit integer using LEB128 encoding.
/// NOTE: ⌈ 128 / 7 ⌉ = 19
const INT128_BUF_SIZE: usize = 19;
pub type Map = BTreeMap<String, Value>;
pub type Hash = [u8; 32];

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Blob(ByteBuf),
    Text(String),
    Nat(Nat),
    Nat64(u64),
    Int(Int),
    Array(Vec<Value>),
    Map(Map),
}

impl Value {
    pub fn text(t: impl ToString) -> Self {
        Self::Text(t.to_string())
    }

    pub fn blob(t: impl Into<Vec<u8>>) -> Self {
        Self::Blob(ByteBuf::from(t.into()))
    }

    /// Computes the representation-independent hash of a value.
    pub fn hash(&self) -> Hash {
        match self {
            Value::Nat(nat) => {
                let mut buf = vec![];
                nat.encode(&mut buf).expect("bug: cannot encode a Nat");
                Sha256::digest(&buf).into()
            }
            Value::Nat64(n) => {
                let mut buf = [0u8; INT128_BUF_SIZE];
                let offset = leb128(&mut buf, *n as u128);
                Sha256::digest(&buf[0..=offset]).into()
            }
            Value::Int(int) => {
                let v = int
                    .0
                    .to_i128()
                    .expect("BUG: blocks cannot contain integers that do not fit into the 128-bit representation");
                let mut buf = [0u8; INT128_BUF_SIZE];
                //TODO: Int should only use sleb128. Due to CiboriumValue only using Integer this is however not possible right now
                //      Unsinged Integers should be represented through Nat or Nat65: https://dfinity.atlassian.net/browse/FI-764
                let offset = match v >= 0 {
                    true => leb128(&mut buf, v as u128),
                    false => sleb128(&mut buf, v),
                };
                Sha256::digest(&buf[0..=offset]).into()
            }
            Value::Blob(bytes) => Sha256::digest(bytes).into(),
            Value::Text(text) => Sha256::digest(text.as_bytes()).into(),
            Value::Array(values) => {
                let mut hasher = Sha256::new();
                for v in values.iter() {
                    hasher.update(v.hash());
                }
                hasher.finalize().into()
            }
            Value::Map(map) => {
                let mut hpairs = Vec::with_capacity(map.len());
                for (k, v) in map.iter() {
                    let key_hash: Hash = Sha256::digest(k.as_bytes()).into();
                    hpairs.push((key_hash, v.hash()));
                }

                hpairs.sort_unstable();

                let mut hasher = Sha256::new();
                for (khash, vhash) in hpairs.iter() {
                    hasher.update(&khash[..]);
                    hasher.update(&vhash[..]);
                }
                hasher.finalize().into()
            }
        }
    }
}

/// Encodes a 128-bit integer using unsigned LEB-128 encoding.
/// Returns the index of the last valid byte in the buffer.
fn leb128(buf: &mut [u8; INT128_BUF_SIZE], v: u128) -> usize {
    let mut n = v;
    let mut i = 0;

    loop {
        debug_assert!(i < INT128_BUF_SIZE);

        let byte = n as u8;
        n >>= 7;

        if n == 0 {
            buf[i] = byte & 0x7f;
            return i;
        } else {
            buf[i] = byte | 0x80;
            i += 1;
        }
    }
}

/// Encodes a 128-bit integer using signed LEB-128 encoding.
/// Returns the index of the last valid byte in the buffer.
///
fn sleb128(buf: &mut [u8; INT128_BUF_SIZE], v: i128) -> usize {
    let mut n = v;
    let mut i = 0;
    loop {
        debug_assert!(i < INT128_BUF_SIZE);

        let byte = n as u8;
        // Keep the sign bit for testing
        n >>= 6;
        if n == 0 || n == -1 {
            buf[i] = byte & 0x7f;
            return i;
        } else {
            // Remove the sign bit
            n >>= 1;
            buf[i] = byte | 0x80;
            i += 1;
        }
    }
}

#[test]
fn check_interface_spec_example() {
    let value = Value::Map({
        let mut m = BTreeMap::new();
        m.insert("request_type".to_string(), Value::text("call"));
        m.insert(
            "canister_id".to_string(),
            Value::blob(b"\x00\x00\x00\x00\x00\x00\x04\xD2".to_vec()),
        );
        m.insert("method_name".to_string(), Value::text("hello"));
        m.insert("arg".to_string(), Value::blob(b"DIDL\x00\xFD*".to_vec()));
        m
    });
    assert_eq!(
        hex::encode(value.hash()),
        "8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b"
    );
}

#[test]
fn test_leb128() {
    let mut buf = [0; INT128_BUF_SIZE];
    for (n, b) in [
        (0, &[0][..]),
        (624485, &[0xe5, 0x8e, 0x26][..]),
        (
            1677770607672807382,
            &[0xd6, 0x9f, 0xb7, 0xe7, 0xa7, 0xef, 0xa8, 0xa4, 0x17][..],
        ),
    ] {
        let i = leb128(&mut buf, n);
        assert_eq!(&buf[0..=i], b, "invalid encoding of integer {}", n);
    }
}

#[test]
fn test_sleb128() {
    let mut buf = [0; INT128_BUF_SIZE];
    for (n, b) in [(0, &[0][..]), (-123456, &[0xc0, 0xbb, 0x78][..])] {
        let i = sleb128(&mut buf, n);
        assert_eq!(&buf[0..=i], b, "invalid encoding of integer {}", n);
    }
}
