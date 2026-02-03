use candid::{CandidType, Deserialize, Int, Nat, Principal};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::icrc1::account::Account;

/// The number of bytes required to represent a 128-bit integer using LEB128 encoding.
/// NOTE: ⌈ 128 / 7 ⌉ = 19
const INT128_BUF_SIZE: usize = 19;
pub type Map = BTreeMap<String, Value>;
pub type ICRC3Map = BTreeMap<String, ICRC3Value>;
pub type Hash = [u8; 32];

/// A value defined in [the ICRC-3 standard](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md#value).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ICRC3Value {
    Blob(ByteBuf),
    Text(String),
    Nat(Nat),
    Int(Int),
    Array(Vec<ICRC3Value>),
    Map(ICRC3Map),
}

impl std::fmt::Display for ICRC3Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO(FI-1263): copy the Value fmt function to avoid cloning self
        write!(f, "{}", Value::from(self.to_owned()))
    }
}

impl ICRC3Value {
    /// Compute [the hash of an ICRC-3 value](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md#value).
    pub fn hash(self) -> Hash {
        // TODO(FI-1263): copy the value hash function to avoid cloning self
        Value::from(self).hash()
    }
}

/// Deprecated, use `ICRC3Value` instead
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    Blob(ByteBuf),
    Text(String),
    Nat(Nat),
    Nat64(u64),
    Int(Int),
    Array(Vec<Value>),
    Map(Map),
}

impl From<Value> for ICRC3Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Blob(b) => Self::Blob(b),
            Value::Text(t) => Self::Text(t),
            Value::Nat(n) => Self::Nat(n),
            Value::Nat64(n) => Self::Nat(Nat::from(n)),
            Value::Int(i) => Self::Int(i),
            Value::Array(a) => Self::Array(a.into_iter().map(Self::from).collect()),
            Value::Map(m) => Self::Map(m.into_iter().map(|(k, v)| (k, Self::from(v))).collect()),
        }
    }
}

impl From<ICRC3Value> for Value {
    fn from(value: ICRC3Value) -> Self {
        match value {
            ICRC3Value::Blob(b) => Self::Blob(b),
            ICRC3Value::Text(t) => Self::Text(t),
            ICRC3Value::Nat(n) => Self::Nat(n),
            ICRC3Value::Int(i) => Self::Int(i),
            ICRC3Value::Array(a) => Self::Array(a.into_iter().map(Value::from).collect()),
            ICRC3Value::Map(m) => {
                Self::Map(m.into_iter().map(|(k, v)| (k, Self::from(v))).collect())
            }
        }
    }
}

impl Value {
    pub fn variant_name(&self) -> String {
        match self {
            Self::Blob(_) => "Blob".to_string(),
            Self::Text(_) => "Text".to_string(),
            Self::Nat(_) => "Nat".to_string(),
            Self::Nat64(_) => "Nat64".to_string(),
            Self::Int(_) => "Int".to_string(),
            Self::Array(_) => "Array".to_string(),
            Self::Map(_) => "Map".to_string(),
        }
    }

    pub fn text(t: impl ToString) -> Self {
        Self::Text(t.to_string())
    }

    pub fn blob(t: impl Into<Vec<u8>>) -> Self {
        Self::Blob(ByteBuf::from(t.into()))
    }

    pub fn map<S, V>(v: V) -> Self
    where
        S: ToString,
        V: IntoIterator<Item = (S, Value)>,
    {
        Self::Map(v.into_iter().map(|(s, v)| (s.to_string(), v)).collect())
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
                //      Unsigned Integers should be represented through Nat or Nat64: https://dfinity.atlassian.net/browse/FI-764
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

    pub fn as_blob(self) -> Result<ByteBuf, String> {
        match self {
            Self::Blob(b) => Ok(b),
            _ => Err(self.variant_name()),
        }
    }

    pub fn as_text(self) -> Result<String, String> {
        match self {
            Self::Text(s) => Ok(s),
            _ => Err(self.variant_name()),
        }
    }

    pub fn as_nat(self) -> Result<Nat, String> {
        match self {
            Self::Nat(n) => Ok(n),
            Self::Nat64(n) => Ok(Nat::from(n)),
            Self::Int(i) => match BigUint::try_from(i.0) {
                Ok(n) => Ok(Nat(n)),
                Err(e) => Err(format!("Failed to convert Int to Nat: {e:?}")),
            },
            _ => Err(self.variant_name()),
        }
    }

    pub fn as_int(self) -> Result<Int, String> {
        match self {
            Self::Int(i) => Ok(i),
            _ => Err(self.variant_name()),
        }
    }

    pub fn as_array(self) -> Result<Vec<Value>, String> {
        match self {
            Self::Array(v) => Ok(v),
            _ => Err(self.variant_name()),
        }
    }

    pub fn as_map(self) -> Result<Map, String> {
        match self {
            Self::Map(m) => Ok(m),
            _ => Err(self.variant_name()),
        }
    }
}

impl TryFrom<Value> for ByteBuf {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_blob()
            .map_err(|found_variant| format!("Expecting variant Blob but found {found_variant}"))
    }
}

impl TryFrom<Value> for Vec<u8> {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(ByteBuf::try_from(value)?.to_vec())
    }
}

impl TryFrom<Value> for String {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_text()
            .map_err(|found_variant| format!("Expecting variant Text but found {found_variant}"))
    }
}

impl TryFrom<Value> for Nat {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_nat()
            .map_err(|found_variant| format!("Expecting variant Nat but found {found_variant}"))
    }
}

impl TryFrom<Value> for u64 {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Nat::try_from(value)?
            .0
            .to_u64()
            .ok_or_else(|| "Unable to convert nat {nat} to u64".to_string())
    }
}

impl TryFrom<Value> for Int {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_int()
            .map_err(|found_variant| format!("Expecting variant Int but found {found_variant}"))
    }
}

impl TryFrom<Value> for Vec<Value> {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_array()
            .map_err(|found_variant| format!("Expecting variant Array but found {found_variant}"))
    }
}

impl TryFrom<Value> for Map {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        value
            .as_map()
            .map_err(|found_variant| format!("Expecting variant Map but found {found_variant}"))
    }
}

impl TryFrom<Value> for Account {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let mut array = value.as_array()?;
        if array.len() > 2 {
            return Err(format!(
                "Account should be an array of either one or two elements but found an array of {} elements",
                array.len()
            ));
        }
        let owner = Principal::try_from_slice(array.remove(0).as_blob()?.as_slice())
            .map_err(|err| format!("Unable to decode the owner of the account, error {err}"))?;
        if let Some(subaccount) = array.pop() {
            let subaccount = subaccount.as_blob()?.as_slice().try_into().map_err(|err| {
                format!("Unable to decode the subaccount of the account, error {err}")
            })?;
            Ok(Account {
                owner,
                subaccount: Some(subaccount),
            })
        } else {
            Ok(Account {
                owner,
                subaccount: None,
            })
        }
    }
}

impl From<Account> for Value {
    fn from(Account { owner, subaccount }: Account) -> Self {
        let mut parts = vec![];
        parts.push(Self::blob(owner.as_slice()));
        if let Some(subaccount) = subaccount {
            parts.push(Self::blob(subaccount.as_slice()));
        }
        Self::Array(parts)
    }
}

impl TryFrom<Value> for Principal {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Principal::try_from_slice(value.as_blob()?.as_slice())
            .map_err(|err| format!("Unable to decode the principal, error {err}"))
    }
}

impl From<Principal> for Value {
    fn from(principal: Principal) -> Self {
        Self::blob(principal.as_slice())
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Blob(bytes) => write!(f, "{}", hex::encode(bytes.as_ref())),
            Value::Text(text) => write!(f, "{text}"),
            Value::Nat(nat) => write!(f, "{nat}"),
            Value::Nat64(nat64) => write!(f, "{nat64}"),
            Value::Int(int) => write!(f, "{int}"),
            Value::Array(array) => {
                write!(f, "Array(")?;
                let mut first = true;
                for e in array {
                    if first {
                        first = false
                    } else {
                        write!(f, ", ")?
                    }
                    write!(f, "{e}")?;
                }
                write!(f, ")")
            }
            Value::Map(map) => {
                write!(f, "Map(")?;
                let mut first = true;
                for (k, v) in map {
                    if first {
                        first = false
                    } else {
                        write!(f, ", ")?
                    }
                    write!(f, "{k}: {v}")?;
                }
                write!(f, ")")
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
        assert_eq!(&buf[0..=i], b, "invalid encoding of integer {n}");
    }
}

#[test]
fn test_sleb128() {
    let mut buf = [0; INT128_BUF_SIZE];
    for (n, b) in [(0, &[0][..]), (-123456, &[0xc0, 0xbb, 0x78][..])] {
        let i = sleb128(&mut buf, n);
        assert_eq!(&buf[0..=i], b, "invalid encoding of integer {n}");
    }
}

#[test]
fn test_test_vectors() {
    let test_vectors = vec![
        (
            Value::Nat(42_u32.into()),
            "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1",
        ),
        (
            Value::Int((-42).into()),
            "de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc",
        ),
        (
            Value::text("Hello, World!"),
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
        ),
        (
            Value::blob(hex::decode("01020304").unwrap()),
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
        ),
        (
            Value::Array(vec![
                Value::Nat(3_u32.into()),
                Value::text("foo"),
                Value::blob(hex::decode("0506").unwrap()),
            ]),
            "514a04011caa503990d446b7dec5d79e19c221ae607fb08b2848c67734d468d6",
        ),
        (
            Value::map(vec![
                (
                    "from",
                    Value::blob(
                        hex::decode("00abcdef0012340056789a00bcdef000012345678900abcdef01")
                            .unwrap(),
                    ),
                ),
                (
                    "to",
                    Value::blob(
                        hex::decode("00ab0def0012340056789a00bcdef000012345678900abcdef01")
                            .unwrap(),
                    ),
                ),
                ("amount", Value::Nat(42_u32.into())),
                ("created_at", Value::Nat(1699218263_u32.into())),
                ("memo", Value::Nat(0_u32.into())),
            ]),
            "c56ece650e1de4269c5bdeff7875949e3e2033f85b2d193c2ff4f7f78bdcfc75",
        ),
    ];

    for (input, expected) in test_vectors {
        assert_eq!(
            input.hash().to_vec(),
            hex::decode(expected).unwrap(),
            "input: {input}"
        );
    }
}

#[cfg(test)]
pub fn arb_value() -> impl proptest::prelude::Strategy<Value = Value> {
    use num_bigint::{BigInt, Sign};
    use proptest::prelude::{Just, any, prop_oneof};
    use proptest::strategy::Strategy;

    // https://altsysrq.github.io/proptest-book/proptest/tutorial/recursive.html

    let any_blob = any::<Vec<u8>>().prop_map(|bytes| Value::Blob(ByteBuf::from(bytes)));
    let any_text = any::<String>().prop_map(Value::Text);
    let any_nat =
        any::<Vec<u32>>().prop_map(|digits| Value::Nat(candid::Nat(BigUint::new(digits))));
    let any_nat64 = any::<u64>().prop_map(Value::Nat64);
    let any_sign = prop_oneof![Just(Sign::Minus), Just(Sign::NoSign), Just(Sign::Plus)];
    let any_int = (any_sign, any::<Vec<u32>>())
        .prop_map(|(sign, digits)| Value::Int(candid::Int(BigInt::new(sign, digits))));

    let leaf = prop_oneof![any_blob, any_text, any_nat, any_nat64, any_int];
    leaf.prop_recursive(
        3,  // 3 levels deep
        16, // Shoot for maximum size of 16 nodes
        10, // We put up to 10 items per collection
        |inner| {
            prop_oneof![
                // Take the inner strategy and make the two recursive cases.
                proptest::collection::vec(inner.clone(), 0..10).prop_map(Value::Array),
                proptest::collection::btree_map(".*", inner, 0..10).prop_map(Value::Map),
            ]
        },
    )
}

#[test]
fn test_value_to_icrc3value_roundtrip() {
    use proptest::{prop_assert_eq, proptest};
    fn remove_nat64(value: Value) -> Value {
        match value {
            Value::Nat64(n) => Value::Nat(candid::Nat::from(n)),
            Value::Array(a) => Value::Array(a.into_iter().map(remove_nat64).collect()),
            Value::Map(m) => Value::Map(m.into_iter().map(|(k, v)| (k, remove_nat64(v))).collect()),
            v => v,
        }
    }

    proptest!(|(value in arb_value())| {
        let icrc3_value = ICRC3Value::from(value.clone());
        prop_assert_eq!(Value::from(icrc3_value), remove_nat64(value));
    })
}
