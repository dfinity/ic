use crate::known_tags::{BIGNUM, SELF_DESCRIBED};
use ciborium::value::Value;
use ic_crypto_sha2::Sha256;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use std::ops::{BitAnd, ShrAssign};

pub type Hash = [u8; 32];

/// Implements representation-independent hashing for CBOR values.
/// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map
pub fn hash_cbor(bytes: &[u8]) -> Result<Hash, String> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|e| e.to_string())?;
    hash_value(&value)
}

fn hash_value(value: &Value) -> Result<Hash, String> {
    match value {
        Value::Integer(int) => {
            let v: i128 = (*int).into();
            if v < 0 {
                return Err("RI hash is not defined for negative integers".to_string());
            }

            // We need at most ⌈ 128 / 7 ⌉ = 19 bytes to encode a 128 bit
            // integer in LEB128.
            let mut buf = [0u8; 19];
            let mut i = 0;
            leb128_encode(v, |byte| {
                buf[i] = byte;
                i += 1;
            });
            debug_assert!(i > 0);

            Ok(Sha256::hash(&buf[..i]))
        }
        Value::Bytes(bytes) => Ok(Sha256::hash(bytes)),
        Value::Text(text) => Ok(Sha256::hash(text.as_bytes())),
        Value::Tag(SELF_DESCRIBED, value) => hash_value(value),
        Value::Tag(BIGNUM, value) => {
            let bytes = value
                .clone()
                .into_bytes()
                .expect("bug: bignum value is not bytes");
            let mut leb_buf = vec![];
            let v = BigUint::from_bytes_be(&bytes);
            leb128_encode(v, |byte| leb_buf.push(byte));
            Ok(Sha256::hash(&leb_buf[..]))
        }
        Value::Array(values) => {
            let mut hasher = Sha256::new();
            for v in values.iter() {
                let h = hash_value(v)?;
                hasher.write(&h);
            }
            Ok(hasher.finish())
        }
        Value::Map(map) => {
            let mut hpairs = Vec::with_capacity(map.len());
            for (k, v) in map.iter() {
                hpairs.push((hash_value(k)?, hash_value(v)?));
            }

            hpairs.sort_unstable();

            let mut hasher = Sha256::new();
            for (khash, vhash) in hpairs.iter() {
                hasher.write(&khash[..]);
                hasher.write(&vhash[..]);
            }
            Ok(hasher.finish())
        }
        Value::Bool(_) => Err("RI hash is not defined for booleans".to_string()),
        Value::Null => Err("RI hash is not defined for NULL".to_string()),
        Value::Float(_) => Err("RI hash is not defined for floats".to_string()),
        _ => Err(format!("unsupported value type: {value:?}")),
    }
}

fn leb128_encode<N>(mut n: N, mut sink: impl FnMut(u8))
where
    N: ShrAssign<u8> + BitAnd<N, Output = N> + From<u8> + Zero + ToPrimitive + Clone,
{
    loop {
        let byte = (n.clone() & N::from(0x7f))
            .to_u8()
            .expect("bug: cannot cast to u8");
        n >>= 7u8;

        if n.is_zero() {
            sink(byte);
            break;
        } else {
            sink(byte | 0x80);
        }
    }
}

#[test]
fn check_interface_spec_example() {
    use ciborium::cbor;
    use serde_bytes::ByteBuf;

    let value = cbor!({
         "request_type" => "call",
         "canister_id" => ByteBuf::from(b"\x00\x00\x00\x00\x00\x00\x04\xD2".to_vec()),
         "method_name" => "hello",
         "arg" => ByteBuf::from(b"DIDL\x00\xFD*".to_vec()),
    })
    .unwrap();
    assert_eq!(
        hex::encode(hash_value(&value).unwrap()),
        "8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b"
    );
}

#[test]
fn bignum_leb128_encode() {
    let mut bytes = vec![];
    leb128::write::unsigned(&mut bytes, u64::MAX).unwrap();

    let mut bigint_bytes = vec![];
    leb128_encode(BigUint::from(u64::MAX), |b| bigint_bytes.push(b));
    assert_eq!(bytes, bigint_bytes);
}

#[test]
fn u64_leb128_encode() {
    let mut bytes = vec![];
    leb128::write::unsigned(&mut bytes, u64::MAX).unwrap();

    let mut u64_bytes = vec![];
    leb128_encode(u64::MAX, |b| u64_bytes.push(b));
    assert_eq!(bytes, u64_bytes);
}

#[test]
fn hash_max_u64() {
    use ciborium::value::Integer;

    let mut bytes = vec![];
    leb128::write::unsigned(&mut bytes, u64::MAX).unwrap();
    let expected_hash =
        hash_value(&Value::Bytes(bytes.clone())).expect("failed to hash leb128 bytes");

    assert_eq!(
        hash_value(&Value::Integer(Integer::from(u64::MAX))).expect("failed to hash u64::MAX"),
        expected_hash
    );

    assert_eq!(
        hash_value(&Value::Tag(
            BIGNUM,
            Box::new(Value::Bytes(u64::MAX.to_be_bytes().to_vec()))
        ))
        .expect("failed to hash u64::MAX"),
        expected_hash,
    );
}
