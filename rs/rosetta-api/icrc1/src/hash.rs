use ciborium::value::Value;
use ic_crypto_sha::Sha256;

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
            let mut n = v;
            let mut i = 0;

            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;

                if n == 0 {
                    buf[i] = byte;
                    break;
                } else {
                    buf[i] = byte | 0x80;
                    i += 1;
                }
            }

            Ok(Sha256::hash(&buf[..=i]))
        }
        Value::Bytes(bytes) => Ok(Sha256::hash(bytes)),
        Value::Text(text) => Ok(Sha256::hash(text.as_bytes())),
        Value::Tag(_tag, value) => hash_value(value),
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
        _ => Err(format!("unsupported value type: {:?}", value)),
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
fn hash_max_u64() {
    use ciborium::value::Integer;
    use std::convert::TryFrom;

    // Currently, the conversion fails for any values above u64::MAX
    let value = Value::Integer(Integer::try_from(u64::MAX).unwrap());
    let mut bytes = vec![];
    leb128::write::unsigned(&mut bytes, u64::MAX).unwrap();
    assert_eq!(
        hash_value(&value).expect("failed to hash u64::MAX"),
        hash_value(&Value::Bytes(bytes)).expect("failed to hash leb128 bytes")
    );
}
