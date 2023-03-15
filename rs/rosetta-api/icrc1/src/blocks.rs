use candid::types::number::Nat;
use ciborium::value::Value;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::block::Block;
use icrc_ledger_types::value::Value as BlockValue;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

pub fn icrc1_block_from_encoded(encoded_block: &EncodedBlock) -> Block {
    let value: Value =
        ciborium::de::from_reader(encoded_block.as_slice()).expect("failed to decode block");
    icrc1_block_from_value(&value)
}

fn icrc1_block_from_value(value: &Value) -> Block {
    match value {
        Value::Integer(int) => {
            let v: i128 = (*int).into();
            let uv: u128 = v
                .try_into()
                .expect("blocks should not contain negative integers");
            BlockValue::Nat(Nat::from(uv))
        }
        Value::Bytes(bytes) => BlockValue::Blob(ByteBuf::from(bytes.to_vec())),
        Value::Text(text) => BlockValue::Text(text.to_string()),
        Value::Tag(_tag, value) => icrc1_block_from_value(value),
        Value::Array(values) => {
            let mut vec = Vec::new();
            for v in values.iter() {
                vec.push(icrc1_block_from_value(v));
            }
            BlockValue::Array(vec)
        }
        Value::Map(map) => {
            let mut result = BTreeMap::new();
            for (k, v) in map.iter() {
                let key_id = match k {
                    Value::Text(text) => text.to_string(),
                    _ => panic!("icrc1 block value key should be a string, not: {:?}", k),
                };
                result.insert(key_id, icrc1_block_from_value(v));
            }

            BlockValue::Map(result)
        }
        Value::Bool(_) => panic!("boolean values not supported in icrc1 blocks"),
        Value::Null => panic!("Null values not supported in icrc1 blocks"),
        Value::Float(_) => panic!("float values not supported in icrc1 blocks"),
        _ => panic!("unsupported value type: {:?}", value),
    }
}
