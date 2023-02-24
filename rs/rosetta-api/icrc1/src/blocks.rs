use candid::types::number::{Int, Nat};
use candid::CandidType;
use ciborium::value::{Integer, Value};
use ic_ledger_core::block::EncodedBlock;
use num_traits::ToPrimitive;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// Variant type for the block endpoint values.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum BlockValue {
    Blob(ByteBuf),
    Text(String),
    Nat(Nat),
    Nat64(u64),
    Int(Int),
    Array(Vec<BlockValue>),
    Map(BlockValueMap),
}

impl BlockValue {
    pub fn hash(&self) -> [u8; 32] {
        crate::hash::hash_value(&self.to_cbor().expect("bug: invalid block"))
            .expect("bug: cannot compute hash of a valid block")
    }

    fn to_cbor(&self) -> Result<Value, String> {
        match self {
            Icrc1Block::Int(int) => {
                let int = int
                    .0
                    .to_i128()
                    .ok_or_else(|| "big int does not fit into i128".to_string())?;
                Ok(Value::from(int))
            }
            Icrc1Block::Nat(nat) => {
                let nat = nat
                    .0
                    .to_i128()
                    .ok_or_else(|| "nat does not fit into i128".to_string())?;
                Ok(Value::from(nat))
            }
            Icrc1Block::Nat64(nat64) => Ok(Value::Integer(Integer::from(*nat64))),
            Icrc1Block::Text(text) => Ok(Value::Text(text.to_string())),
            Icrc1Block::Blob(blob) => Ok(Value::Bytes(blob.to_vec())),
            Icrc1Block::Array(array) => {
                let mut vec = Vec::new();
                for v in array.iter() {
                    vec.push(v.to_cbor()?);
                }
                Ok(Value::Array(vec))
            }
            Icrc1Block::Map(map) => {
                let mut vec = Vec::with_capacity(map.len());
                for (k, v) in map.iter() {
                    vec.push((Value::Text(k.to_string()), v.to_cbor()?));
                }
                Ok(Value::Map(vec))
            }
        }
    }
}

pub type BlockValueMap = BTreeMap<String, BlockValue>;

pub type Icrc1Block = BlockValue;

impl From<&EncodedBlock> for Icrc1Block {
    fn from(encoded_block: &EncodedBlock) -> Icrc1Block {
        let value: Value =
            ciborium::de::from_reader(encoded_block.as_slice()).expect("failed to decode block");
        icrc1_block_from_value(&value)
    }
}

fn icrc1_block_from_value(value: &Value) -> Icrc1Block {
    match value {
        Value::Integer(int) => {
            let v: i128 = (*int).into();
            BlockValue::Int(Int::from(v))
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
