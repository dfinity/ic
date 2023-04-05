use candid::types::number::Nat;
use ciborium::value::Value as CiboriumValue;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc::generic_value::Value as GenericValue;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

pub fn icrc1_block_from_encoded(encoded_block: &EncodedBlock) -> GenericBlock {
    let value: CiboriumValue =
        ciborium::de::from_reader(encoded_block.as_slice()).expect("failed to decode block");
    icrc1_block_from_value(&value)
}

fn icrc1_block_from_value(value: &CiboriumValue) -> GenericBlock {
    match value {
        CiboriumValue::Integer(int) => {
            let v: i128 = (*int).into();
            let uv: u128 = v
                .try_into()
                .expect("blocks should not contain negative integers");
            GenericValue::Nat(Nat::from(uv))
        }
        CiboriumValue::Bytes(bytes) => GenericValue::Blob(ByteBuf::from(bytes.to_vec())),
        CiboriumValue::Text(text) => GenericValue::Text(text.to_string()),
        CiboriumValue::Array(values) => {
            let mut vec = Vec::new();
            for v in values.iter() {
                vec.push(icrc1_block_from_value(v));
            }
            GenericValue::Array(vec)
        }
        CiboriumValue::Map(map) => {
            let mut result = BTreeMap::new();
            for (k, v) in map.iter() {
                let key_id = match k {
                    CiboriumValue::Text(text) => text.to_string(),
                    _ => panic!("icrc1 block value key should be a string, not: {:?}", k),
                };
                result.insert(key_id, icrc1_block_from_value(v));
            }

            GenericValue::Map(result)
        }
        CiboriumValue::Bool(_) => panic!("boolean values not supported in icrc1 blocks"),
        CiboriumValue::Null => panic!("Null values not supported in icrc1 blocks"),
        CiboriumValue::Float(_) => panic!("float values not supported in icrc1 blocks"),
        CiboriumValue::Tag(_tag, value) => icrc1_block_from_value(value),
        _ => panic!("unsupported value type: {:?}", value),
    }
}
