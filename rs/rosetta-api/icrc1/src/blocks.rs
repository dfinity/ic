use candid::types::number::Nat;
use ciborium::into_writer;
use ciborium::value::Value as CiboriumValue;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc::generic_value::Value as GenericValue;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use icrc_ledger_types::icrc3::transactions::GenericTransaction;
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

const CBOR_TRANSACTION_KEY: &str = "tx";

// Tag for Self-described CBOR; see Section 3.4.6 https://www.rfc-editor.org/rfc/rfc8949.html
const SELF_DESCRIBED_CBOR_TAG: u64 = 55799;

fn generic_block_to_ciborium_value(generic_block: GenericBlock) -> Result<ciborium::Value, String> {
    fn extract_value(value: GenericBlock) -> Result<ciborium::Value, String> {
        match value {
            GenericBlock::Nat(nat) => {
                let uint = nat.0.to_u64().ok_or("Could not convert Nat to u64")?;
                Ok(ciborium::Value::Integer(uint.into()))
            }
            GenericBlock::Nat64(int) => Ok(ciborium::Value::Integer(int.into())),
            GenericBlock::Int(int) => {
                let v: i64 = int.0.to_i64().ok_or("Could not convert Int to i64")?;
                let uv: u64 = v
                    .try_into()
                    .map_err(|e| format!("Could not convert Int to i64: {}", e))?;
                Ok(ciborium::Value::Integer(uv.into()))
            }
            GenericBlock::Blob(bytes) => Ok(ciborium::Value::Bytes(bytes.to_vec())),
            GenericBlock::Text(text) => Ok(ciborium::Value::Text(text)),
            GenericBlock::Array(values) => Ok(ciborium::Value::Array(
                values
                    .into_iter()
                    .map(extract_value)
                    .collect::<Result<Vec<ciborium::Value>, String>>()?,
            )),
            GenericBlock::Map(map) => Ok(ciborium::Value::Map(
                map.into_iter()
                    .map(|(k, v)| extract_value(v).map(|value| (ciborium::Value::Text(k), value)))
                    .collect::<Result<Vec<(ciborium::Value, ciborium::Value)>, String>>()?,
            )),
        }
    }
    Ok(ciborium::Value::Tag(
        SELF_DESCRIBED_CBOR_TAG,
        Box::new(extract_value(generic_block)?),
    ))
}

pub fn generic_block_to_encoded_block(generic_block: GenericBlock) -> Result<EncodedBlock, String> {
    // Convert the GenericBlock into ciborium::value::Value
    let derived: ciborium::Value = generic_block_to_ciborium_value(generic_block)?;
    // Convert the ciborium::value::Value into bytes
    let mut bytes = vec![];
    into_writer(&derived, &mut bytes).map_err(|e| e.to_string())?;
    Ok(EncodedBlock::from_vec(bytes))
}

pub fn encoded_block_to_generic_block(encoded_block: &EncodedBlock) -> GenericBlock {
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

pub fn generic_transaction_from_generic_block(
    generic_block: GenericBlock,
) -> Result<GenericTransaction, String> {
    match generic_block {
        GenericBlock::Map(map) => map
            .get(CBOR_TRANSACTION_KEY)
            .ok_or_else(|| {
                "Generic Block must contain 'tx' key for cbor representation of transaction".into()
            })
            .cloned(),
        _ => Err("Generic Block must be a Map".into()),
    }
}
