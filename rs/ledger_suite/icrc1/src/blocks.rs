use crate::known_tags::{BIGNUM, NEG_BIGNUM, SELF_DESCRIBED};
use crate::{Block, Transaction};
use candid::{Int, Nat};
use ciborium::into_writer;
use ciborium::value::Value as CiboriumValue;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc::generic_value::Value as GenericValue;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use icrc_ledger_types::icrc3::transactions::GenericTransaction;
use num_traits::{Signed, ToPrimitive};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use thiserror::Error;

const CBOR_TRANSACTION_KEY: &str = "tx";

/// The maximum allowed value nesting within a CBOR value.
const VALUE_DEPTH_LIMIT: usize = 64;

fn generic_block_to_ciborium_value(generic_block: GenericBlock) -> Result<ciborium::Value, String> {
    fn extract_value(value: GenericBlock) -> Result<ciborium::Value, String> {
        match value {
            GenericBlock::Nat(nat) => match nat.0.to_u64() {
                Some(n) => Ok(CiboriumValue::Integer(n.into())),
                None => Ok(CiboriumValue::Tag(
                    BIGNUM,
                    Box::new(CiboriumValue::Bytes(nat.0.to_bytes_be())),
                )),
            },
            GenericBlock::Nat64(int) => Ok(ciborium::Value::Integer(int.into())),
            GenericBlock::Int(int) => match int.0.to_i64() {
                Some(n) => Ok(ciborium::Value::Integer(n.into())),
                None => Ok(if int.0.is_positive() {
                    let (_sign, bytes) = int.0.to_bytes_be();
                    CiboriumValue::Tag(BIGNUM, Box::new(CiboriumValue::Bytes(bytes)))
                } else {
                    // The spec says:
                    // > For tag number 3, the value of the bignum is -1 - n.
                    // So we add one to the value before obtaining the BE bytes.
                    let (_sign, bytes) = (int.0 + 1u8).to_bytes_be();
                    CiboriumValue::Tag(NEG_BIGNUM, Box::new(CiboriumValue::Bytes(bytes)))
                }),
            },
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
        SELF_DESCRIBED,
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
    icrc1_block_from_value(value, 0).expect("failed to decode encoded block")
}

#[derive(Debug, Error)]
enum ValueDecodingError {
    #[error("CBOR value depth must not exceed {max_depth}")]
    DepthLimitExceeded { max_depth: usize },
    #[error("unsupported CBOR map key value {0:?} (only text keys are allowed)")]
    UnsupportedKeyType(String),
    #[error("unsupported CBOR tag {0} (value = {1:?})")]
    UnsupportedTag(u64, CiboriumValue),
    #[error("unsupported CBOR value value {0}")]
    UnsupportedValueType(&'static str),
    #[error("cannot decode CBOR value {0:?}")]
    UnsupportedValue(CiboriumValue),
}

fn icrc1_block_from_value(
    value: CiboriumValue,
    depth: usize,
) -> Result<GenericBlock, ValueDecodingError> {
    if depth == VALUE_DEPTH_LIMIT {
        return Err(ValueDecodingError::DepthLimitExceeded {
            max_depth: VALUE_DEPTH_LIMIT,
        });
    }

    match value {
        CiboriumValue::Integer(int) => {
            let value: i128 = int.into();
            let maybe_unsigned: Result<u128, _> = value.try_into();
            match maybe_unsigned {
                Ok(positive) => {
                    if positive <= u64::MAX as u128 {
                        Ok(GenericValue::Nat64(positive as u64))
                    } else {
                        Ok(GenericValue::Nat(Nat::from(positive)))
                    }
                }
                Err(_) => Ok(GenericValue::Int(Int::from(value))),
            }
        }
        CiboriumValue::Bytes(bytes) => Ok(GenericValue::Blob(ByteBuf::from(bytes))),
        CiboriumValue::Text(text) => Ok(GenericValue::Text(text)),
        CiboriumValue::Array(values) => Ok(GenericValue::Array(
            values
                .into_iter()
                .map(|v| icrc1_block_from_value(v, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        CiboriumValue::Map(map) => Ok(GenericValue::Map(
            map.into_iter()
                .map(|(k, v)| {
                    let key = k
                        .into_text()
                        .map_err(|k| ValueDecodingError::UnsupportedKeyType(format!("{k:?}")))?;
                    Ok((key, icrc1_block_from_value(v, depth + 1)?))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        )),
        CiboriumValue::Bool(_) => Err(ValueDecodingError::UnsupportedValueType("bool")),
        CiboriumValue::Null => Err(ValueDecodingError::UnsupportedValueType("null")),
        CiboriumValue::Float(_) => Err(ValueDecodingError::UnsupportedValueType("float")),
        CiboriumValue::Tag(SELF_DESCRIBED, value) => icrc1_block_from_value(*value, depth + 1),
        CiboriumValue::Tag(BIGNUM, value) => {
            let value_bytes = value
                .into_bytes()
                .map_err(|_| ValueDecodingError::UnsupportedValueType("non-bytes bignums"))?;
            Ok(GenericValue::Nat(Nat(num_bigint::BigUint::from_bytes_be(
                &value_bytes,
            ))))
        }
        CiboriumValue::Tag(NEG_BIGNUM, value) => {
            use num_bigint::{BigInt, BigUint, Sign};
            let value_bytes = value.into_bytes().map_err(|_| {
                ValueDecodingError::UnsupportedValueType("non-bytes negative bignums")
            })?;
            Ok(GenericValue::Int(Int(BigInt::from_biguint(
                Sign::Minus,
                BigUint::from_bytes_be(&value_bytes),
            ) - 1)))
        }
        CiboriumValue::Tag(tag, value) => Err(ValueDecodingError::UnsupportedTag(tag, *value)),
        // NB. ciborium::value::Value is marked as #[non_exhaustive]
        other => Err(ValueDecodingError::UnsupportedValue(other)),
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

impl<Tokens: TokensType> TryFrom<GenericBlock> for Block<Tokens> {
    type Error = String;
    fn try_from(value: GenericBlock) -> Result<Self, Self::Error> {
        Self::decode(generic_block_to_encoded_block(value)?)
    }
}

impl<Tokens: TokensType> TryFrom<GenericBlock> for Transaction<Tokens> {
    type Error = String;
    fn try_from(value: GenericBlock) -> Result<Self, Self::Error> {
        Ok(Block::try_from(value)?.transaction)
    }
}

#[test]
fn negative_integer_round_trip() {
    fn check(text: &str) {
        let int: Int = text.parse().expect("failed to parse an integer");
        let value = GenericValue::Int(int);
        let cbor_value = generic_block_to_ciborium_value(value.clone()).unwrap();
        assert_eq!(
            value,
            icrc1_block_from_value(cbor_value, 0).unwrap(),
            "round trip failed for {text}"
        );
    }

    check("-1");
    check("-1_000_000_000_000_000");
    check("-1_000_000_000_000_000_000_000");
    check("-1_000_000_000_000_000_000_000_000_000_000");
    check("-1_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000");
    check("-1_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000");
}

#[test]
fn positive_big_integer_round_trip() {
    fn check(text: &str) {
        let nat: Nat = text.parse().expect("failed to parse an integer");
        let value = GenericValue::Nat(nat);
        let cbor_value = generic_block_to_ciborium_value(value.clone()).unwrap();
        assert_eq!(
            value,
            icrc1_block_from_value(cbor_value, 0).unwrap(),
            "round trip failed for {text}"
        );
    }

    check("18446744073709551616");
    check("184467440737095516160");
    check("1844674407370955161600");
    check("1844674407370955161600000000000000000000000000000000000000000000");
}
