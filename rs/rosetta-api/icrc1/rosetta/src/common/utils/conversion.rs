use ciborium::Value as CiboriumValue;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use num_traits::ToPrimitive;

// Tag for Self-described CBOR; see Section 3.4.6 https://www.rfc-editor.org/rfc/rfc8949.html
const SELF_DESCRIBED_CBOR_TAG: u64 = 55799;

pub fn generic_block_to_ciborium_value(
    generic_block: GenericBlock,
) -> anyhow::Result<CiboriumValue> {
    fn extract_value(value: GenericBlock) -> anyhow::Result<CiboriumValue> {
        match value {
            GenericBlock::Nat(nat) => {
                let uint = nat
                    .0
                    .to_u64()
                    .ok_or_else(|| anyhow::Error::msg("Could not convert Nat to u64"))?;
                Ok(CiboriumValue::Integer(uint.into()))
            }
            GenericBlock::Nat64(int) => Ok(CiboriumValue::Integer(int.into())),
            GenericBlock::Int(int) => {
                let v: i64 = int
                    .0
                    .to_i64()
                    .ok_or_else(|| anyhow::Error::msg("Could not convert Int to i64"))?;
                let uv: u64 = v
                    .try_into()
                    .map_err(|_| anyhow::Error::msg("Could not convert Int to i64".to_string()))?;
                Ok(CiboriumValue::Integer(uv.into()))
            }
            GenericBlock::Blob(bytes) => Ok(CiboriumValue::Bytes(bytes.to_vec())),
            GenericBlock::Text(text) => Ok(CiboriumValue::Text(text)),
            GenericBlock::Array(values) => Ok(CiboriumValue::Array(
                values
                    .into_iter()
                    .map(extract_value)
                    .collect::<anyhow::Result<Vec<CiboriumValue>>>()?,
            )),
            GenericBlock::Map(map) => Ok(CiboriumValue::Map(
                map.into_iter()
                    .map(|(k, v)| extract_value(v).map(|value| (CiboriumValue::Text(k), value)))
                    .collect::<anyhow::Result<Vec<(CiboriumValue, CiboriumValue)>>>()?,
            )),
        }
    }
    Ok(CiboriumValue::Tag(
        SELF_DESCRIBED_CBOR_TAG,
        Box::new(extract_value(generic_block)?),
    ))
}

#[cfg(test)]
mod tests {
    use crate::common::utils::conversion::generic_block_to_ciborium_value;
    use candid::Principal;
    use ciborium::ser::into_writer;
    use ciborium::Value;
    use ic_icrc1::{blocks::icrc1_block_from_encoded, Block, Operation, Transaction};
    use ic_ledger_core::block::{BlockType, EncodedBlock};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use icrc_ledger_types::icrc3::blocks::GenericBlock;
    use proptest::prelude::*;
    use serde_bytes::ByteBuf;

    fn principal_strategy() -> impl Strategy<Value = Principal> {
        let bytes_strategy = prop::collection::vec(0..=255u8, 29);
        bytes_strategy.prop_map(|bytes| Principal::from_slice(bytes.as_slice()))
    }

    fn account_strategy() -> impl Strategy<Value = Account> {
        let bytes_strategy = prop::option::of(prop::collection::vec(0..=255u8, 32));
        let principal_strategy = principal_strategy();
        (bytes_strategy, principal_strategy).prop_map(|(bytes, principal)| Account {
            owner: principal,
            subaccount: bytes.map(|x| x.as_slice().try_into().unwrap()),
        })
    }

    fn operation_strategy() -> impl Strategy<Value = Operation> {
        prop_oneof![
            (any::<u64>(), account_strategy())
                .prop_map(|(amount, to)| Operation::Mint { to, amount }),
            (any::<u64>(), account_strategy())
                .prop_map(|(amount, from)| Operation::Burn { from, amount }),
            (
                any::<u64>(),
                account_strategy(),
                account_strategy(),
                prop::option::of(prop::num::u64::ANY)
            )
                .prop_map(|(amount, to, from, fee)| Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee
                }),
        ]
    }

    fn transaction_strategy() -> impl Strategy<Value = Transaction> {
        let operation_strategy = operation_strategy();
        let memo_strategy = prop::option::of(
            prop::collection::vec(0..=255u8, 32).prop_map(|x| Memo(ByteBuf::from(x))),
        );
        let created_at_time_strategy = prop::option::of(any::<u64>());
        (operation_strategy, memo_strategy, created_at_time_strategy).prop_map(
            |(operation, memo, created_at_time)| Transaction {
                operation,
                created_at_time,
                memo,
            },
        )
    }

    fn blocks_strategy() -> impl Strategy<Value = Block> {
        let transaction_strategy = transaction_strategy();
        let fee_collector_strategy = prop::option::of(account_strategy());
        let fee_collector_block_index_strategy = prop::option::of(any::<u64>());
        let effective_fee_strategy = prop::option::of(any::<u64>());
        let timestamp_strategy = any::<u64>();
        (
            transaction_strategy,
            effective_fee_strategy,
            timestamp_strategy,
            fee_collector_strategy,
            fee_collector_block_index_strategy,
        )
            .prop_map(
                |(
                    transaction,
                    effective_fee,
                    timestamp,
                    fee_collector,
                    fee_collector_block_index,
                )| {
                    Block {
                        parent_hash: Some(Block::block_hash(
                            &Block {
                                parent_hash: None,
                                transaction: transaction.clone(),
                                effective_fee,
                                timestamp,
                                fee_collector,
                                fee_collector_block_index,
                            }
                            .encode(),
                        )),
                        transaction,
                        effective_fee,
                        timestamp,
                        fee_collector,
                        fee_collector_block_index,
                    }
                },
            )
    }

    proptest! {
        #[test]
    fn test_generic_block_to_ciborium_block_conversion(block in blocks_strategy()) {
        let encoded_block = block.clone().encode();
        // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
        let block_value:GenericBlock = icrc1_block_from_encoded(&encoded_block);

        // Convert the GenericBlock into ciborium::value::Value
        let derived:Value = generic_block_to_ciborium_value(block_value).unwrap();

        // Convert the ciborium::value::Value into bytes
        let mut bytes = vec![];
        into_writer(&derived, &mut bytes).unwrap();

        // Convert the bytes to EncodedBlock and then to icrc1::Block and check that the resulting block is the same as the original
        assert_eq!(block,Block::decode( EncodedBlock::from_vec(bytes)).unwrap());
    }
    }
}
