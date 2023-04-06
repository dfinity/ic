use ciborium::ser::into_writer;
use ciborium::Value as CiboriumValue;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc3::{blocks::GenericBlock, transactions::GenericTransaction};
use num_traits::ToPrimitive;

// Tag for Self-described CBOR; see Section 3.4.6 https://www.rfc-editor.org/rfc/rfc8949.html
const SELF_DESCRIBED_CBOR_TAG: u64 = 55799;
const CBOR_TRANSACTION_KEY: &str = "tx";

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

pub fn generic_block_to_encoded_block(generic_block: GenericBlock) -> anyhow::Result<EncodedBlock> {
    // Convert the GenericBlock into ciborium::value::Value
    let derived: CiboriumValue = generic_block_to_ciborium_value(generic_block)?;
    // Convert the ciborium::value::Value into bytes
    let mut bytes = vec![];
    into_writer(&derived, &mut bytes)?;
    Ok(EncodedBlock::from_vec(bytes))
}

pub fn generic_transaction_from_generic_block(
    generic_block: GenericBlock,
) -> anyhow::Result<GenericTransaction> {
    match generic_block {
        GenericBlock::Map(map) => map
            .get(CBOR_TRANSACTION_KEY)
            .ok_or_else(|| {
                anyhow::Error::msg(
                    "Generic Block must contain 'tx' key for cbor representation of transaction",
                )
            })
            .cloned(),
        _ => Err(anyhow::Error::msg("Generic Block must be a Map")),
    }
}

#[cfg(test)]
mod tests {
    use crate::common::utils::conversion::{
        generic_block_to_ciborium_value, generic_transaction_from_generic_block,
    };
    use crate::common::utils::unit_test_utils::strategies::blocks_strategy;

    use ciborium::ser::into_writer;
    use ciborium::Value;
    use ic_icrc1::{blocks::icrc1_block_from_encoded, Block, Transaction};
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::block::{BlockType, EncodedBlock};

    use icrc_ledger_types::icrc3::blocks::GenericBlock;
    use icrc_ledger_types::icrc3::transactions::GenericTransaction;
    use proptest::prelude::*;

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

    #[test]
    fn test_generic_transaction_hash(block in blocks_strategy()) {

        let encoded_block = block.clone().encode();
        // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
        let block_value:GenericBlock = icrc1_block_from_encoded(&encoded_block);

        //Convert generic block to generic transaction
        let derived_transaction:GenericTransaction = generic_transaction_from_generic_block(block_value).unwrap();

       //Check that the hash of the generic transaction and the transaction object are the same
        assert_eq!(derived_transaction.hash().to_vec(),<Transaction as LedgerTransaction>::hash(&block.transaction).as_slice().to_vec());
    }
    }
}
