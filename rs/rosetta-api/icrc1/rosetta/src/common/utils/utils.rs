use crate::{
    common::storage::{storage_client::StorageClient, types::RosettaBlock},
    AppState,
};
use anyhow::{bail, Context};
use rosetta_core::identifiers::{
    AccountIdentifier, BlockIdentifier, NetworkIdentifier, PartialBlockIdentifier,
    SubAccountIdentifier,
};
use serde_bytes::ByteBuf;
use std::sync::Arc;

const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

pub fn verify_network_id(
    network_identifier: &NetworkIdentifier,
    state: &AppState,
) -> anyhow::Result<()> {
    let expected = &NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        state.icrc1_agent.ledger_canister_id.to_string(),
    );

    if network_identifier != expected {
        bail!(
            "Network Identifiers did not match: Expected {:?} | Actual {:?}",
            expected,
            network_identifier
        )
    }
    Ok(())
}

pub fn icrc1_account_to_rosetta_accountidentifier(
    account: &icrc_ledger_types::icrc1::account::Account,
) -> AccountIdentifier {
    AccountIdentifier {
        address: account.owner.to_string(),
        sub_account: account.subaccount.map(|s| SubAccountIdentifier {
            address: hex::encode(s),
            metadata: None,
        }),
        metadata: None,
    }
}

pub fn get_rosetta_block_from_block_identifier(
    block_identifier: BlockIdentifier,
    storage_client: Arc<StorageClient>,
) -> anyhow::Result<RosettaBlock> {
    get_rosetta_block_from_partial_block_identifier(block_identifier.into(), storage_client)
}

pub fn get_rosetta_block_from_partial_block_identifier(
    partial_block_identifier: PartialBlockIdentifier,
    storage_client: Arc<StorageClient>,
) -> anyhow::Result<RosettaBlock> {
    Ok(
        match (
            partial_block_identifier.index,
            partial_block_identifier.hash.as_ref(),
        ) {
            (None, Some(hash)) => {
                let hash_bytes = hex::decode(hash)
                    .with_context(|| format!("Invalid block hash provided: {:?}", hash))?;
                let hash_buf = ByteBuf::from(hash_bytes);
                storage_client
                    .get_block_by_hash(hash_buf.clone())
                    .with_context(|| format!("Unable to retrieve block with hash: {:?}", hash_buf))?
                    .with_context(|| format!("Block with hash {} could not be found", hash))?
            }

            (Some(block_idx), None) => storage_client
                .get_block_at_idx(block_idx)
                .with_context(|| format!("Unable to retrieve block with idx: {}", block_idx))?
                .with_context(|| format!("Block at index {} could not be found", block_idx))?,
            (Some(block_idx), Some(hash)) => {
                let rosetta_block = storage_client
                    .get_block_at_idx(block_idx)
                    .with_context(|| format!("Unable to retrieve block with idx: {}", block_idx))?
                    .with_context(|| format!("Block at index {} could not be found", block_idx))?;
                if &hex::encode(&rosetta_block.block_hash) != hash {
                    bail!("Both index {} and hash {} were provided but they do not match the same block. Actual index {} and hash {}",block_idx,hash,rosetta_block.index,hex::encode(&rosetta_block.block_hash));
                }
                rosetta_block
            }
            (None, None) => bail!("Neither block index nor block hash were provided".to_owned(),),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const NUM_TEST_CASES: u32 = 5;
    use ic_icrc1_test_utils::account_strategy;

    use proptest::prelude::ProptestConfig;
    use proptest::proptest;

    proptest! {
            #![proptest_config(ProptestConfig {
                cases: NUM_TEST_CASES,
                ..ProptestConfig::default()
            })]
            #[test]
            fn test_account_conversions(account in account_strategy()){
                let accountidentifier = icrc1_account_to_rosetta_accountidentifier(&account);
                let derived_account:icrc_ledger_types::icrc1::account::Account  = accountidentifier.try_into().unwrap();
                assert_eq!(derived_account,account);
            }
    }
}
