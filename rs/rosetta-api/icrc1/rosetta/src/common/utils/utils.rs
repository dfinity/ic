use crate::{
    common::{
        constants::DEFAULT_BLOCKCHAIN,
        storage::{
            storage_client::StorageClient,
            types::{RosettaBlock, RosettaToken},
        },
        types::{
            ApproveMetadata, BlockMetadata, BurnMetadata, OperationType, TransactionMetadata,
            TransferMetadata,
        },
    },
    AppState,
};
use anyhow::{bail, Context};
use ic_ledger_core::block::EncodedBlock;
use ic_ledger_hash_of::HashOf;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use rosetta_core::{
    identifiers::{BlockIdentifier, NetworkIdentifier, PartialBlockIdentifier},
    objects::{Amount, Currency},
};
use serde_bytes::ByteBuf;
use std::fmt::Write;
use std::time::Duration;

const MINT_OPERATION_IDENTIFIER: u64 = 0;
const BURN_OPERATION_IDENTIFIER: u64 = 0;
const TRANSFER_OPERATION_IDENTIFIER: u64 = 0;
const APPROVE_OPERATION_IDENTIFIER: u64 = 0;

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

pub fn convert_timestamp_to_millis(timestamp_nanos: u64) -> anyhow::Result<u64> {
    let millis = Duration::from_nanos(timestamp_nanos).as_millis();
    u64::try_from(millis).context(format!(
        "Failed to convert timestamp to milliseconds: {}",
        millis
    ))
}

pub fn get_rosetta_block_from_block_identifier(
    block_identifier: BlockIdentifier,
    storage_client: &StorageClient,
) -> anyhow::Result<RosettaBlock> {
    get_rosetta_block_from_partial_block_identifier(
        &PartialBlockIdentifier::from(block_identifier),
        storage_client,
    )
}

pub fn get_rosetta_block_from_partial_block_identifier(
    partial_block_identifier: &PartialBlockIdentifier,
    storage_client: &StorageClient,
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

pub fn create_progress_bar(start: u64, end: u64) -> ProgressBar {
    // Progress bar for better visualization
    let pb = ProgressBar::new(end.saturating_sub(start).saturating_add(1));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta}) {msg}",
        )
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"),
    );
    pb
}

// Converts a RosettaBlock into a Block from the rosetta_core crate
pub fn icrc1_rosetta_block_to_rosetta_core_block(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<rosetta_core::objects::Block> {
    Ok(rosetta_core::objects::Block {
        metadata: Some(
            BlockMetadata::new(rosetta_block.get_icrc1_block()?, currency.clone())?.try_into()?,
        ),
        block_identifier: rosetta_block.get_block_identifier(),
        parent_block_identifier: rosetta_block.get_parent_block_identifier(),
        timestamp: convert_timestamp_to_millis(rosetta_block.timestamp)?,
        transactions: vec![icrc1_rosetta_block_to_rosetta_core_transaction(
            rosetta_block,
            currency,
        )?],
    })
}

// Converts a rosetta_core Block into an ICRC-1 Block
pub fn rosetta_core_block_to_icrc1_block(
    mut block: rosetta_core::objects::Block,
) -> anyhow::Result<ic_icrc1::Block<RosettaToken>> {
    let block_metadata = BlockMetadata::try_from(block.metadata)?;

    if block.transactions.len() != 1 {
        bail!(
            "Expected one rosetta_core Transaction for one icrc1-Block but got: {:?}",
            block.transactions
        )
    }

    let icrc1_transaction = rosetta_core_transaction_to_icrc1_transaction(
        block
            .transactions
            .pop()
            .context("Transaction vector of rosetta_core Block is empty")?,
    )?;

    Ok(ic_icrc1::Block {
        effective_fee: match icrc1_transaction.operation.clone() {
            ic_icrc1::Operation::Mint { .. } => None,
            ic_icrc1::Operation::Transfer { fee, .. } => {
                if fee.is_none() {
                    block_metadata
                        .fee_paid_by_user
                        .map(RosettaToken::try_from)
                        .transpose()?
                } else {
                    None
                }
            }
            ic_icrc1::Operation::Approve { fee, .. } => {
                if fee.is_none() {
                    block_metadata
                        .fee_paid_by_user
                        .map(RosettaToken::try_from)
                        .transpose()?
                } else {
                    None
                }
            }
            ic_icrc1::Operation::Burn { .. } => None,
        },
        transaction: icrc1_transaction,
        timestamp: block_metadata.block_created_at_nano_seconds,
        fee_collector: block_metadata
            .fee_collector
            .map(|collector| collector.try_into())
            .transpose()?,

        // Parent hash in rosetta_core Block cannot be None for genesis.
        // Genesis block hash is set for Genesis Parent Block Hash
        parent_hash: if block.parent_block_identifier == block.block_identifier {
            None
        } else {
            Some(HashOf::<EncodedBlock>::new(
                ByteBuf::try_from(block.parent_block_identifier)?
                    .as_slice()
                    .try_into()?,
            ))
        },
        fee_collector_block_index: block_metadata.fee_collector_block_index,
    })
}

// Converts a RosettaBlock into a Transaction from the rosetta_core crate
pub fn icrc1_rosetta_block_to_rosetta_core_transaction(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<rosetta_core::objects::Transaction> {
    let icrc1_transaction = rosetta_block.get_transaction()?;
    let metadata: TransactionMetadata = icrc1_transaction.into();

    Ok(rosetta_core::objects::Transaction {
        transaction_identifier: rosetta_block.get_transaction_identifier(),
        operations: vec![icrc1_rosetta_block_to_rosetta_core_operation(
            rosetta_block,
            currency,
        )?],
        metadata: (!metadata.is_empty())
            .then(|| metadata.try_into())
            .transpose()?,
    })
}

// Converts a rosetta_core Transaction into an ICRC-1 Transaction
pub fn rosetta_core_transaction_to_icrc1_transaction(
    mut transaction: rosetta_core::objects::Transaction,
) -> anyhow::Result<ic_icrc1::Transaction<RosettaToken>> {
    let metadata = TransactionMetadata::try_from(transaction.metadata)?;

    if transaction.operations.len() != 1 {
        bail!(
            "Expected one rosetta_core Operation for one icrc1-Operation but got: {:?}",
            transaction.operations
        )
    }

    Ok(ic_icrc1::Transaction {
        operation: rosetta_core_operation_to_icrc1_operation(
            transaction
                .operations
                .pop()
                .context("Operation vector of rosetta_core Transaction is empty")?,
        )?,
        created_at_time: metadata.created_at_time,
        memo: metadata.memo.map(|memo| memo.into()),
    })
}

// Converts a RosettaBlock into an Operation from the rosetta_core crate
pub fn icrc1_rosetta_block_to_rosetta_core_operation(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<rosetta_core::objects::Operation> {
    let icrc1_transaction = rosetta_block.get_transaction()?;
    Ok(match icrc1_transaction.operation {
        ic_icrc1::Operation::Mint { to, amount } => {
            // A Mint operation only has one OperationIdentifier and thus no related Operations
            rosetta_core::objects::Operation::new(
                MINT_OPERATION_IDENTIFIER,
                OperationType::Mint.to_string(),
                Some(to.into()),
                Some(rosetta_core::objects::Amount::new(
                    amount.to_string(),
                    currency,
                )),
                None,
                None,
            )
        }
        ic_icrc1::Operation::Transfer {
            from,
            to,
            spender,
            amount,
            fee,
        } => rosetta_core::objects::Operation::new(
            TRANSFER_OPERATION_IDENTIFIER,
            OperationType::Transfer.to_string(),
            Some(to.into()),
            Some(rosetta_core::objects::Amount::new(
                amount.to_string(),
                currency.clone(),
            )),
            None,
            Some(
                TransferMetadata {
                    from_account: from.into(),
                    spender_account: spender.map(|spender| spender.into()),
                    fee_set_by_user: fee.map(|fee| Amount::new(fee.to_string(), currency)),
                }
                .try_into()?,
            ),
        ),
        ic_icrc1::Operation::Burn {
            from,
            spender,
            amount,
        } => rosetta_core::objects::Operation::new(
            BURN_OPERATION_IDENTIFIER,
            OperationType::Burn.to_string(),
            None,
            Some(rosetta_core::objects::Amount::new(
                amount.to_string(),
                currency,
            )),
            None,
            Some(
                BurnMetadata {
                    from_account: from.into(),
                    spender_account: spender.map(|spender| spender.into()),
                }
                .try_into()?,
            ),
        ),
        ic_icrc1::Operation::Approve {
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
        } => rosetta_core::objects::Operation::new(
            APPROVE_OPERATION_IDENTIFIER,
            OperationType::Approve.to_string(),
            Some(spender.into()),
            Some(Amount::new(amount.to_string(), currency.clone())),
            None,
            Some(
                ApproveMetadata {
                    approver_account: from.into(),
                    expected_allowance: expected_allowance.map(|expected_allowance| {
                        Amount::new(expected_allowance.to_string(), currency.clone())
                    }),
                    expires_at,
                    fee_set_by_user: fee.map(|fee| Amount::new(fee.to_string(), currency)),
                }
                .try_into()?,
            ),
        ),
    })
}

// Takes in a rosetta_core operation that fully defines an icrc1 Operation
// Fails if the given operation is unable to form an icrc1 Operation
pub fn rosetta_core_operation_to_icrc1_operation(
    operation: rosetta_core::objects::Operation,
) -> anyhow::Result<ic_icrc1::Operation<RosettaToken>> {
    Ok(match operation.type_.parse::<OperationType>()? {
        OperationType::Mint => ic_icrc1::Operation::Mint {
            to: operation
                .account
                .context("Account field needs to be populated for Mint operation")?
                .try_into()?,
            amount: operation
                .amount
                .context("Amount field needs to be populated for Mint operation")?
                .try_into()?,
        },
        OperationType::Burn => {
            let metadata = BurnMetadata::try_from(
                operation
                    .metadata
                    .context("Metadata field needs to be populated for Burn operation")?,
            )?;
            ic_icrc1::Operation::Burn {
                from: metadata.from_account.try_into()?,
                amount: operation
                    .amount
                    .context("Amount field needs to be populated for Burn operation")?
                    .try_into()?,
                spender: metadata
                    .spender_account
                    .map(|spender| spender.try_into())
                    .transpose()?,
            }
        }
        OperationType::Transfer => {
            let metadata = TransferMetadata::try_from(
                operation
                    .metadata
                    .context("Metadata field needs to be populated for Transfer operation")?,
            )?;
            ic_icrc1::Operation::Transfer {
                from: metadata.from_account.try_into()?,
                amount: operation
                    .amount
                    .context("Amount field needs to be populated for Transfer operation")?
                    .try_into()?,
                spender: metadata
                    .spender_account
                    .map(|spender| spender.try_into())
                    .transpose()?,
                to: operation
                    .account
                    .context("Account field needs to be populated for Transfer operation")?
                    .try_into()?,
                fee: metadata
                    .fee_set_by_user
                    .map(|fee| fee.try_into())
                    .transpose()?,
            }
        }
        OperationType::Approve => {
            let metadata = ApproveMetadata::try_from(
                operation
                    .metadata
                    .context("Metadata field needs to be populated for Approve operation")?,
            )?;
            ic_icrc1::Operation::Approve {
                from: metadata.approver_account.try_into()?,
                amount: operation
                    .amount
                    .context("Amount field needs to be populated for Approve operation")?
                    .try_into()?,
                spender: operation
                    .account
                    .map(|spender| spender.try_into())
                    .transpose()?
                    .context("Account field needs to be populated for Approve operation")?,
                fee: metadata
                    .fee_set_by_user
                    .map(|fee| fee.try_into())
                    .transpose()?,
                expected_allowance: metadata
                    .expected_allowance
                    .map(|expected_allowance| expected_allowance.try_into())
                    .transpose()?,
                expires_at: metadata.expires_at,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_icrc1::Block;
    use ic_icrc1_test_utils::account_strategy;
    use ic_icrc1_test_utils::arb_amount;
    use ic_icrc1_test_utils::blocks_strategy;
    use ic_icrc1_tokens_u256::U256;
    use ic_icrc1_tokens_u64::U64;
    use ic_ledger_core::{block::BlockType, tokens::TokensType};
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;
    use rosetta_core::identifiers::AccountIdentifier;

    const NUM_TEST_CASES: u32 = 100;

    fn test_block_conversion<T: TokensType>(block: Block<T>) {
        let currency = Currency::default();
        let rosetta_block = RosettaBlock::from_encoded_block(block.encode(), 0).unwrap();
        let rosetta_core_block =
            icrc1_rosetta_block_to_rosetta_core_block(rosetta_block.clone(), currency).unwrap();
        let derived_block = rosetta_core_block_to_icrc1_block(rosetta_core_block).unwrap();
        assert_eq!(rosetta_block.get_icrc1_block().unwrap(), derived_block);
    }

    proptest! {
            #![proptest_config(ProptestConfig {
                cases: NUM_TEST_CASES,
                ..ProptestConfig::default()
            })]

            #[test]
            fn test_account_conversions(account in account_strategy()){
                let accountidentifier:AccountIdentifier = account.into();
                let derived_account:icrc_ledger_types::icrc1::account::Account  = accountidentifier.try_into().unwrap();
                assert_eq!(derived_account,account);
            }

            #[test]
            fn test_block_conversions_rosetta_tokens(block in blocks_strategy::<RosettaToken>(arb_amount())){
                test_block_conversion(block)
            }

            #[test]
            fn test_block_conversions_u64(block in blocks_strategy::<U64>(arb_amount())){
                test_block_conversion(block)
            }

            #[test]
            fn test_block_conversions_u256(block in blocks_strategy::<U256>(arb_amount())){
                test_block_conversion(block)
            }
    }
}
