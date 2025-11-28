use crate::common::storage::types::{IcrcOperation, RosettaBlock};
use crate::common::types::{FeeMetadata, FeeSetter};
use crate::{
    AppState, MultiTokenAppState,
    common::{
        constants::{DEFAULT_BLOCKCHAIN, MIN_PROGRESS_BAR},
        storage::storage_client::StorageClient,
        types::{ApproveMetadata, BlockMetadata, OperationType, TransactionMetadata},
    },
};
use anyhow::{Context, bail};
use candid::Nat;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use num_bigint::BigInt;
use rosetta_core::identifiers::*;
use rosetta_core::{
    identifiers::{BlockIdentifier, NetworkIdentifier, PartialBlockIdentifier},
    objects::{Amount, Currency},
};
use serde_bytes::ByteBuf;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

pub fn get_state_from_network_id(
    network_identifier: &NetworkIdentifier,
    multitoken_state: &MultiTokenAppState,
) -> anyhow::Result<Arc<AppState>> {
    let state = match multitoken_state
        .token_states
        .get(network_identifier.network.as_str())
    {
        Some(state) => state.clone(),
        None => {
            bail!(
                "Network Identifier {} not being tracked",
                network_identifier.blockchain
            );
        }
    };

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
    Ok(state.clone())
}

pub fn convert_timestamp_to_millis(timestamp_nanos: u64) -> anyhow::Result<u64> {
    let millis = Duration::from_nanos(timestamp_nanos).as_millis();
    u64::try_from(millis).context(format!(
        "Failed to convert timestamp to milliseconds: {millis}"
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
                    .with_context(|| format!("Invalid block hash provided: {hash:?}"))?;
                let hash_buf = ByteBuf::from(hash_bytes);
                storage_client
                    .get_block_by_hash(hash_buf.clone())
                    .with_context(|| format!("Unable to retrieve block with hash: {hash_buf:?}"))?
                    .with_context(|| format!("Block with hash {hash} could not be found"))?
            }

            (Some(block_idx), None) => storage_client
                .get_block_at_idx(block_idx)
                .with_context(|| format!("Unable to retrieve block with idx: {block_idx}"))?
                .with_context(|| format!("Block at index {block_idx} could not be found"))?,
            (Some(block_idx), Some(hash)) => {
                let rosetta_block = storage_client
                    .get_block_at_idx(block_idx)
                    .with_context(|| format!("Unable to retrieve block with idx: {block_idx}"))?
                    .with_context(|| format!("Block at index {block_idx} could not be found"))?;
                if &hex::encode(rosetta_block.clone().get_block_hash()) != hash {
                    bail!(
                        "Both index {} and hash {} were provided but they do not match the same block. Actual index {} and hash {}",
                        block_idx,
                        hash,
                        rosetta_block.index,
                        hex::encode(rosetta_block.clone().get_block_hash())
                    );
                }
                rosetta_block
            }
            (None, None) => storage_client
                .get_block_with_highest_block_idx()
                .with_context(|| "Unable to retrieve the latest block".to_string())?
                .with_context(|| {
                    "Latest block could not be found, the blockchain is empty".to_string()
                })?,
        },
    )
}

pub fn create_progress_bar_if_needed(start: u64, end: u64) -> Option<ProgressBar> {
    if end - start < MIN_PROGRESS_BAR {
        return None;
    }
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
    Some(pb)
}

/// Takes in a vector of rosetta_core operations that fully define a single icrc1 Operation
/// Fails if the given operation is unable to form an icrc1 Operation
pub fn rosetta_core_operations_to_icrc1_operation(
    operation: Vec<rosetta_core::objects::Operation>,
) -> anyhow::Result<crate::common::storage::types::IcrcOperation> {
    enum IcrcOperation {
        Mint,
        Burn,
        Transfer,
        Approve,
    }

    // A builder which helps depict the icrc1 Operation and allows for an arbitrary order of rosetta_core Operations
    struct IcrcOperationBuilder {
        icrc_operation: Option<IcrcOperation>,
        to: Option<AccountIdentifier>,
        from: Option<AccountIdentifier>,
        spender: Option<AccountIdentifier>,
        amount: Option<Nat>,
        fee: Option<Nat>,
        expected_allowance: Option<Nat>,
        expires_at: Option<u64>,
        allowance: Option<Nat>,
    }

    impl IcrcOperationBuilder {
        pub fn new() -> Self {
            Self {
                icrc_operation: None,
                to: None,
                from: None,
                spender: None,
                amount: None,
                fee: None,
                expected_allowance: None,
                expires_at: None,
                allowance: None,
            }
        }

        pub fn with_icrc_operation(mut self, icrc_operation: IcrcOperation) -> Self {
            self.icrc_operation = Some(icrc_operation);
            self
        }

        pub fn with_to_accountidentifier(mut self, to: AccountIdentifier) -> Self {
            self.to = Some(to);
            self
        }

        pub fn with_from_accountidentifier(mut self, from: AccountIdentifier) -> Self {
            self.from = Some(from);
            self
        }

        pub fn with_spender_accountidentifier(mut self, spender: AccountIdentifier) -> Self {
            self.spender = Some(spender);
            self
        }

        pub fn with_amount(mut self, amount: Nat) -> Self {
            self.amount = Some(amount);
            self
        }

        pub fn with_fee(mut self, fee: Nat) -> Self {
            self.fee = Some(fee);
            self
        }

        pub fn with_expected_allowance(mut self, expected_allowance: Nat) -> Self {
            self.expected_allowance = Some(expected_allowance);
            self
        }

        pub fn with_allowance(mut self, allowance: Nat) -> Self {
            self.allowance = Some(allowance);
            self
        }

        pub fn with_expires_at(mut self, expires_at: u64) -> Self {
            self.expires_at = Some(expires_at);
            self
        }

        pub fn build(self) -> anyhow::Result<crate::common::storage::types::IcrcOperation> {
            Ok(match self.icrc_operation.context("Icrc Operation type needs to be of type Mint, Burn, Transfer or Approve")? {
                IcrcOperation::Mint => {
                    if self.from.is_some() {
                        bail!("From AccountIdentifier field is not allowed for Mint operation")
                    }
                    if self.spender.is_some() {
                        bail!("Spender AccountIdentifier field is not allowed for Mint operation")
                    }
                    crate::common::storage::types::IcrcOperation::Mint{
                    to: self.to.context("Account field needs to be populated for Mint operation")?.try_into()?,
                    amount: self.amount.context("Amount field needs to be populated for Mint operation")?,
                    fee: self.fee,
                }},
                IcrcOperation::Burn => {
                    if self.to.is_some() {
                        bail!("To AccountIdentifier field is not allowed for Burn operation")
                    }
                    crate::common::storage::types::IcrcOperation::Burn{
                    from: self.from.context("From AccountIdentifier field needs to be populated for Burn operation")?.try_into()?,
                    amount: self.amount.context("Amount field needs to be populated for Burn operation")?,
                    spender: self.spender.map(|spender| spender.try_into()).transpose()?,
                    fee: self.fee,
                }},
                IcrcOperation::Transfer => crate::common::storage::types::IcrcOperation::Transfer{
                    from: self.from.context("From AccountIdentifier field needs to be populated for Transfer operation")?.try_into()?,
                    amount: self.amount.context("Amount field needs to be populated for Transfer operation")?,
                    spender: self.spender.map(|spender| spender.try_into()).transpose()?,
                    to: self.to.context("To AccountIdentifier field needs to be populated for Transfer operation")?.try_into()?,
                    fee: self.fee,
                },
                IcrcOperation::Approve => {
                    if self.to.is_some() {
                        bail!("To AccountIdentifier field is not allowed for Approve operation")
                    }
                    crate::common::storage::types::IcrcOperation::Approve{
                    from: self.from.context("From AccountIdentifier field needs to be populated for Approve operation")?.try_into()?,
                    amount: self.allowance.context("Allowance field needs to be populated for Approve operation")?,
                    spender: self.spender.context("To AccountIdentifier field needs to be populated for Approve operation")?.try_into()?,
                    fee: self.fee,
                    expected_allowance: self.expected_allowance,
                    expires_at: self.expires_at,
                }},
            })
        }
    }

    let mut icrc1_operation_builder = IcrcOperationBuilder::new();
    for operation in operation.into_iter() {
        icrc1_operation_builder = match operation.type_.parse::<OperationType>()? {
            OperationType::Mint => {
                let amount = operation
                    .amount
                    .context("Amount field needs to be populated for Mint operation")?;
                let to_account = operation.account.context(
                    "To AccountIdentifier field needs to be populated for Mint operation",
                )?;

                icrc1_operation_builder
                    .with_icrc_operation(IcrcOperation::Mint)
                    .with_to_accountidentifier(to_account)
                    .with_amount(Nat::try_from(amount)?)
            }

            OperationType::Burn => {
                let amount = operation
                    .amount
                    .context("Amount field needs to be populated for Burn operation")?;
                let from_account = operation.account.context(
                    "From AccountIdentifier field needs to be populated for Burn operation",
                )?;

                icrc1_operation_builder
                    .with_icrc_operation(IcrcOperation::Burn)
                    .with_from_accountidentifier(from_account)
                    .with_amount(Nat::try_from(amount)?)
            }

            OperationType::Transfer => {
                let amount = operation
                    .amount
                    .context("Amount field needs to be populated for icrc1 Operation")?;
                let account = operation
                    .account
                    .context("AccountIdentifier field needs to be populated for Burn operation")?;

                if amount.value.starts_with('-') {
                    icrc1_operation_builder.with_from_accountidentifier(account)
                } else {
                    icrc1_operation_builder.with_to_accountidentifier(account)
                }
                .with_icrc_operation(IcrcOperation::Transfer)
                .with_amount(Nat::try_from(amount)?)
            }

            OperationType::Approve => {
                let metadata = ApproveMetadata::try_from(operation.metadata)?;
                let from_account = operation.account.context(
                    "From AccountIdentifier field needs to be populated for Approve operation",
                )?;

                icrc1_operation_builder = icrc1_operation_builder
                    .with_icrc_operation(IcrcOperation::Approve)
                    .with_from_accountidentifier(from_account);

                icrc1_operation_builder =
                    if let Some(expected_allowance) = metadata.expected_allowance {
                        icrc1_operation_builder
                            .with_expected_allowance(Nat::try_from(expected_allowance)?)
                    } else {
                        icrc1_operation_builder
                    };

                icrc1_operation_builder = if let Some(expires_at) = metadata.expires_at {
                    icrc1_operation_builder.with_expires_at(expires_at)
                } else {
                    icrc1_operation_builder
                };
                icrc1_operation_builder.with_allowance(Nat::try_from(metadata.allowance)?)
            }
            OperationType::Fee => {
                let fee = operation
                    .amount
                    .context("Amount field needs to be populated for Approve operation")?;

                // The fee inside of icrc1 operation is always the fee set by the user
                let icrc1_operation_fee_set = match operation.metadata {
                    Some(metadata) => {
                        let fee_metadata = FeeMetadata::try_from(metadata)?;
                        match fee_metadata.fee_set_by {
                            FeeSetter::User => true,
                            FeeSetter::Ledger => false,
                        }
                    }
                    // If the metadata was not set the default behaviour is to set the fee in icrc1 operation
                    None => true,
                };

                if icrc1_operation_fee_set {
                    icrc1_operation_builder.with_fee(Nat::try_from(fee)?)
                } else {
                    icrc1_operation_builder
                }
            }
            OperationType::Spender => {
                let spender = operation.account.context(
                    "Spender AccountIdentifier field needs to be populated for Approve operation",
                )?;
                icrc1_operation_builder.with_spender_accountidentifier(spender)
            }
            // We do not have to convert this Operation on the icrc1 side as the crate::common::storage::types::IcrcOperation does not know anything about the FeeCollector
            OperationType::FeeCollector => icrc1_operation_builder,
        };
    }
    icrc1_operation_builder.build()
}

pub fn icrc1_operation_to_rosetta_core_operations(
    operation: IcrcOperation,
    currency: Currency,
    fee_payed: Option<Nat>,
) -> anyhow::Result<Vec<rosetta_core::objects::Operation>> {
    let mut operations = vec![];
    match operation {
        crate::common::storage::types::IcrcOperation::Mint { to, amount, fee } => {
            operations.push(rosetta_core::objects::Operation::new(
                0,
                OperationType::Mint.to_string(),
                Some(to.into()),
                Some(rosetta_core::objects::Amount::new(
                    BigInt::from(amount.0),
                    currency.clone(),
                )),
                None,
                None,
            ));

            if let Some(fee_paid) = fee_payed {
                operations.push(rosetta_core::objects::Operation::new(
                    1,
                    OperationType::Fee.to_string(),
                    Some(to.into()), // Mint fees are payed by the receiving account.
                    Some(Amount::new(
                        BigInt::from_biguint(num_bigint::Sign::Minus, fee_paid.0),
                        currency,
                    )),
                    None,
                    // If the fee inside the operation is set that means the User set the fee and the Ledger did nothing
                    Some(
                        FeeMetadata {
                            fee_set_by: match fee {
                                Some(_) => FeeSetter::User,
                                None => FeeSetter::Ledger,
                            },
                        }
                        .try_into()?,
                    ),
                ));
            }
        }

        crate::common::storage::types::IcrcOperation::Burn {
            from,
            spender,
            amount,
            fee,
        } => {
            operations.push(rosetta_core::objects::Operation::new(
                0,
                OperationType::Burn.to_string(),
                Some(from.into()),
                Some(rosetta_core::objects::Amount::new(
                    BigInt::from_biguint(num_bigint::Sign::Minus, amount.0),
                    currency.clone(),
                )),
                None,
                None,
            ));

            let mut idx = 1;

            if let Some(spender) = spender {
                operations.push(rosetta_core::objects::Operation::new(
                    idx,
                    OperationType::Spender.to_string(),
                    Some(spender.into()),
                    None,
                    None,
                    None,
                ));
                idx += 1;
            }

            if let Some(fee_paid) = fee_payed {
                operations.push(rosetta_core::objects::Operation::new(
                    idx,
                    OperationType::Fee.to_string(),
                    Some(from.into()),
                    Some(Amount::new(
                        BigInt::from_biguint(num_bigint::Sign::Minus, fee_paid.0),
                        currency,
                    )),
                    None,
                    // If the fee inside the operation is set that means the User set the fee and the Ledger did nothing
                    Some(
                        FeeMetadata {
                            fee_set_by: match fee {
                                Some(_) => FeeSetter::User,
                                None => FeeSetter::Ledger,
                            },
                        }
                        .try_into()?,
                    ),
                ));
            }
        }

        crate::common::storage::types::IcrcOperation::Transfer {
            from,
            to,
            spender,
            amount,
            fee,
        } => {
            operations.push(rosetta_core::objects::Operation::new(
                0,
                OperationType::Transfer.to_string(),
                Some(to.into()),
                Some(rosetta_core::objects::Amount::new(
                    BigInt::from(amount.0.clone()),
                    currency.clone(),
                )),
                None,
                None,
            ));

            operations.push(rosetta_core::objects::Operation::new(
                1,
                OperationType::Transfer.to_string(),
                Some(from.into()),
                Some(rosetta_core::objects::Amount::new(
                    BigInt::from_biguint(num_bigint::Sign::Minus, amount.0),
                    currency.clone(),
                )),
                None,
                None,
            ));

            let mut idx = 2;

            if let Some(spender) = spender {
                operations.push(rosetta_core::objects::Operation::new(
                    idx,
                    OperationType::Spender.to_string(),
                    Some(spender.into()),
                    None,
                    None,
                    None,
                ));
                idx += 1;
            }

            if let Some(fee_paid) = fee_payed {
                operations.push(rosetta_core::objects::Operation::new(
                    idx,
                    OperationType::Fee.to_string(),
                    Some(from.into()),
                    Some(Amount::new(
                        BigInt::from_biguint(num_bigint::Sign::Minus, fee_paid.0),
                        currency,
                    )),
                    None,
                    // If the fee inside the operation is set that means the User set the fee and the Ledger did nothing
                    Some(
                        FeeMetadata {
                            fee_set_by: match fee {
                                Some(_) => FeeSetter::User,
                                None => FeeSetter::Ledger,
                            },
                        }
                        .try_into()?,
                    ),
                ));
            }
        }

        crate::common::storage::types::IcrcOperation::Approve {
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
        } => {
            operations.push(rosetta_core::objects::Operation::new(
                0,
                OperationType::Approve.to_string(),
                Some(from.into()),
                None,
                None,
                Some(
                    ApproveMetadata {
                        allowance: Amount::new(BigInt::from(amount.0), currency.clone()),
                        expected_allowance: expected_allowance.map(|expected_allowance| {
                            Amount::new(BigInt::from(expected_allowance.0), currency.clone())
                        }),
                        expires_at,
                    }
                    .try_into()?,
                ),
            ));

            operations.push(rosetta_core::objects::Operation::new(
                1,
                OperationType::Spender.to_string(),
                Some(spender.into()),
                None,
                None,
                None,
            ));

            if let Some(fee_paid) = fee_payed {
                operations.push(rosetta_core::objects::Operation::new(
                    2,
                    OperationType::Fee.to_string(),
                    Some(from.into()),
                    Some(Amount::new(
                        BigInt::from_biguint(num_bigint::Sign::Minus, fee_paid.0),
                        currency,
                    )),
                    None,
                    // If the fee inside the operation is set that means the User set the fee and the Ledger did nothing
                    Some(
                        FeeMetadata {
                            fee_set_by: match fee {
                                Some(_) => FeeSetter::User,
                                None => FeeSetter::Ledger,
                            },
                        }
                        .try_into()?,
                    ),
                ));
            }
        }
        crate::common::storage::types::IcrcOperation::FeeCollector { .. } => {
            // There is no fee crediting operation at his moment so we might not need to do anything here
            // Below in icrc1_rosetta_block_to_rosetta_core_operations we create an operation that credits
            // the fee to the legacy fee collector. This needs to be adapted to not do anything if the
            // new fee collector is present.
        }
    };

    Ok(operations)
}

// Takes in a rosetta_core operation that fully defines an icrc1 Operation
// Fails if the given operation is unable to form an icrc1 Operation

pub fn icrc1_rosetta_block_to_rosetta_core_operations(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<Vec<rosetta_core::objects::Operation>> {
    let icrc1_transaction = rosetta_block.get_transaction();

    let mut operations = icrc1_operation_to_rosetta_core_operations(
        icrc1_transaction.operation,
        currency.clone(),
        rosetta_block.get_fee_paid()?,
    )?;

    if let Some(fee_collector) = rosetta_block.get_fee_collector()
        && let Some(_fee_payed) = rosetta_block.get_fee_paid()?
    {
        operations.push(rosetta_core::objects::Operation::new(
            operations.len().try_into().unwrap(),
            OperationType::FeeCollector.to_string(),
            Some(fee_collector.into()),
            Some(rosetta_core::objects::Amount::new(
                BigInt::from(
                    rosetta_block
                        .get_fee_paid()?
                        .context("Fee payed needs to be populated for FeeCollector operation")?
                        .0,
                ),
                currency.clone(),
            )),
            None,
            None,
        ));
    }
    Ok(operations)
}

// Converts a RosettaBlock into a Block from the rosetta_core crate
pub fn icrc1_rosetta_block_to_rosetta_core_block(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<rosetta_core::objects::Block> {
    Ok(rosetta_core::objects::Block {
        metadata: Some(
            BlockMetadata::new(rosetta_block.get_icrc1_block(), currency.clone())?.try_into()?,
        ),
        block_identifier: rosetta_block.clone().get_block_identifier(),
        parent_block_identifier: rosetta_block.get_parent_block_identifier(),
        timestamp: convert_timestamp_to_millis(rosetta_block.get_timestamp())?,
        transactions: vec![icrc1_rosetta_block_to_rosetta_core_transaction(
            rosetta_block,
            currency,
        )?],
    })
}

// Converts a rosetta_core Block into an ICRC-1 Block
pub fn rosetta_core_block_to_icrc1_block(
    mut block: rosetta_core::objects::Block,
) -> anyhow::Result<crate::common::storage::types::IcrcBlock> {
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

    Ok(crate::common::storage::types::IcrcBlock {
        effective_fee: block_metadata
            .effective_fee
            .map(Nat::try_from)
            .transpose()?,
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
            Some(
                ByteBuf::try_from(block.parent_block_identifier)?
                    .as_slice()
                    .try_into()?,
            )
        },
        fee_collector_block_index: block_metadata.fee_collector_block_index,
        btype: None, // TODO: implement panic!("FeeCollector107 not implemented")
    })
}

// Converts a RosettaBlock into a Transaction from the rosetta_core crate
pub fn icrc1_rosetta_block_to_rosetta_core_transaction(
    rosetta_block: RosettaBlock,
    currency: Currency,
) -> anyhow::Result<rosetta_core::objects::Transaction> {
    let icrc1_transaction = rosetta_block.get_transaction();
    let metadata: TransactionMetadata = icrc1_transaction.into();

    Ok(rosetta_core::objects::Transaction {
        transaction_identifier: rosetta_block.clone().get_transaction_identifier(),
        operations: icrc1_rosetta_block_to_rosetta_core_operations(rosetta_block, currency)?,
        metadata: (!metadata.is_empty())
            .then(|| metadata.try_into())
            .transpose()?,
    })
}

// Converts a rosetta_core Transaction into an ICRC-1 Transaction
pub fn rosetta_core_transaction_to_icrc1_transaction(
    transaction: rosetta_core::objects::Transaction,
) -> anyhow::Result<crate::common::storage::types::IcrcTransaction> {
    let metadata = TransactionMetadata::try_from(transaction.metadata)?;

    Ok(crate::common::storage::types::IcrcTransaction {
        operation: rosetta_core_operations_to_icrc1_operation(transaction.operations)?,
        created_at_time: metadata.created_at_time,
        memo: metadata.memo.map(|memo| memo.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_icrc1_test_utils::account_strategy;
    use ic_icrc1_test_utils::arb_amount;
    use ic_icrc1_test_utils::blocks_strategy;
    use ic_icrc1_tokens_u64::U64;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_core::{block::BlockType, tokens::TokensType};
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;
    use rosetta_core::identifiers::AccountIdentifier;

    const NUM_TEST_CASES: u32 = 100;

    fn test_block_conversion<T: TokensType>(block: ic_icrc1::Block<T>) {
        let currency = Currency::default();
        let rosetta_block = RosettaBlock::from_encoded_block(&block.encode(), 0).unwrap();
        let rosetta_core_block =
            icrc1_rosetta_block_to_rosetta_core_block(rosetta_block.clone(), currency).unwrap();
        let derived_block = rosetta_core_block_to_icrc1_block(rosetta_core_block).unwrap();
        assert_eq!(rosetta_block.get_icrc1_block(), derived_block);
    }

    proptest! {
            #![proptest_config(ProptestConfig {
                cases: NUM_TEST_CASES,
                max_shrink_iters: 0,
                ..ProptestConfig::default()
            })]

            #[test]
            fn test_account_conversions(account in account_strategy()){
                let accountidentifier:AccountIdentifier = account.into();
                let derived_account:icrc_ledger_types::icrc1::account::Account  = accountidentifier.try_into().unwrap();
                assert_eq!(derived_account,account);
            }

            #[test]
            fn test_block_conversions_u64(block in blocks_strategy::<U64>(arb_amount())){
                test_block_conversion::<U64>(block)
            }

            #[test]
            fn test_block_conversions_u256(block in blocks_strategy::<U256>(arb_amount())){
                test_block_conversion::<U256>(block)
            }
    }
}
