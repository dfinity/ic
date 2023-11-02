use std::time::Duration;

use anyhow::Context;
use axum::{http::StatusCode, response::IntoResponse, Json};
use candid::Deserialize;

use ic_base_types::CanisterId;
use ic_icrc1_tokens_u64::U64;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use serde::Serialize;
use serde_json::Number;

use super::storage::types::RosettaBlock;

// Generated from the [Rosetta API specification v1.4.13](https://github.com/coinbase/rosetta-specifications/blob/v1.4.13/api.json)
// Documentation for the Rosetta API can be found at https://www.rosetta-api.org/docs/1.4.13/welcome.html

const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

pub type Object = serde_json::map::Map<String, serde_json::Value>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkListResponse {
    pub network_identifiers: Vec<NetworkIdentifier>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkIdentifier {
    pub blockchain: String,

    pub network: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_network_identifier: Option<SubNetworkIdentifier>,
}

impl NetworkIdentifier {
    pub fn for_ledger_id(ledger_id: CanisterId) -> Self {
        let network = hex::encode(ledger_id.get().into_vec());
        NetworkIdentifier {
            blockchain: DEFAULT_BLOCKCHAIN.to_string(),
            network,
            sub_network_identifier: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubNetworkIdentifier {
    pub network: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkOptionsResponse {
    pub version: Version,

    pub allow: Allow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Version {
    pub rosetta_version: String,

    pub node_version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub middleware_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Allow {
    pub operation_statuses: Vec<OperationStatus>,

    pub operation_types: Vec<String>,

    pub errors: Vec<Error>,

    pub historical_balance_lookup: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_start_index: Option<i64>,

    pub call_methods: Vec<String>,

    pub balance_exemptions: Vec<BalanceExemption>,

    pub mempool_coins: bool,

    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_hash_case: Option<Option<Case>>,

    #[serde(
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_hash_case: Option<Option<Case>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BalanceExemption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Box<Currency>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exemption_type: Option<ExemptionType>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Currency {
    pub symbol: String,

    pub decimals: u8,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ExemptionType {
    GreaterOrEqual,
    LessOrEqual,
    Dynamic,
}

impl Default for ExemptionType {
    fn default() -> ExemptionType {
        Self::GreaterOrEqual
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Case {
    UpperCase,
    LowerCase,
    CaseSensitive,
    Null,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationStatus {
    pub status: String,

    pub successful: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Error {
    pub code: u32,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub retriable: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

const ERROR_CODE_INVALID_NETWORK_ID: u32 = 1;
const ERROR_CODE_UNABLE_TO_FIND_BLOCK: u32 = 2;
const ERROR_CODE_INVALID_BLOCK_IDENTIFIER: u32 = 3;
const ERROR_CODE_FAILED_TO_BUILD_BLOCK_RESPONSE: u32 = 4;

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

impl Error {
    pub fn invalid_network_id(expected: &NetworkIdentifier) -> Self {
        Self {
            code: ERROR_CODE_INVALID_NETWORK_ID,
            message: "Invalid network identifier".into(),
            description: Some(format!(
                "Invalid network identifier. Expected {}",
                serde_json::to_string(expected).unwrap()
            )),
            retriable: false,
            details: None,
        }
    }

    pub fn unable_to_find_block(description: String) -> Self {
        Self {
            code: ERROR_CODE_UNABLE_TO_FIND_BLOCK,
            message: "Unable to find block".into(),
            description: Some(description),
            retriable: false,
            details: None,
        }
    }

    pub fn invalid_block_identifier() -> Self {
        Self {
            code: ERROR_CODE_INVALID_BLOCK_IDENTIFIER,
            message: "Invalid block identifier provided".into(),
            description: Some(
                "Invalid block identifier provided. Must provide either an index or hash.".into(),
            ),
            retriable: false,
            details: None,
        }
    }

    pub fn failed_to_build_block_response(description: String) -> Self {
        Self {
            code: ERROR_CODE_FAILED_TO_BUILD_BLOCK_RESPONSE,
            message: "Failed to build block response".into(),
            description: Some(description),
            retriable: false,
            details: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkRequest {
    pub network_identifier: NetworkIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockIdentifier {
    pub index: u64,
    pub hash: String,
}

impl From<&RosettaBlock> for BlockIdentifier {
    fn from(block: &RosettaBlock) -> Self {
        Self {
            index: block.index,
            hash: hex::encode(&block.block_hash),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced: Option<bool>,
}

/// NetworkStatusResponse contains basic information about the node's view of a
/// blockchain network.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkStatusResponse {
    pub current_block_identifier: BlockIdentifier,
    /// The timestamp of the block in milliseconds since the Unix Epoch.
    pub current_block_timestamp: u64,
    pub genesis_block_identifier: BlockIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_block_identifier: Option<BlockIdentifier>,
    // TODO: sync status should be displayed as it is helpful, but work
    // needs to be done in order to share syncing status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<SyncStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartialBlockIdentifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Block {
    pub block_identifier: BlockIdentifier,
    pub parent_block_identifier: BlockIdentifier,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Transaction {
    pub transaction_identifier: TransactionIdentifier,
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

impl Transaction {
    pub fn builder() -> TransactionBuilder {
        TransactionBuilder::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionIdentifier {
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Operation {
    pub operation_identifier: OperationIdentifier,
    pub account: AccountIdentifier,
    pub r#type: OperationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Object>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationIdentifier {
    pub index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Amount {
    pub amount: String,
    pub currency: Currency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationType {
    Mint,
    Burn,
    Transfer,
    Approve,
    Fee,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountIdentifier {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_account: Option<SubAccountIdentifier>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubAccountIdentifier {
    pub address: String,
}

impl From<&icrc_ledger_types::icrc1::account::Account> for AccountIdentifier {
    fn from(account: &icrc_ledger_types::icrc1::account::Account) -> Self {
        Self {
            address: account.owner.to_string(),
            sub_account: account.subaccount.map(|s| SubAccountIdentifier {
                address: hex::encode(s),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApproveMetadata {
    pub from: AccountIdentifier,
    pub spender: AccountIdentifier,
    pub allowance: U64,
    pub expected_allowance: Option<U64>,
    pub expires_at: Option<u64>,
}

impl From<ApproveMetadata> for Object {
    fn from(m: ApproveMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

#[derive(Default)]
pub struct TransactionBuilder {
    currency: Option<Currency>,
    transaction: Option<ic_icrc1::Transaction<U64>>,
    effective_fee: Option<U64>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_currency(mut self, currency: Currency) -> Self {
        self.currency = Some(currency);
        self
    }

    pub fn with_transaction(mut self, transaction: ic_icrc1::Transaction<U64>) -> Self {
        self.transaction = Some(transaction);
        self
    }

    pub fn with_effective_fee(mut self, effective_fee: U64) -> Self {
        self.effective_fee = Some(effective_fee);
        self
    }

    pub fn build(self) -> anyhow::Result<Transaction> {
        let transaction = self
            .transaction
            .clone()
            .context("A Transaction<U64> is required to build a transaction.")?;
        let currency = self
            .currency
            .clone()
            .context("A currency is required to build a transaction.")?;

        let transaction_identifier = TransactionIdentifier {
            hash: transaction.hash().to_string(),
        };

        let mut operations = vec![];
        let mut push_operation = |r#type: OperationType,
                                  account: AccountIdentifier,
                                  amount: Option<String>,
                                  metadata: Option<Object>| {
            operations.push(Operation {
                operation_identifier: OperationIdentifier {
                    index: operations.len() as u64,
                },
                account,
                r#type,
                amount: amount.map(|amount| Amount {
                    amount,
                    currency: currency.clone(),
                }),
                metadata,
            });
        };

        match transaction.operation {
            ic_icrc1::Operation::Mint { to, amount } => {
                push_operation(
                    OperationType::Mint,
                    AccountIdentifier::from(&to),
                    Some(format!("{}", amount)),
                    None,
                );
            }
            ic_icrc1::Operation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => {
                push_operation(
                    OperationType::Transfer,
                    AccountIdentifier::from(&from),
                    Some(format!("-{}", amount)),
                    None,
                );
                push_operation(
                    OperationType::Transfer,
                    AccountIdentifier::from(&to),
                    Some(format!("{}", amount)),
                    None,
                );

                let fee = self
                    .effective_fee
                    .or(fee)
                    .context("Unable to determine fee")?;
                push_operation(
                    OperationType::Fee,
                    AccountIdentifier::from(&from),
                    Some(format!("-{}", fee)),
                    None,
                );
            }
            ic_icrc1::Operation::Burn { from, amount, .. } => {
                push_operation(
                    OperationType::Burn,
                    AccountIdentifier::from(&from),
                    Some(format!("-{}", amount)),
                    None,
                );
            }
            ic_icrc1::Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                push_operation(
                    OperationType::Approve,
                    AccountIdentifier::from(&from),
                    None,
                    Some(
                        ApproveMetadata {
                            from: AccountIdentifier::from(&from),
                            spender: AccountIdentifier::from(&spender),
                            allowance: amount,
                            expected_allowance,
                            expires_at,
                        }
                        .into(),
                    ),
                );

                let fee = self
                    .effective_fee
                    .or(fee)
                    .context("Unable to determine fee")?;
                push_operation(
                    OperationType::Fee,
                    AccountIdentifier::from(&from),
                    Some(format!("-{}", fee)),
                    None,
                );
            }
        };

        let mut metadata = Object::new();
        if let Some(created_at_time) = transaction.created_at_time() {
            metadata.insert(
                "created_at_time".to_string(),
                serde_json::Value::Number(Number::from(
                    created_at_time.as_nanos_since_unix_epoch(),
                )),
            );
        }

        if let Some(memo) = transaction.memo {
            metadata.insert(
                "memo".to_string(),
                serde_json::Value::Array(
                    memo.0
                        .iter()
                        .map(|byte| serde_json::Value::Number(Number::from(*byte)))
                        .collect(),
                ),
            );
        }

        Ok(Transaction {
            transaction_identifier,
            operations,
            metadata: if !metadata.is_empty() {
                Some(metadata)
            } else {
                None
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockRequest {
    pub block_identifier: PartialBlockIdentifier,
    pub network_identifier: NetworkIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockResponse {
    pub block: Block,
}

impl BlockResponse {
    pub fn builder() -> BlockResponseBuilder {
        BlockResponseBuilder::new()
    }
}

pub struct BlockResponseBuilder {
    block: Option<RosettaBlock>,
    currency: Option<Currency>,
}

impl BlockResponseBuilder {
    fn new() -> Self {
        Self {
            block: None,
            currency: None,
        }
    }

    pub fn with_rosetta_block(mut self, block: RosettaBlock) -> Self {
        self.block = Some(block);
        self
    }

    pub fn with_currency(mut self, currency: Currency) -> Self {
        self.currency = Some(currency);
        self
    }

    pub fn build(self) -> anyhow::Result<BlockResponse> {
        let block = self
            .block
            .clone()
            .context("A RosettaBlock is required to build a response.")?;
        let timestamp = convert_timestamp_to_millis(block.timestamp)
            .context("Failed to convert block's timestamp to milliseconds")?;
        let currency = self
            .currency
            .clone()
            .context("A currency is required to build a response.")?;

        let block_identifier = BlockIdentifier::from(&block);

        let parent_hash = block
            .parent_hash
            .as_ref()
            .map(|hash| hex::encode(hash))
            .unwrap_or_else(|| block_identifier.hash.clone());
        let parent_block_identifier = BlockIdentifier {
            index: block.index.saturating_sub(1),
            hash: parent_hash,
        };

        let icrc1_transaction = block.get_transaction()?;

        let mut tx_builder = Transaction::builder()
            .with_currency(currency)
            .with_transaction(icrc1_transaction);
        if let Some(effective_fee) = block.get_effective_fee()? {
            tx_builder = tx_builder.with_effective_fee(effective_fee);
        }

        let transaction = tx_builder.build()?;

        Ok(BlockResponse {
            block: Block {
                block_identifier,
                parent_block_identifier,
                timestamp,
                transactions: vec![transaction],
            },
        })
    }
}

fn convert_timestamp_to_millis(timestamp_nanos: u64) -> anyhow::Result<u64> {
    let millis = Duration::from_nanos(timestamp_nanos).as_millis();
    u64::try_from(millis).context("Failed to convert timestamp to milliseconds")
}

#[cfg(test)]
mod test {

    use super::*;
    use ic_icrc1_test_utils::{
        arb_small_amount, blocks_strategy, decimals_strategy, symbol_strategy, transaction_strategy,
    };
    use ic_ledger_core::block::BlockType;
    use proptest::prelude::*;

    fn currency_strategy() -> impl Strategy<Value = Currency> {
        (decimals_strategy(), symbol_strategy()).prop_map(|(decimals, symbol)| Currency {
            symbol,
            decimals,
            metadata: None,
        })
    }

    fn build_expected_transaction(
        transaction: ic_icrc1::Transaction<U64>,
        currency: Currency,
        effective_fee: Option<U64>,
    ) -> Transaction {
        let operations = match transaction.operation {
            ic_icrc1::Operation::Mint { to, amount } => vec![Operation {
                operation_identifier: OperationIdentifier { index: 0 },
                account: AccountIdentifier {
                    address: to.owner.to_string(),
                    sub_account: to.subaccount.map(|s| SubAccountIdentifier {
                        address: hex::encode(s),
                    }),
                },
                amount: Some(Amount {
                    amount: amount.to_string(),
                    currency: currency.clone(),
                }),
                r#type: OperationType::Mint,
                metadata: None,
            }],
            ic_icrc1::Operation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => {
                let from = AccountIdentifier {
                    address: from.owner.to_string(),
                    sub_account: from.subaccount.map(|s| SubAccountIdentifier {
                        address: hex::encode(s),
                    }),
                };
                let fee = effective_fee
                    .or(fee)
                    .expect("There should be a fee or an effective fee!");
                vec![
                    Operation {
                        operation_identifier: OperationIdentifier { index: 0 },
                        account: from.clone(),
                        amount: Some(Amount {
                            amount: format!("-{}", amount),
                            currency: currency.clone(),
                        }),
                        r#type: OperationType::Transfer,
                        metadata: None,
                    },
                    Operation {
                        operation_identifier: OperationIdentifier { index: 1 },
                        account: AccountIdentifier {
                            address: to.owner.to_string(),
                            sub_account: to.subaccount.map(|s| SubAccountIdentifier {
                                address: hex::encode(s),
                            }),
                        },
                        amount: Some(Amount {
                            amount: amount.to_string(),
                            currency: currency.clone(),
                        }),
                        r#type: OperationType::Transfer,
                        metadata: None,
                    },
                    Operation {
                        operation_identifier: OperationIdentifier { index: 2 },
                        account: from,
                        amount: Some(Amount {
                            amount: format!("-{}", fee),
                            currency: currency.clone(),
                        }),
                        r#type: OperationType::Fee,
                        metadata: None,
                    },
                ]
            }
            ic_icrc1::Operation::Burn { from, amount, .. } => vec![Operation {
                operation_identifier: OperationIdentifier { index: 0 },
                account: AccountIdentifier {
                    address: from.owner.to_string(),
                    sub_account: from.subaccount.map(|s| SubAccountIdentifier {
                        address: hex::encode(s),
                    }),
                },
                amount: Some(Amount {
                    amount: format!("-{}", amount),
                    currency: currency.clone(),
                }),
                r#type: OperationType::Burn,
                metadata: None,
            }],
            ic_icrc1::Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                let account = AccountIdentifier {
                    address: from.owner.to_string(),
                    sub_account: from.subaccount.map(|s| SubAccountIdentifier {
                        address: hex::encode(s),
                    }),
                };
                let fee = effective_fee
                    .or(fee)
                    .expect("There should be a fee or an effective fee!");
                vec![
                    Operation {
                        operation_identifier: OperationIdentifier { index: 0 },
                        account: account.clone(),
                        amount: None,
                        r#type: OperationType::Approve,
                        metadata: Some(
                            ApproveMetadata {
                                from: account.clone(),
                                spender: AccountIdentifier {
                                    address: spender.owner.to_string(),
                                    sub_account: spender.subaccount.map(|s| SubAccountIdentifier {
                                        address: hex::encode(s),
                                    }),
                                },
                                allowance: amount,
                                expected_allowance,
                                expires_at,
                            }
                            .into(),
                        ),
                    },
                    Operation {
                        operation_identifier: OperationIdentifier { index: 1 },
                        account,
                        amount: Some(Amount {
                            amount: format!("-{}", fee),
                            currency: currency.clone(),
                        }),
                        r#type: OperationType::Fee,
                        metadata: None,
                    },
                ]
            }
        };

        let mut metadata = Object::new();
        if let Some(memo) = &transaction.memo {
            let value = serde_json::Value::Array(
                memo.0
                    .iter()
                    .map(|i| serde_json::Value::Number(Number::from(*i)))
                    .collect(),
            );
            metadata.insert("memo".to_string(), value);
        }

        if let Some(timestamp) = &transaction.created_at_time {
            metadata.insert(
                "created_at_time".to_string(),
                serde_json::Value::Number(Number::from(*timestamp)),
            );
        }

        Transaction {
            transaction_identifier: TransactionIdentifier {
                hash: transaction.hash().to_string(),
            },
            operations,
            metadata: if !metadata.is_empty() {
                Some(metadata)
            } else {
                None
            },
        }
    }

    proptest! {

        #[test]
        fn test_transaction_builder(
            transaction in prop::option::of(transaction_strategy(arb_small_amount())),
            currency in prop::option::of(currency_strategy()),
            effective_fee in prop::option::of(arb_small_amount()),
        ) {

            let mut builder = Transaction::builder();
            if let Some(transaction) = &transaction {
                builder = builder.with_transaction(transaction.clone());
            }

            if let Some(currency) = &currency {
                builder = builder.with_currency(currency.clone());
            }

            if let Some(effective_fee) = effective_fee {
                builder = builder.with_effective_fee(effective_fee);
            }

            match builder.build() {
                // Unwraps are safe as a transaction and currency are required to build successfully.
                Ok(built_transaction) => {
                    let expected_transaction = build_expected_transaction(
                        transaction.unwrap(),
                        currency.unwrap(),
                        effective_fee,
                    );
                    assert_eq!(expected_transaction, built_transaction);
                },
                Err(error) => {
                    let expected_error = if transaction.is_none() {
                        "A Transaction<U64> is required to build a transaction."
                    } else if currency.is_none() {
                        "A currency is required to build a transaction."
                    } else {
                        // If the other fields are set, (currently) the only error that could
                        // occur would be the inability to determine the fee.
                        "Unable to determine fee"
                    };

                    assert_eq!(error.to_string(), expected_error);
                }
            };

        }

        #[test]
        fn test_block_response_builder(
            block in prop::option::of(blocks_strategy(arb_small_amount())),
            currency in prop::option::of(currency_strategy()),
            block_idx in 0..100_000u64
        ) {
            let mut builder = BlockResponse::builder();
            if let Some(block) = &block {
                let rosetta_block = RosettaBlock::from_icrc_ledger_block(block.clone(), block_idx).expect("Failed to make rosetta block");
                builder = builder.with_rosetta_block(rosetta_block);
            }

            if let Some(currency) = &currency {
                builder = builder.with_currency(currency.clone());
            }

            match builder.build() {
                Ok(built_block_response) => {
                    // Safe to unwrap here as building was successful.
                    let block = block.unwrap();
                    let currency = currency.unwrap();

                    let expected_response = BlockResponse {
                        block: Block {
                            block_identifier: BlockIdentifier { index: block_idx, hash: ic_icrc1::Block::<U64>::block_hash(&block.clone().encode()).to_string()  },
                            parent_block_identifier: block.parent_hash.map(|h| BlockIdentifier {
                                hash: h.to_string(),
                                index: block_idx.saturating_sub(1)
                            }).unwrap_or_else(|| {
                                built_block_response.block.block_identifier.clone()
                            }),
                            timestamp: convert_timestamp_to_millis(block.timestamp).unwrap(),
                            transactions: vec![build_expected_transaction(block.transaction, currency, block.effective_fee)]
                        }
                    };

                    assert_eq!(built_block_response, expected_response);
                },
                Err(error) => {
                    let expected_error = match block {
                        Some(block) => {
                            if convert_timestamp_to_millis(block.timestamp).is_err() {
                                "Failed to convert block's timestamp to milliseconds"
                            } else if currency.is_none() {
                                "A currency is required to build a response."
                            } else {
                                // If the other fields are set, (currently) the only error that could
                                // occur would be the inability to determine the fee.
                                "Unable to determine fee"
                            }
                        },
                        None => "A RosettaBlock is required to build a response.",
                    };

                    assert_eq!(error.to_string(), expected_error);
                },
            };
        }

    }
}
