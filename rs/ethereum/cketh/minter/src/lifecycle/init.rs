use crate::endpoints::CandidBlockTag;
use crate::eth_rpc::BlockTag;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, TransactionNonce, Wei};
use crate::state::transactions::EthTransactions;
use crate::state::{InvalidStateError, State};
use candid::types::number::Nat;
use candid::types::principal::Principal;
use candid::{CandidType, Deserialize};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};

#[derive(CandidType, Deserialize, Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct InitArg {
    #[n(0)]
    pub ethereum_network: EthereumNetwork,
    #[n(1)]
    pub ecdsa_key_name: String,
    #[n(2)]
    pub ethereum_contract_address: Option<String>,
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub ledger_id: Principal,
    #[n(4)]
    pub ethereum_block_height: CandidBlockTag,
    #[cbor(n(6), with = "crate::cbor::nat")]
    pub minimum_withdrawal_amount: Nat,
    #[cbor(n(7), with = "crate::cbor::nat")]
    pub next_transaction_nonce: Nat,
    #[cbor(n(8), with = "crate::cbor::nat")]
    pub last_scraped_block_number: Nat,
}

impl TryFrom<InitArg> for State {
    type Error = InvalidStateError;
    fn try_from(
        InitArg {
            ethereum_network,
            ecdsa_key_name,
            ethereum_contract_address,
            ledger_id,
            ethereum_block_height,
            minimum_withdrawal_amount,
            next_transaction_nonce,
            last_scraped_block_number,
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {}", e)))?;
        let minimum_withdrawal_amount = Wei::try_from(minimum_withdrawal_amount).map_err(|e| {
            InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {}", e))
        })?;
        let eth_helper_contract_address = ethereum_contract_address
            .map(|a| Address::from_str(&a))
            .transpose()
            .map_err(|e| {
                InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {}", e))
            })?;
        let last_scraped_block_number =
            BlockNumber::try_from(last_scraped_block_number).map_err(|e| {
                InvalidStateError::InvalidLastScrapedBlockNumber(format!("ERROR: {}", e))
            })?;
        let first_scraped_block_number =
            last_scraped_block_number
                .checked_increment()
                .ok_or_else(|| {
                    InvalidStateError::InvalidLastScrapedBlockNumber(
                        "ERROR: last_scraped_block_number is at maximum value".to_string(),
                    )
                })?;
        let state = Self {
            ethereum_network,
            ecdsa_key_name,
            eth_helper_contract_address,
            erc20_helper_contract_address: None,
            pending_withdrawal_principals: Default::default(),
            eth_transactions: EthTransactions::new(initial_nonce),
            cketh_ledger_id: ledger_id,
            cketh_minimum_withdrawal_amount: minimum_withdrawal_amount,
            ethereum_block_height: BlockTag::from(ethereum_block_height),
            first_scraped_block_number,
            last_scraped_block_number,
            last_erc20_scraped_block_number: last_scraped_block_number,
            last_observed_block_number: None,
            events_to_mint: Default::default(),
            minted_events: Default::default(),
            ecdsa_public_key: None,
            invalid_events: Default::default(),
            eth_balance: Default::default(),
            skipped_blocks: Default::default(),
            active_tasks: Default::default(),
            http_request_counter: 0,
            last_transaction_price_estimate: None,
            ledger_suite_orchestrator_id: None,
            evm_rpc_id: None,
            ckerc20_tokens: Default::default(),
            erc20_balances: Default::default(),
        };
        state.validate_config()?;
        Ok(state)
    }
}
