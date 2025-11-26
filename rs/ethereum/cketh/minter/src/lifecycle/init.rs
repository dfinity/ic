use crate::endpoints::CandidBlockTag;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, TransactionNonce, Wei};
use crate::state::eth_logs_scraping::{LogScrapingId, LogScrapings};
use crate::state::transactions::EthTransactions;
use crate::state::{InvalidStateError, State};
use crate::{EVM_RPC_ID_PRODUCTION, EVM_RPC_ID_STAGING};
use candid::types::number::Nat;
use candid::types::principal::Principal;
use candid::{CandidType, Deserialize};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Decode, Deserialize, Encode)]
pub struct InitArg {
    #[n(0)]
    pub ethereum_network: EthereumNetwork,
    #[n(1)]
    pub ecdsa_key_name: String,
    #[n(2)]
    pub ethereum_contract_address: Option<String>,
    #[cbor(n(3), with = "icrc_cbor::principal")]
    pub ledger_id: Principal,
    #[n(4)]
    pub ethereum_block_height: CandidBlockTag,
    #[cbor(n(6), with = "icrc_cbor::nat")]
    pub minimum_withdrawal_amount: Nat,
    #[cbor(n(7), with = "icrc_cbor::nat")]
    pub next_transaction_nonce: Nat,
    #[cbor(n(8), with = "icrc_cbor::nat")]
    pub last_scraped_block_number: Nat,
    #[cbor(n(9), with = "icrc_cbor::principal::option")]
    pub evm_rpc_id: Option<Principal>,
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
            evm_rpc_id,
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {e}")))?;
        let minimum_withdrawal_amount = Wei::try_from(minimum_withdrawal_amount).map_err(|e| {
            InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {e}"))
        })?;
        let eth_helper_contract_address = ethereum_contract_address
            .map(|a| Address::from_str(&a))
            .transpose()
            .map_err(|e| {
                InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {e}"))
            })?;
        let last_scraped_block_number = BlockNumber::try_from(last_scraped_block_number)
            .map_err(|e| InvalidStateError::InvalidLastScrapedBlockNumber(format!("ERROR: {e}")))?;
        let first_scraped_block_number =
            last_scraped_block_number
                .checked_increment()
                .ok_or_else(|| {
                    InvalidStateError::InvalidLastScrapedBlockNumber(
                        "ERROR: last_scraped_block_number is at maximum value".to_string(),
                    )
                })?;
        let evm_rpc_id = evm_rpc_id.unwrap_or(match ethereum_network {
            EthereumNetwork::Mainnet => EVM_RPC_ID_PRODUCTION,
            EthereumNetwork::Sepolia => EVM_RPC_ID_STAGING,
        });
        let mut log_scrapings = LogScrapings::new(last_scraped_block_number);
        if let Some(contract_address) = eth_helper_contract_address {
            log_scrapings
                .set_contract_address(LogScrapingId::EthDepositWithoutSubaccount, contract_address)
                .map_err(|e| {
                    InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {e:?}"))
                })?;
        }
        let state = Self {
            ethereum_network,
            ecdsa_key_name,
            pending_withdrawal_principals: Default::default(),
            eth_transactions: EthTransactions::new(initial_nonce),
            cketh_ledger_id: ledger_id,
            cketh_minimum_withdrawal_amount: minimum_withdrawal_amount,
            ethereum_block_height,
            first_scraped_block_number,
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
            evm_rpc_id,
            ckerc20_tokens: Default::default(),
            erc20_balances: Default::default(),
            log_scrapings,
        };
        state.validate_config()?;
        Ok(state)
    }
}
