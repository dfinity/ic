use crate::address::Address;
use crate::eth_rpc::BlockNumber;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{TransactionNonce, Wei};
use crate::state::{InvalidStateError, State};
use crate::transactions::EthTransactions;
use candid::types::number::Nat;
use candid::types::principal::Principal;
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArg {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub ethereum_contract_address: Option<String>,
    pub ledger_id: Principal,
    pub minimum_withdrawal_amount: Nat,
    pub next_transaction_nonce: Nat,
}

impl TryFrom<InitArg> for State {
    type Error = InvalidStateError;
    fn try_from(
        InitArg {
            ethereum_network,
            ecdsa_key_name,
            ethereum_contract_address,
            ledger_id,
            minimum_withdrawal_amount,
            next_transaction_nonce,
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {:?}", e)))?;
        let minimum_withdrawal_amount = Wei::try_from(minimum_withdrawal_amount).map_err(|e| {
            InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {:?}", e))
        })?;
        let ethereum_contract_address = ethereum_contract_address
            .map(|a| Address::from_str(&a))
            .transpose()
            .map_err(|e| {
                InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {:?}", e))
            })?;
        let state = Self {
            ethereum_network,
            ecdsa_key_name,
            ethereum_contract_address,
            next_transaction_nonce: initial_nonce,
            retrieve_eth_principals: Default::default(),
            eth_transactions: EthTransactions::new(initial_nonce),
            ledger_id,
            minimum_withdrawal_amount,
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_scraped_block_number: BlockNumber::new(3_956_206),
            last_finalized_block_number: None,
            events_to_mint: Default::default(),
            minted_events: Default::default(),
            ecdsa_public_key: None,
            invalid_events: Default::default(),
            active_tasks: Default::default(),
        };
        state.validate_config()?;
        Ok(state)
    }
}
