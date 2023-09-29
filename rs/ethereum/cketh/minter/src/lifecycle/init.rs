use crate::address::Address;
use crate::endpoints::CandidBlockTag;
use crate::eth_rpc::BlockTag;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{BlockNumber, TransactionNonce, Wei};
use crate::state::{InvalidStateError, State};
use crate::transactions::EthTransactions;
use candid::types::number::Nat;
use candid::types::principal::Principal;
use candid::{CandidType, Deserialize};
use minicbor::{Decode, Encode};

#[derive(
    CandidType, serde::Serialize, Deserialize, Clone, Debug, Encode, Decode, PartialEq, Eq,
)]
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
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {}", e)))?;
        let minimum_withdrawal_amount = Wei::try_from(minimum_withdrawal_amount).map_err(|e| {
            InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {}", e))
        })?;
        let ethereum_contract_address = ethereum_contract_address
            .map(|a| Address::from_str(&a))
            .transpose()
            .map_err(|e| {
                InvalidStateError::InvalidEthereumContractAddress(format!("ERROR: {}", e))
            })?;
        let state = Self {
            ethereum_network,
            ecdsa_key_name,
            ethereum_contract_address,
            retrieve_eth_principals: Default::default(),
            eth_transactions: EthTransactions::new(initial_nonce),
            ledger_id,
            minimum_withdrawal_amount,
            ethereum_block_height: BlockTag::from(ethereum_block_height),
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_scraped_block_number: BlockNumber::new(3_956_206),
            last_observed_block_number: None,
            events_to_mint: Default::default(),
            minted_events: Default::default(),
            ecdsa_public_key: None,
            invalid_events: Default::default(),
            active_tasks: Default::default(),
            http_request_counter: 0,
        };
        state.validate_config()?;
        Ok(state)
    }
}
