use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArg {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub next_transaction_nonce: Nat,
}

#[derive(CandidType, Clone, Copy, Default, Serialize, Deserialize, Debug, Eq, PartialEq, Hash)]
pub enum EthereumNetwork {
    Mainnet,
    #[default]
    Sepolia,
}

impl EthereumNetwork {
    pub fn chain_id(&self) -> u64 {
        match self {
            EthereumNetwork::Mainnet => 1,
            EthereumNetwork::Sepolia => 11155111,
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MinterArg {
    InitArg(InitArg),
    UpgradeArg,
}

#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReceivedEthEvent {
    pub transaction_hash: String,
    pub block_number: Nat,
    pub log_index: Nat,
    pub from_address: String,
    pub value: Nat,
    pub principal: candid::Principal,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Eip1559TransactionPrice {
    pub base_fee_from_last_finalized_block: Nat,
    pub base_fee_of_next_finalized_block: Nat,
    pub max_priority_fee_per_gas: Nat,
    pub max_fee_per_gas: Nat,
    pub gas_limit: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DebugState {
    pub ecdsa_key_name: String,
    pub last_seen_block_number: Nat,
    pub minted_transactions: Vec<EthTransaction>,
    pub invalid_transactions: Vec<EthTransaction>,
    pub next_transaction_nonce: Nat,
    pub unapproved_retrieve_eth_requests: Vec<String>,
    pub signed_retrieve_eth_requests: Vec<String>,
    pub sent_retrieve_eth_requests: Vec<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct EthTransaction {
    pub transaction_hash: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RetrieveEthRequest {
    pub block_index: Nat,
}

#[derive(CandidType, Deserialize)]
pub enum RetrieveEthStatus {
    NotFound,
    PendingSigning,
    Found(EthTransaction),
}
