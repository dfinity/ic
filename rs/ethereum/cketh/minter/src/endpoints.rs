use candid::{CandidType, Deserialize, Nat};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArg {
    pub ecdsa_key_name: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MinterArg {
    InitArg(InitArg),
    UpgradeArg,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DisplayLogsRequest {
    pub address: String,
    pub from: String,
    pub to: String,
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
pub struct Eip2930TransactionPrice {
    pub gas_price: Nat,
    pub gas_limit: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DebugState {
    pub ecdsa_key_name: String,
    pub last_seen_block_number: Nat,
    pub minted_transactions: Vec<EthTransaction>,
    pub invalid_transactions: Vec<EthTransaction>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct EthTransaction {
    pub transaction_hash: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RetrieveEthRequest {
    pub block_index: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum TransactionStatus {
    NotFound,
    Pending,
    Finalized,
}
