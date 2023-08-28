use candid::{CandidType, Deserialize, Nat, Principal};
use icrc_ledger_types::icrc2::transfer_from::TransferFromError;
use serde::Serialize;

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArg {
    pub ethereum_network: EthereumNetwork,
    pub ecdsa_key_name: String,
    pub ledger_id: Principal,
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
    Signed(EthTransaction),
    Sent(EthTransaction),
}

#[derive(CandidType)]
pub enum WithdrawalError {
    AmountTooLow { min_withdrawal_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TemporarilyUnavailable(String),
}

impl From<TransferFromError> for WithdrawalError {
    fn from(transfer_from_error: TransferFromError) -> Self {
        match transfer_from_error {
            TransferFromError::BadFee { expected_fee } => {
                panic!("bug: bad fee, expected fee: {expected_fee}")
            }
            TransferFromError::BadBurn { min_burn_amount } => {
                panic!("bug: bad burn, minimum burn amount: {min_burn_amount}")
            }
            TransferFromError::InsufficientFunds { balance } => Self::InsufficientFunds { balance },
            TransferFromError::InsufficientAllowance { allowance } => {
                Self::InsufficientAllowance { allowance }
            }
            TransferFromError::TooOld => panic!("bug: transfer too old"),
            TransferFromError::CreatedInFuture { ledger_time } => {
                panic!("bug: created in future, ledger time: {ledger_time}")
            }
            TransferFromError::Duplicate { duplicate_of } => {
                panic!("bug: duplicate transfer of: {duplicate_of}")
            }
            TransferFromError::TemporarilyUnavailable => Self::TemporarilyUnavailable(
                "ckETH ledger temporarily unavailble, try again".to_string(),
            ),
            TransferFromError::GenericError {
                error_code,
                message,
            } => Self::TemporarilyUnavailable(
                format!(
                    "ckETH ledger unreachable, error code: {error_code}, with message: {message}"
                )
                .to_string(),
            ),
        }
    }
}
