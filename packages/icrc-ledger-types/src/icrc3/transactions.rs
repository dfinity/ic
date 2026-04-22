use candid::{CandidType, Deserialize, Nat, Principal};
use serde::Serialize;

use crate::{
    icrc::generic_value::Value,
    icrc1::{
        account::Account,
        transfer::{BlockIndex, Memo},
    },
};

use super::{
    archive::{ArchivedRange, QueryTxArchiveFn},
    blocks::GetBlocksRequest,
};

// Constants for tx.kind
pub const TRANSACTION_APPROVE: &str = "approve";
pub const TRANSACTION_BURN: &str = "burn";
pub const TRANSACTION_MINT: &str = "mint";
pub const TRANSACTION_TRANSFER: &str = "transfer";
pub const TRANSACTION_FEE_COLLECTOR: &str = "107feecol";
pub const TRANSACTION_AUTHORIZED_MINT: &str = "122mint";
pub const TRANSACTION_AUTHORIZED_BURN: &str = "122burn";
pub const TRANSACTION_FREEZE_ACCOUNT: &str = "123freezeaccount";
pub const TRANSACTION_UNFREEZE_ACCOUNT: &str = "123unfreezeaccount";
pub const TRANSACTION_FREEZE_PRINCIPAL: &str = "123freezeprincipal";
pub const TRANSACTION_UNFREEZE_PRINCIPAL: &str = "123unfreezeprincipal";

pub type GenericTransaction = Value;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Mint {
    pub amount: Nat,
    pub to: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
    pub fee: Option<Nat>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub amount: Nat,
    pub from: Account,
    pub spender: Option<Account>,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
    pub fee: Option<Nat>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub amount: Nat,
    pub from: Account,
    pub to: Account,
    pub spender: Option<Account>,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Approve {
    pub from: Account,
    pub spender: Account,
    pub amount: Nat,
    pub expected_allowance: Option<Nat>,
    pub expires_at: Option<u64>,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FeeCollector {
    pub fee_collector: Option<Account>,
    pub caller: Option<Principal>,
    pub ts: Option<u64>,
    pub mthd: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedMint {
    pub amount: Nat,
    pub to: Account,
    pub created_at_time: Option<u64>,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedBurn {
    pub amount: Nat,
    pub from: Account,
    pub created_at_time: Option<u64>,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FreezeAccount {
    pub account: Account,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UnfreezeAccount {
    pub account: Account,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FreezePrincipal {
    pub principal: Principal,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UnfreezePrincipal {
    pub principal: Principal,
    pub caller: Option<Principal>,
    pub mthd: Option<String>,
    pub reason: Option<String>,
}

// Representation of a Transaction which supports the Icrc1 Standard functionalities
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub kind: String,
    pub mint: Option<Mint>,
    pub burn: Option<Burn>,
    pub transfer: Option<Transfer>,
    pub approve: Option<Approve>,
    pub fee_collector: Option<FeeCollector>,
    pub authorized_mint: Option<AuthorizedMint>,
    pub authorized_burn: Option<AuthorizedBurn>,
    pub freeze_account: Option<FreezeAccount>,
    pub unfreeze_account: Option<UnfreezeAccount>,
    pub freeze_principal: Option<FreezePrincipal>,
    pub unfreeze_principal: Option<UnfreezePrincipal>,
    pub timestamp: u64,
}

impl Transaction {
    pub fn burn(burn: Burn, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_BURN.into(),
            timestamp,
            mint: None,
            burn: Some(burn),
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn mint(mint: Mint, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_MINT.into(),
            timestamp,
            mint: Some(mint),
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn transfer(transfer: Transfer, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_TRANSFER.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: Some(transfer),
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn approve(approve: Approve, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_APPROVE.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: Some(approve),
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn set_fee_collector(fee_collector: FeeCollector, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_FEE_COLLECTOR.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: Some(fee_collector),
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn authorized_mint(authorized_mint: AuthorizedMint, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_AUTHORIZED_MINT.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: Some(authorized_mint),
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn authorized_burn(authorized_burn: AuthorizedBurn, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_AUTHORIZED_BURN.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: Some(authorized_burn),
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn freeze_account(freeze_account: FreezeAccount, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_FREEZE_ACCOUNT.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: Some(freeze_account),
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn unfreeze_account(unfreeze_account: UnfreezeAccount, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_UNFREEZE_ACCOUNT.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: Some(unfreeze_account),
            freeze_principal: None,
            unfreeze_principal: None,
        }
    }

    pub fn freeze_principal(freeze_principal: FreezePrincipal, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_FREEZE_PRINCIPAL.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: Some(freeze_principal),
            unfreeze_principal: None,
        }
    }

    pub fn unfreeze_principal(unfreeze_principal: UnfreezePrincipal, timestamp: u64) -> Self {
        Self {
            kind: TRANSACTION_UNFREEZE_PRINCIPAL.into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            authorized_mint: None,
            authorized_burn: None,
            freeze_account: None,
            unfreeze_account: None,
            freeze_principal: None,
            unfreeze_principal: Some(unfreeze_principal),
        }
    }
}

/// Deprecated. Use [`GetBlocksResponse`] returned from the
/// [`icrc3_get_blocks`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint instead.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsResponse {
    pub log_length: Nat,
    pub first_index: BlockIndex,
    pub transactions: Vec<Transaction>,
    pub archived_transactions: Vec<ArchivedRange<QueryTxArchiveFn>>,
}

/// Deprecated. Use Vec<[`ICRC3GenericBlock`]> instead
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionRange {
    pub transactions: Vec<Transaction>,
}

pub type GetTransactionsRequest = GetBlocksRequest;
