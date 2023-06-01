use crate::Block;
use candid::types::number::Nat;
use candid::CandidType;
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use icrc_ledger_types::icrc1::transfer::TransferError;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint, Transaction, Transfer};
use serde::Deserialize;

pub fn convert_transfer_error(err: CoreTransferError) -> TransferError {
    use ic_ledger_canister_core::ledger::TransferError as LTE;
    use TransferError as TE;

    match err {
        LTE::BadFee { expected_fee } => TE::BadFee {
            expected_fee: Nat::from(expected_fee.get_e8s()),
        },
        LTE::InsufficientFunds { balance } => TE::InsufficientFunds {
            balance: Nat::from(balance.get_e8s()),
        },
        LTE::TxTooOld { .. } => TE::TooOld,
        LTE::TxCreatedInFuture { ledger_time } => TE::CreatedInFuture {
            ledger_time: ledger_time.as_nanos_since_unix_epoch(),
        },
        LTE::TxThrottled => TE::TemporarilyUnavailable,
        LTE::TxDuplicate { duplicate_of } => TE::Duplicate {
            duplicate_of: Nat::from(duplicate_of),
        },
        LTE::InsufficientAllowance { .. } => todo!(),
        LTE::ExpiredApproval { .. } => todo!(),
        LTE::AllowanceChanged { .. } => todo!(),
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}

// Non-standard queries

impl From<Block> for Transaction {
    fn from(b: Block) -> Transaction {
        use crate::Operation;

        let mut tx = Transaction {
            kind: "".to_string(),
            mint: None,
            burn: None,
            transfer: None,
            timestamp: b.timestamp,
        };
        let created_at_time = b.transaction.created_at_time;
        let memo = b.transaction.memo;

        match b.transaction.operation {
            Operation::Mint { to, amount } => {
                tx.kind = "mint".to_string();
                tx.mint = Some(Mint {
                    to,
                    amount: Nat::from(amount),
                    created_at_time,
                    memo,
                });
            }
            Operation::Burn { from, amount } => {
                tx.kind = "burn".to_string();
                tx.burn = Some(Burn {
                    from,
                    amount: Nat::from(amount),
                    created_at_time,
                    memo,
                });
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                tx.kind = "transfer".to_string();
                tx.transfer = Some(Transfer {
                    from,
                    to,
                    amount: Nat::from(amount),
                    fee: fee
                        .map(Nat::from)
                        .or_else(|| b.effective_fee.map(Nat::from)),
                    created_at_time,
                    memo,
                });
            }
        }

        tx
    }
}
