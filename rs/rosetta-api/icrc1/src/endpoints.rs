use crate::Block;
use candid::types::number::Nat;
use candid::CandidType;
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use icrc_ledger_types::icrc1::transfer::TransferError;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{
    Approve, Burn, Mint, Transaction, Transfer, TransferFrom,
};
use serde::Deserialize;

pub fn convert_transfer_error(err: CoreTransferError) -> EndpointsTransferError {
    EndpointsTransferError(err)
}

pub struct EndpointsTransferError(pub CoreTransferError);

impl From<EndpointsTransferError> for TransferError {
    fn from(err: EndpointsTransferError) -> Self {
        use ic_ledger_canister_core::ledger::TransferError as LTE;
        use TransferError as TE;

        match err.0 {
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
            LTE::InsufficientAllowance { .. } => {
                unimplemented!("InsufficientAllowance error should not happen for transfer")
            }
            LTE::ExpiredApproval { .. } => {
                unimplemented!("ExpiredApproval error should not happen for transfer")
            }
            LTE::AllowanceChanged { .. } => {
                unimplemented!("AllowanceChanged error should not happen for transfer")
            }
            LTE::SelfApproval { .. } => {
                unimplemented!("SelfApproval error should not happen for transfer")
            }
        }
    }
}

impl From<EndpointsTransferError> for ApproveError {
    fn from(err: EndpointsTransferError) -> Self {
        use ic_ledger_canister_core::ledger::TransferError as LTE;
        use ApproveError as AE;

        match err.0 {
            LTE::BadFee { expected_fee } => AE::BadFee {
                expected_fee: Nat::from(expected_fee.get_e8s()),
            },
            LTE::InsufficientFunds { balance } => AE::InsufficientFunds {
                balance: Nat::from(balance.get_e8s()),
            },
            LTE::TxTooOld { .. } => AE::TooOld,
            LTE::TxCreatedInFuture { ledger_time } => AE::CreatedInFuture {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            LTE::TxThrottled => AE::TemporarilyUnavailable,
            LTE::TxDuplicate { duplicate_of } => AE::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            LTE::InsufficientAllowance { .. } => {
                unimplemented!("InsufficientAllowance error should not happen for approval")
            }
            LTE::ExpiredApproval { ledger_time } => AE::Expired {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            LTE::AllowanceChanged { current_allowance } => AE::AllowanceChanged {
                current_allowance: Nat::from(current_allowance.get_e8s()),
            },
            LTE::SelfApproval { .. } => {
                unimplemented!("self approval not implemented for ApproveError")
            }
        }
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
            approve: None,
            transfer_from: None,
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
            Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => {
                tx.kind = "approve".to_string();
                tx.approve = Some(Approve {
                    from,
                    spender,
                    amount: Nat::from(amount),
                    expected_allowance: expected_allowance.map(|ea| Nat::from(ea.get_e8s())),
                    expires_at: expires_at.map(|exp| exp.as_nanos_since_unix_epoch()),
                    fee: fee
                        .map(Nat::from)
                        .or_else(|| b.effective_fee.map(Nat::from)),
                    created_at_time,
                    memo,
                });
            }
            Operation::TransferFrom {
                spender,
                from,
                to,
                amount,
                fee,
            } => {
                tx.kind = "transfer_from".to_string();
                tx.transfer_from = Some(TransferFrom {
                    spender,
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
