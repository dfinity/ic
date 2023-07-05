use crate::Block;
use candid::types::number::Nat;
use candid::CandidType;
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc1::transfer::TransferError;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{
    Approve, Burn, Mint, Transaction, Transfer, TransferFrom,
};
use serde::Deserialize;

pub fn convert_transfer_error<Tokens: TokensType>(
    err: CoreTransferError<Tokens>,
) -> EndpointsTransferError<Tokens> {
    EndpointsTransferError(err)
}

pub struct EndpointsTransferError<Tokens>(pub CoreTransferError<Tokens>);

impl<Tokens: TokensType> TryFrom<EndpointsTransferError<Tokens>> for TransferError {
    type Error = String;
    fn try_from(err: EndpointsTransferError<Tokens>) -> Result<Self, Self::Error> {
        use ic_ledger_canister_core::ledger::TransferError as LTE;
        use TransferError as TE;

        Ok(match err.0 {
            LTE::BadFee { expected_fee } => TE::BadFee {
                expected_fee: expected_fee.into(),
            },
            LTE::InsufficientFunds { balance } => TE::InsufficientFunds {
                balance: balance.into(),
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
                return Err(
                    "InsufficientAllowance error should not happen for transfer".to_string()
                );
            }
            LTE::ExpiredApproval { .. } => {
                return Err("ExpiredApproval error should not happen for transfer".to_string());
            }
            LTE::AllowanceChanged { .. } => {
                return Err("AllowanceChanged error should not happen for transfer".to_string());
            }
            LTE::SelfApproval { .. } => {
                return Err("SelfApproval error should not happen for transfer".to_string());
            }
        })
    }
}

impl<Tokens: TokensType> TryFrom<EndpointsTransferError<Tokens>> for ApproveError {
    type Error = String;
    fn try_from(err: EndpointsTransferError<Tokens>) -> Result<Self, Self::Error> {
        use ic_ledger_canister_core::ledger::TransferError as LTE;
        use ApproveError as AE;

        Ok(match err.0 {
            LTE::BadFee { expected_fee } => AE::BadFee {
                expected_fee: expected_fee.into(),
            },
            LTE::InsufficientFunds { balance } => AE::InsufficientFunds {
                balance: balance.into(),
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
                return Err(
                    "InsufficientAllowance error should not happen for approval".to_string()
                );
            }
            LTE::ExpiredApproval { ledger_time } => AE::Expired {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            LTE::AllowanceChanged { current_allowance } => AE::AllowanceChanged {
                current_allowance: current_allowance.into(),
            },
            LTE::SelfApproval { .. } => {
                return Err("self-approvals are not allowed".to_string());
            }
        })
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
