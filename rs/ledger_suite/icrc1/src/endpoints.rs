use crate::Block;
use candid::CandidType;
use candid::types::number::Nat;
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc1::transfer::TransferError;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc2::transfer_from::TransferFromError;
use icrc_ledger_types::icrc3::transactions::{
    Approve, Burn, FeeCollector, Mint, Transaction, Transfer,
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
        use TransferError as TE;
        use ic_ledger_canister_core::ledger::TransferError as CTE;

        Ok(match err.0 {
            CTE::BadFee { expected_fee } => TE::BadFee {
                expected_fee: expected_fee.into(),
            },
            CTE::InsufficientFunds { balance } => TE::InsufficientFunds {
                balance: balance.into(),
            },
            CTE::TxTooOld { .. } => TE::TooOld,
            CTE::TxCreatedInFuture { ledger_time } => TE::CreatedInFuture {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            CTE::TxThrottled => TE::TemporarilyUnavailable,
            CTE::TxDuplicate { duplicate_of } => TE::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            CTE::InsufficientAllowance { .. } => {
                return Err(
                    "InsufficientAllowance error should not happen for transfer".to_string()
                );
            }
            CTE::ExpiredApproval { .. } => {
                return Err("ExpiredApproval error should not happen for transfer".to_string());
            }
            CTE::AllowanceChanged { .. } => {
                return Err("AllowanceChanged error should not happen for transfer".to_string());
            }
            CTE::SelfApproval => {
                return Err("SelfApproval error should not happen for transfer".to_string());
            }
            CTE::BadBurn { min_burn_amount } => TE::BadBurn {
                min_burn_amount: min_burn_amount.into(),
            },
        })
    }
}

impl<Tokens: TokensType> TryFrom<EndpointsTransferError<Tokens>> for ApproveError {
    type Error = String;
    fn try_from(err: EndpointsTransferError<Tokens>) -> Result<Self, Self::Error> {
        use ApproveError as AE;
        use ic_ledger_canister_core::ledger::TransferError as CTE;

        Ok(match err.0 {
            CTE::BadFee { expected_fee } => AE::BadFee {
                expected_fee: expected_fee.into(),
            },
            CTE::InsufficientFunds { balance } => AE::InsufficientFunds {
                balance: balance.into(),
            },
            CTE::TxTooOld { .. } => AE::TooOld,
            CTE::TxCreatedInFuture { ledger_time } => AE::CreatedInFuture {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            CTE::TxThrottled => AE::TemporarilyUnavailable,
            CTE::TxDuplicate { duplicate_of } => AE::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            CTE::InsufficientAllowance { .. } => {
                return Err(
                    "InsufficientAllowance error should not happen for approval".to_string()
                );
            }
            CTE::ExpiredApproval { ledger_time } => AE::Expired {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            CTE::AllowanceChanged { current_allowance } => AE::AllowanceChanged {
                current_allowance: current_allowance.into(),
            },
            CTE::SelfApproval => {
                return Err("self-approvals are not allowed".to_string());
            }
            CTE::BadBurn { .. } => {
                return Err("BadBurn error should not happen for Approve".to_string());
            }
        })
    }
}

impl<Tokens: TokensType> TryFrom<EndpointsTransferError<Tokens>> for TransferFromError {
    type Error = String;
    fn try_from(err: EndpointsTransferError<Tokens>) -> Result<Self, Self::Error> {
        use TransferFromError as TFE;
        use ic_ledger_canister_core::ledger::TransferError as CTE;

        Ok(match err.0 {
            CTE::BadFee { expected_fee } => TFE::BadFee {
                expected_fee: expected_fee.into(),
            },
            CTE::InsufficientFunds { balance } => TFE::InsufficientFunds {
                balance: balance.into(),
            },
            CTE::TxTooOld { .. } => TFE::TooOld,
            CTE::TxCreatedInFuture { ledger_time } => TFE::CreatedInFuture {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            CTE::TxThrottled => TFE::TemporarilyUnavailable,
            CTE::TxDuplicate { duplicate_of } => TFE::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
            CTE::InsufficientAllowance { allowance } => TFE::InsufficientAllowance {
                allowance: allowance.into(),
            },
            CTE::ExpiredApproval { .. } => {
                return Err("Expired not implemented for TransferFromError".to_string());
            }
            CTE::AllowanceChanged { .. } => {
                return Err("AllowanceChanged not implemented for TransferFromError".to_string());
            }
            CTE::SelfApproval => {
                return Err("self approval not implemented for TransferFromError".to_string());
            }
            CTE::BadBurn { min_burn_amount } => TFE::BadBurn {
                min_burn_amount: min_burn_amount.into(),
            },
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}

// Non-standard queries

impl<Tokens: TokensType> From<Block<Tokens>> for Transaction {
    fn from(b: Block<Tokens>) -> Self {
        use crate::Operation;

        let mut tx = Transaction {
            kind: "".to_string(),
            mint: None,
            burn: None,
            transfer: None,
            approve: None,
            fee_collector: None,
            timestamp: b.timestamp,
        };
        let created_at_time = b.transaction.created_at_time;
        let memo = b.transaction.memo;

        match b.transaction.operation {
            Operation::Mint { to, amount, fee } => {
                tx.kind = "mint".to_string();
                tx.mint = Some(Mint {
                    to,
                    amount: amount.into(),
                    created_at_time,
                    memo,
                    fee: fee.map(Into::into),
                });
            }
            Operation::Burn {
                from,
                spender,
                amount,
                fee,
            } => {
                tx.kind = "burn".to_string();
                tx.burn = Some(Burn {
                    from,
                    spender,
                    amount: amount.into(),
                    created_at_time,
                    memo,
                    fee: fee.map(Into::into),
                });
            }
            Operation::Transfer {
                from,
                to,
                spender,
                amount,
                fee,
            } => {
                tx.kind = "transfer".to_string();
                tx.transfer = Some(Transfer {
                    from,
                    to,
                    spender,
                    amount: amount.into(),
                    fee: fee.or(b.effective_fee).map(Into::into),
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
                    amount: amount.into(),
                    expected_allowance: expected_allowance.map(Into::into),
                    expires_at,
                    fee: fee
                        .map(Into::into)
                        .or_else(|| b.effective_fee.map(Into::into)),
                    created_at_time,
                    memo,
                });
            }
            Operation::FeeCollector {
                fee_collector,
                caller,
                op,
            } => {
                tx.kind = "107feecol".to_string();
                tx.fee_collector = Some(FeeCollector {
                    fee_collector,
                    caller,
                    ts: created_at_time,
                    op,
                });
            }
        }

        tx
    }
}
