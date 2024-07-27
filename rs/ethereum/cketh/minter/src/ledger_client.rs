use crate::erc20::{CkErc20Token, CkTokenSymbol};
use crate::logs::DEBUG;
use crate::memo::BurnMemo;
use crate::numeric::LedgerBurnIndex;
use crate::state::State;
use candid::{Nat, Principal};
use ic_canister_log::log;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use num_traits::ToPrimitive;

pub struct LedgerClient {
    token_symbol: CkTokenSymbol,
    client: ICRC1Client<CdkRuntime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CkLedger {
    pub token_symbol: CkTokenSymbol,
    pub id: Principal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerBurnError {
    TemporarilyUnavailable {
        message: String,
        ledger: CkLedger,
    },
    AmountTooLow {
        minimum_burn_amount: Nat,
        failed_burn_amount: Nat,
        ledger: CkLedger,
    },
    InsufficientFunds {
        balance: Nat,
        failed_burn_amount: Nat,
        ledger: CkLedger,
    },
    InsufficientAllowance {
        allowance: Nat,
        failed_burn_amount: Nat,
        ledger: CkLedger,
    },
}

impl LedgerClient {
    pub fn cketh_ledger_from_state(state: &State) -> Self {
        Self {
            token_symbol: CkTokenSymbol::cketh_symbol_from_state(state),
            client: ICRC1Client {
                runtime: CdkRuntime,
                ledger_canister_id: state.cketh_ledger_id,
            },
        }
    }

    pub fn ckerc20_ledger(token: &CkErc20Token) -> Self {
        Self {
            token_symbol: token.ckerc20_token_symbol.clone(),
            client: ICRC1Client {
                runtime: CdkRuntime,
                ledger_canister_id: token.ckerc20_ledger_id,
            },
        }
    }

    pub async fn burn_from<A: Into<Nat>>(
        &self,
        from: Account,
        amount: A,
        memo: BurnMemo,
    ) -> Result<LedgerBurnIndex, LedgerBurnError> {
        let amount = amount.into();
        match self
            .client
            .transfer_from(TransferFromArgs {
                spender_subaccount: None,
                from,
                to: ic_cdk::id().into(),
                amount: amount.clone(),
                fee: None,
                memo: Some(Memo::from(memo)),
                created_at_time: None, // We don't set this field to disable transaction deduplication
                                       // which is unnecessary in canister-to-canister calls.
            })
            .await
        {
            Ok(Ok(block_index)) => Ok(LedgerBurnIndex::new(
                block_index.0.to_u64().expect("nat does not fit into u64"),
            )),
            Ok(Err(transfer_from_error)) => {
                log!(
                    DEBUG,
                    "[burn]: failed to transfer_from from the {:?} ledger with error: {transfer_from_error:?}",
                    self.ck_ledger()
                );
                let burn_error = match transfer_from_error {
                    TransferFromError::BadFee { expected_fee } => {
                        panic!("BUG: bad fee, expected fee: {expected_fee}")
                    }
                    TransferFromError::BadBurn { min_burn_amount } => {
                        LedgerBurnError::AmountTooLow {
                            minimum_burn_amount: min_burn_amount,
                            failed_burn_amount: amount.clone(),
                            ledger: self.ck_ledger(),
                        }
                    }
                    TransferFromError::InsufficientFunds { balance } => {
                        LedgerBurnError::InsufficientFunds {
                            balance,
                            failed_burn_amount: amount.clone(),
                            ledger: self.ck_ledger(),
                        }
                    }
                    TransferFromError::InsufficientAllowance { allowance } => {
                        LedgerBurnError::InsufficientAllowance {
                            allowance,
                            failed_burn_amount: amount,
                            ledger: self.ck_ledger(),
                        }
                    }
                    TransferFromError::TooOld => panic!("BUG: transfer too old"),
                    TransferFromError::CreatedInFuture { ledger_time } => {
                        panic!("BUG: created in future, ledger time: {ledger_time}")
                    }
                    TransferFromError::Duplicate { duplicate_of } => {
                        panic!("BUG: duplicate transfer of: {duplicate_of}")
                    }
                    TransferFromError::TemporarilyUnavailable => {
                        LedgerBurnError::TemporarilyUnavailable {
                            message: format!(
                                "{} ledger temporarily unavailable, try again",
                                self.token_symbol
                            ),
                            ledger: self.ck_ledger(),
                        }
                    }
                    TransferFromError::GenericError {
                        error_code,
                        message,
                    } => LedgerBurnError::TemporarilyUnavailable {
                        message: format!(
                        "{} ledger unreachable, error code: {error_code}, with message: {message}",
                        self.token_symbol
                    ),
                        ledger: self.ck_ledger(),
                    },
                };
                Err(burn_error)
            }
            Err((error_code, message)) => {
                let err_msg = format!(
                    "failed to call {} ledger with error_code: {error_code} and message: {message}",
                    self.token_symbol
                );
                log!(DEBUG, "[burn]: {err_msg}",);
                Err(LedgerBurnError::TemporarilyUnavailable {
                    message: err_msg,
                    ledger: self.ck_ledger(),
                })
            }
        }
    }

    fn ck_ledger(&self) -> CkLedger {
        CkLedger {
            token_symbol: self.token_symbol.clone(),
            id: self.client.ledger_canister_id,
        }
    }
}
