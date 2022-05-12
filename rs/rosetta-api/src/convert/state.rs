use crate::errors::ApiError;
use crate::models::seconds::Seconds;
use crate::request::Request;
use crate::request_types::{
    AddHotKey, Disburse, Follow, MergeMaturity, NeuronInfo, PublicKeyOrPrincipal, RemoveHotKey,
    SetDissolveTimestamp, Spawn, Stake, StartDissolve, StopDissolve,
};
use ic_types::PrincipalId;
use ledger_canister::{Operation, Tokens, DEFAULT_TRANSFER_FEE};

/// Helper for `from_operations` that creates `Transfer`s from related
/// debit/credit/fee operations.
pub struct State {
    preprocessing: bool,
    pub(crate) actions: Vec<Request>,
    credit: Option<AccountTokens>,
    debit: Option<AccountTokens>,
    fee: Option<AccountTokens>,
}

impl State {
    pub fn new(
        preprocessing: bool,
        actions: Vec<Request>,
        credit: Option<AccountTokens>,
        debit: Option<AccountTokens>,
        fee: Option<AccountTokens>,
    ) -> Self {
        Self {
            preprocessing,
            actions,
            credit,
            debit,
            fee,
        }
    }

    /// Create a `Transfer` from the credit/debit/fee operations seen
    /// previously.
    pub fn flush(&mut self) -> Result<(), ApiError> {
        let trans_err = |msg| {
            let msg = format!("Bad transaction: {}", msg);
            let err = ApiError::InvalidTransaction(false, msg.into());
            Err(err)
        };

        if self.credit.is_none() && self.debit.is_none() && self.fee.is_none() {
            return Ok(());
        }

        // If you're preprocessing just continue with the default fee
        if self.preprocessing && self.fee.is_none() && self.debit.is_some() {
            self.fee = Some(AccountTokens {
                tokens: DEFAULT_TRANSFER_FEE,
                account: self.debit.as_ref().unwrap().account,
            })
        }

        if self.credit.is_none() || self.debit.is_none() || self.fee.is_none() {
            return trans_err(
                "Operations do not combine to make a recognizable transaction".to_string(),
            );
        }
        let AccountTokens {
            account: mut to,
            tokens: cr_amount,
        } = self.credit.take().unwrap();
        let AccountTokens {
            account: mut from,
            tokens: db_amount,
        } = self.debit.take().unwrap();
        let AccountTokens {
            account: fee_acc,
            tokens: fee_amount,
        } = self.fee.take().unwrap();

        if fee_acc != from {
            if cr_amount == Tokens::ZERO && fee_acc == to {
                std::mem::swap(&mut from, &mut to);
            } else {
                let msg = format!("Fee should be taken from {}", from);
                return trans_err(msg);
            }
        }
        if cr_amount != db_amount {
            return trans_err("Debit_amount should be equal -credit_amount".to_string());
        }

        self.actions.push(Request::Transfer(Operation::Transfer {
            from,
            to,
            amount: cr_amount,
            fee: fee_amount,
        }));

        Ok(())
    }

    pub fn transaction(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        amount: i128,
    ) -> Result<(), ApiError> {
        if amount > 0 || self.debit.is_some() && amount == 0 {
            if self.credit.is_some() {
                self.flush()?;
            }
            self.credit = Some(AccountTokens {
                account,
                tokens: Tokens::from_e8s(amount as u64),
            });
        } else {
            if self.debit.is_some() {
                self.flush()?;
            }
            self.debit = Some(AccountTokens {
                account,
                tokens: Tokens::from_e8s((-amount) as u64),
            });
        }
        Ok(())
    }

    pub fn fee(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        amount: Tokens,
    ) -> Result<(), ApiError> {
        if self.fee.is_some() {
            self.flush()?;
        }
        self.fee = Some(AccountTokens {
            account,
            tokens: amount,
        });
        Ok(())
    }

    pub fn stake(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::Stake(Stake {
            account,
            neuron_index,
        }));
        Ok(())
    }

    pub fn set_dissolve_timestamp(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        timestamp: Seconds,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions
            .push(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account,
                neuron_index,
                timestamp,
            }));
        Ok(())
    }

    pub fn start_dissolve(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::StartDissolve(StartDissolve {
            account,
            neuron_index,
        }));
        Ok(())
    }

    pub fn stop_dissolve(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::StopDissolve(StopDissolve {
            account,
            neuron_index,
        }));
        Ok(())
    }

    pub fn add_hot_key(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        key: PublicKeyOrPrincipal,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::AddHotKey(AddHotKey {
            account,
            neuron_index,
            key,
        }));
        Ok(())
    }

    pub fn remove_hotkey(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        key: PublicKeyOrPrincipal,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::RemoveHotKey(RemoveHotKey {
            account,
            neuron_index,
            key,
        }));
        Ok(())
    }

    pub fn disburse(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        amount: Option<Tokens>,
        recipient: Option<ledger_canister::AccountIdentifier>,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::Disburse(Disburse {
            account,
            amount,
            recipient,
            neuron_index,
        }));
        Ok(())
    }

    pub fn spawn(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        spawned_neuron_index: u64,
        percentage_to_spawn: Option<u32>,
        controller: Option<PrincipalId>,
    ) -> Result<(), ApiError> {
        if let Some(pct) = percentage_to_spawn {
            if !(1..=100).contains(&pct) {
                let msg = format!("Invalid percentage to spawn: {}", pct);
                let err = ApiError::InvalidTransaction(false, msg.into());
                return Err(err);
            }
        }
        self.flush()?;
        self.actions.push(Request::Spawn(Spawn {
            account,
            spawned_neuron_index,
            controller,
            percentage_to_spawn,
            neuron_index,
        }));

        Ok(())
    }

    pub fn merge_maturity(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        percentage_to_merge: Option<u32>,
    ) -> Result<(), ApiError> {
        if let Some(pct) = percentage_to_merge {
            if !(1..=100).contains(&pct) {
                let msg = format!("Invalid percentage to merge: {}", pct);
                let err = ApiError::InvalidTransaction(false, msg.into());
                return Err(err);
            }
        }
        self.flush()?;
        self.actions.push(Request::MergeMaturity(MergeMaturity {
            account,
            neuron_index,
            percentage_to_merge: percentage_to_merge.unwrap_or(100),
        }));
        Ok(())
    }

    pub fn neuron_info(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        controller: Option<PrincipalId>,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::NeuronInfo(NeuronInfo {
            account,
            controller,
            neuron_index,
        }));
        Ok(())
    }

    pub fn follow(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        controller: Option<PrincipalId>,
        neuron_index: u64,
        topic: i32,
        followees: Vec<u64>,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::Follow(Follow {
            account,
            topic,
            followees,
            controller,
            neuron_index,
        }));
        Ok(())
    }
}

/// Structure for manipulating tokens in relation to account, for example during transfers.
pub struct AccountTokens {
    account: ledger_canister::AccountIdentifier,
    tokens: Tokens,
}
