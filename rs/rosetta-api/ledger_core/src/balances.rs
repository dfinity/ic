use crate::tokens::Tokens;
use serde::{Deserialize, Serialize};
use std::collections::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};
use std::marker::PhantomData;

pub trait BalancesStore<AccountId> {
    /// Returns the balance on the specified account.
    fn get_balance(&self, k: &AccountId) -> Option<&Tokens>;

    /// Update balance for an account using function f.
    /// Its arg is previous balance or None if not found and
    /// return value is the new balance.
    fn update<F, E>(&mut self, acc: AccountId, action_on_acc: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>;
}

impl<AccountId: std::hash::Hash + Eq> BalancesStore<AccountId> for HashMap<AccountId, Tokens> {
    fn get_balance(&self, k: &AccountId) -> Option<&Tokens> {
        self.get(k)
    }

    fn update<F, E>(&mut self, k: AccountId, mut f: F) -> Result<Tokens, E>
    where
        F: FnMut(Option<&Tokens>) -> Result<Tokens, E>,
    {
        match self.entry(k) {
            Occupied(mut entry) => {
                let new_v = f(Some(entry.get()))?;
                if new_v != Tokens::ZERO {
                    *entry.get_mut() = new_v;
                } else {
                    entry.remove_entry();
                }
                Ok(new_v)
            }
            Vacant(entry) => {
                let new_v = f(None)?;
                if new_v != Tokens::ZERO {
                    entry.insert(new_v);
                }
                Ok(new_v)
            }
        }
    }
}

/// An error returned by `Balances` if the debit operation fails.
#[derive(Debug)]
pub enum BalanceError {
    /// An error indicating that the account doesn't hold enough funds for
    /// completing the transaction.
    InsufficientFunds { balance: Tokens },
}

/// Describes the state of users accounts at the tip of the chain
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Balances<AccountId, S: BalancesStore<AccountId>> {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub store: S,
    #[serde(alias = "icpt_pool")]
    pub token_pool: Tokens,
    #[serde(skip)]
    _marker: PhantomData<AccountId>,
}

impl<AccountId, S> Default for Balances<AccountId, S>
where
    AccountId: Clone,
    S: Default + BalancesStore<AccountId>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<AccountId, S> Balances<AccountId, S>
where
    AccountId: Clone,
    S: Default + BalancesStore<AccountId>,
{
    pub fn new() -> Self {
        Self {
            store: S::default(),
            token_pool: Tokens::MAX,
            _marker: PhantomData,
        }
    }

    pub fn transfer(
        &mut self,
        from: &AccountId,
        to: &AccountId,
        amount: Tokens,
        fee: Tokens,
    ) -> Result<(), BalanceError> {
        let debit_amount = (amount + fee).map_err(|_| {
            // No account can hold more than u64::MAX.
            let balance = self.account_balance(from);
            BalanceError::InsufficientFunds { balance }
        })?;
        self.debit(from, debit_amount)?;
        self.credit(to, amount);
        // NB. integer overflow is not possible here unless there is a
        // severe bug in the system: total amount of tokens in the
        // circulation cannot exceed u64::MAX.
        self.token_pool += fee;
        Ok(())
    }

    pub fn burn(&mut self, from: &AccountId, amount: Tokens) -> Result<(), BalanceError> {
        self.debit(from, amount)?;
        self.token_pool += amount;
        Ok(())
    }

    pub fn mint(&mut self, to: &AccountId, amount: Tokens) -> Result<(), BalanceError> {
        self.token_pool = (self.token_pool - amount).expect("total token supply exceeded");
        self.credit(to, amount);
        Ok(())
    }

    // Debiting an account will automatically remove it from the `inner`
    // HashMap if the balance reaches zero.
    pub fn debit(&mut self, from: &AccountId, amount: Tokens) -> Result<Tokens, BalanceError> {
        self.store.update(from.clone(), |prev| {
            let mut balance = match prev {
                Some(x) => *x,
                None => {
                    return Err(BalanceError::InsufficientFunds {
                        balance: Tokens::ZERO,
                    });
                }
            };
            if balance < amount {
                return Err(BalanceError::InsufficientFunds { balance });
            }

            balance -= amount;
            Ok(balance)
        })
    }

    // Crediting an account will automatically add it to the `inner` HashMap if
    // not already present.
    pub fn credit(&mut self, to: &AccountId, amount: Tokens) {
        self.store
            .update(
                to.clone(),
                |prev| -> Result<Tokens, std::convert::Infallible> {
                    // NB. credit cannot overflow unless there is a bug in the
                    // system: the total amount of tokens in the circulation cannot
                    // exceed u64::MAX, so it's impossible to have more than
                    // u64::MAX tokens on a single account.
                    Ok((amount + *prev.unwrap_or(&Tokens::ZERO)).expect("bug: overflow in credit"))
                },
            )
            .unwrap();
    }

    pub fn account_balance(&self, account: &AccountId) -> Tokens {
        self.store
            .get_balance(account)
            .cloned()
            .unwrap_or(Tokens::ZERO)
    }

    /// Returns the total quantity of Tokens that are "in existence" -- that
    /// is, excluding un-minted "potential" Tokens.
    pub fn total_supply(&self) -> Tokens {
        (Tokens::MAX - self.token_pool).unwrap_or_else(|e| {
            panic!(
                "It is expected that the token_pool is always smaller than \
            or equal to Tokens::MAX, yet subtracting it lead to the following error: {}",
                e
            )
        })
    }
}
