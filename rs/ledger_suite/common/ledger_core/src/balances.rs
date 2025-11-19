use num_traits::Bounded;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, btree_map::Entry};

use crate::tokens::{CheckedAdd, CheckedSub, TokensType, Zero};

pub trait BalancesStore {
    type AccountId: Clone;
    type Tokens;

    /// Returns the balance on the specified account.
    fn get_balance(&self, k: &Self::AccountId) -> Option<Self::Tokens>;

    /// Update balance for an account using function f.
    /// Its arg is previous balance or None if not found and
    /// return value is the new balance.
    fn update<F, E>(&mut self, acc: Self::AccountId, action_on_acc: F) -> Result<Self::Tokens, E>
    where
        F: FnMut(Option<&Self::Tokens>) -> Result<Self::Tokens, E>;
}

impl<AccountId, Tokens> BalancesStore for BTreeMap<AccountId, Tokens>
where
    AccountId: Eq + Clone + std::cmp::Ord,
    Tokens: TokensType,
{
    type AccountId = AccountId;
    type Tokens = Tokens;

    fn get_balance(&self, k: &Self::AccountId) -> Option<Self::Tokens> {
        self.get(k).cloned()
    }

    fn update<F, E>(&mut self, k: AccountId, mut f: F) -> Result<Self::Tokens, E>
    where
        F: FnMut(Option<&Self::Tokens>) -> Result<Self::Tokens, E>,
    {
        match self.entry(k) {
            Entry::Occupied(mut entry) => {
                let new_v = f(Some(entry.get()))?;
                if !new_v.is_zero() {
                    *entry.get_mut() = new_v.clone();
                } else {
                    entry.remove_entry();
                }
                Ok(new_v)
            }
            Entry::Vacant(entry) => {
                let new_v = f(None)?;
                if !new_v.is_zero() {
                    entry.insert(new_v.clone());
                }
                Ok(new_v)
            }
        }
    }
}

/// An error returned by `Balances` if the debit operation fails.
#[derive(Debug)]
pub enum BalanceError<Tokens> {
    /// An error indicating that the account doesn't hold enough funds for
    /// completing the transaction.
    InsufficientFunds { balance: Tokens },
}

/// Describes the state of users accounts at the tip of the chain
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Balances<S: BalancesStore> {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub store: S,
    #[serde(alias = "icpt_pool")]
    pub token_pool: S::Tokens,
}

impl<S> Default for Balances<S>
where
    S: Default + BalancesStore,
    S::Tokens: TokensType,
{
    fn default() -> Self {
        Self {
            store: Default::default(),
            token_pool: S::Tokens::max_value(),
        }
    }
}

impl<S> Balances<S>
where
    S: Default + BalancesStore,
    S::Tokens: TokensType,
{
    pub fn new() -> Self {
        Self {
            store: S::default(),
            token_pool: S::Tokens::max_value(),
        }
    }

    pub fn transfer(
        &mut self,
        from: &S::AccountId,
        to: &S::AccountId,
        amount: S::Tokens,
        fee: S::Tokens,
        fee_collector: Option<&S::AccountId>,
    ) -> Result<(), BalanceError<S::Tokens>> {
        let debit_amount = amount.checked_add(&fee).ok_or_else(|| {
            // No account can hold more than Tokens::max_value().
            let balance = self.account_balance(from);
            BalanceError::InsufficientFunds { balance }
        })?;
        self.debit(from, debit_amount)?;
        self.credit(to, amount);
        match fee_collector {
            None => {
                // NB. integer overflow is not possible here unless there is a
                // severe bug in the system: total amount of tokens in the
                // circulation cannot exceed Tokens::max_value().
                self.token_pool = self
                    .token_pool
                    .checked_add(&fee)
                    .expect("Overflow while adding the fee to the token pool");
            }
            Some(fee_collector) => self.credit(fee_collector, fee),
        }
        Ok(())
    }

    pub fn burn(
        &mut self,
        from: &S::AccountId,
        amount: S::Tokens,
    ) -> Result<(), BalanceError<S::Tokens>> {
        self.debit(from, amount.clone())?;
        self.token_pool = self
            .token_pool
            .checked_add(&amount)
            .expect("Overflow of the token pool while burning");
        Ok(())
    }

    pub fn mint(
        &mut self,
        to: &S::AccountId,
        amount: S::Tokens,
    ) -> Result<(), BalanceError<S::Tokens>> {
        self.token_pool = self
            .token_pool
            .checked_sub(&amount)
            .expect("total token supply exceeded");
        self.credit(to, amount);
        Ok(())
    }

    // Debiting an account will automatically remove it from the inner
    // `BalancesStore` if the balance reaches zero.
    pub fn debit(
        &mut self,
        from: &S::AccountId,
        amount: S::Tokens,
    ) -> Result<S::Tokens, BalanceError<S::Tokens>> {
        self.store.update(from.clone(), |prev| {
            let mut balance = match prev {
                Some(x) => x.clone(),
                None => {
                    return Err(BalanceError::InsufficientFunds {
                        balance: S::Tokens::zero(),
                    });
                }
            };
            if balance < amount {
                return Err(BalanceError::InsufficientFunds { balance });
            }

            balance = balance
                .checked_sub(&amount)
                .expect("Underflow while subtracting the amount from the balance");
            Ok(balance)
        })
    }

    // Crediting an account will automatically add it to the `inner` HashMap if
    // not already present.
    pub fn credit(&mut self, to: &S::AccountId, amount: S::Tokens) {
        self.store
            .update(
                to.clone(),
                |prev| -> Result<S::Tokens, std::convert::Infallible> {
                    // NB. credit cannot overflow unless there is a bug in the
                    // system: the total amount of tokens in the circulation cannot
                    // exceed Tokens::max_value(), so it's impossible to have more than
                    // Tokens::max_value() tokens on a single account.
                    Ok(amount
                        .checked_add(prev.unwrap_or(&S::Tokens::zero()))
                        .expect("bug: overflow in credit"))
                },
            )
            .unwrap();
    }

    pub fn account_balance(&self, account: &S::AccountId) -> S::Tokens {
        self.store
            .get_balance(account)
            .unwrap_or_else(S::Tokens::zero)
    }

    /// Returns the total quantity of Tokens that are "in existence" -- that
    /// is, excluding un-minted "potential" Tokens.
    pub fn total_supply(&self) -> S::Tokens {
        S::Tokens::max_value().checked_sub(&self.token_pool).expect(
            "It is expected that the token_pool is always smaller than \
            or equal to Tokens::max_value(), yet subtracting it lead to underflow",
        )
    }
}
