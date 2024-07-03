use crate::timestamp::TimeStamp;
use crate::tokens::{TokensType, Zero};
use candid::Nat;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::marker::PhantomData;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsufficientAllowance<Tokens>(pub Tokens);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApproveError<Tokens> {
    AllowanceChanged { current_allowance: Tokens },
    ExpiredApproval { now: TimeStamp },
    SelfApproval,
}

pub trait Approvals {
    type AccountId;
    type Tokens;

    /// Returns the current spender's allowance for the account.
    fn allowance(
        &self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        now: TimeStamp,
    ) -> Allowance<Self::Tokens>;

    /// Increases the spender's allowance for the account by the specified amount.
    fn approve(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        amount: Self::Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
        expected_allowance: Option<Self::Tokens>,
    ) -> Result<Self::Tokens, ApproveError<Self::Tokens>>;

    /// Returns the number of approvals.
    fn get_num_approvals(&self) -> usize;

    /// Consumes amount from the spender's allowance for the account.
    ///
    /// This method behaves like [decrease_amount] but bails out if the
    /// allowance goes negative.
    fn use_allowance(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::AccountId,
        amount: Self::Tokens,
        now: TimeStamp,
    ) -> Result<Self::Tokens, InsufficientAllowance<Self::Tokens>>;

    /// Returns a vector of pairs (account, spender) of size min(n, approvals_size)
    /// that represent approvals selected for trimming.
    fn select_approvals_to_trim(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)>;
}

#[allow(clippy::len_without_is_empty)]
pub trait PrunableApprovals {
    fn len(&self) -> usize;

    fn prune(&mut self, now: TimeStamp, limit: usize) -> usize;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowance<Tokens> {
    pub amount: Tokens,
    pub expires_at: Option<TimeStamp>,
    pub arrived_at: TimeStamp,
}

impl<Tokens: Zero> Default for Allowance<Tokens> {
    fn default() -> Self {
        Self {
            amount: Tokens::zero(),
            expires_at: Default::default(),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        }
    }
}

impl<Tokens: Clone + Into<Nat> + TryFrom<Nat, Error = String>> Storable for Allowance<Tokens> {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buffer = vec![];
        let amount: Nat = self.amount.clone().into();
        amount
            .encode(&mut buffer)
            .expect("Unable to serialize amount");
        buffer.extend(self.arrived_at.as_nanos_since_unix_epoch().to_le_bytes());
        if let Some(expires_at) = self.expires_at {
            buffer.extend(expires_at.as_nanos_since_unix_epoch().to_le_bytes());
        }
        Cow::Owned(buffer)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut cursor = Cursor::new(bytes.into_owned());
        let amount = Nat::decode(&mut cursor).expect("Unable to deserialize amount");
        let amount = Tokens::try_from(amount).expect("Unable to deserialize amount");
        let mut arrived_at_bytes = [0u8; 8];
        cursor
            .read_exact(&mut arrived_at_bytes)
            .expect("Unable to read arrived_at bytes");
        let arrived_at =
            TimeStamp::from_nanos_since_unix_epoch(u64::from_le_bytes(arrived_at_bytes));
        let mut expires_at_bytes = [0u8; 8];
        let expires_at = match cursor.read_exact(&mut expires_at_bytes) {
            Ok(()) => Some(TimeStamp::from_nanos_since_unix_epoch(u64::from_le_bytes(
                expires_at_bytes,
            ))),
            _ => None,
        };
        Self {
            amount,
            arrived_at,
            expires_at,
        }
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AllowanceTable<K, AccountId, Tokens>
where
    K: Ord,
{
    pub allowances: BTreeMap<K, Allowance<Tokens>>,
    pub expiration_queue: BTreeSet<(TimeStamp, K)>,
    #[serde(default = "Default::default")]
    pub arrival_queue: BTreeSet<(TimeStamp, K)>,
    #[serde(skip)]
    #[serde(default)]
    _marker: PhantomData<fn(&AccountId, &AccountId) -> K>,
}

impl<K: Ord, AccountId, Tokens> Default for AllowanceTable<K, AccountId, Tokens> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, AccountId, Tokens> AllowanceTable<K, AccountId, Tokens>
where
    K: Ord,
{
    pub fn new() -> Self {
        Self {
            allowances: BTreeMap::new(),
            expiration_queue: BTreeSet::new(),
            arrival_queue: BTreeSet::new(),
            _marker: PhantomData,
        }
    }

    fn check_postconditions(&self) {
        debug_assert!(
            self.expiration_queue.len() <= self.allowances.len(),
            "expiration queue length ({}) larger than allowances length ({})",
            self.expiration_queue.len(),
            self.allowances.len()
        );
        debug_assert!(
            self.arrival_queue.len() == self.allowances.len(),
            "arrival_queue length ({}) should be equal to allowances length ({})",
            self.arrival_queue.len(),
            self.allowances.len()
        );
    }

    fn with_postconditions_check<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let r = f(self);
        self.check_postconditions();
        r
    }
}

impl<K, AccountId, Tokens> Approvals for AllowanceTable<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone,
    K: Into<(AccountId, AccountId)>,
    AccountId: std::cmp::PartialEq,
    Tokens: TokensType,
{
    type AccountId = AccountId;
    type Tokens = Tokens;

    fn allowance(
        &self,
        account: &AccountId,
        spender: &AccountId,
        now: TimeStamp,
    ) -> Allowance<Tokens> {
        let key = K::from((account, spender));
        match self.allowances.get(&key) {
            Some(allowance) if allowance.expires_at.unwrap_or_else(remote_future) > now => {
                allowance.clone()
            }
            _ => Allowance::default(),
        }
    }

    fn approve(
        &mut self,
        account: &AccountId,
        spender: &AccountId,
        amount: Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
        expected_allowance: Option<Tokens>,
    ) -> Result<Tokens, ApproveError<Tokens>> {
        self.with_postconditions_check(|table| {
            if account == spender {
                return Err(ApproveError::SelfApproval);
            }

            if expires_at.unwrap_or_else(remote_future) <= now {
                return Err(ApproveError::ExpiredApproval { now });
            }

            let key = K::from((account, spender));

            match table.allowances.entry(key.clone()) {
                Entry::Vacant(e) => {
                    if let Some(expected_allowance) = expected_allowance {
                        if !expected_allowance.is_zero() {
                            return Err(ApproveError::AllowanceChanged {
                                current_allowance: Tokens::zero(),
                            });
                        }
                    }
                    if amount == Tokens::zero() {
                        return Ok(amount);
                    }
                    if let Some(expires_at) = expires_at {
                        table.expiration_queue.insert((expires_at, key.clone()));
                    }
                    table.arrival_queue.insert((now, key));
                    e.insert(Allowance {
                        amount: amount.clone(),
                        expires_at,
                        arrived_at: now,
                    });
                    Ok(amount)
                }
                Entry::Occupied(mut e) => {
                    let allowance = e.get_mut();
                    if let Some(expected_allowance) = expected_allowance {
                        let current_allowance = if let Some(expires_at) = allowance.expires_at {
                            if expires_at <= now {
                                Tokens::zero()
                            } else {
                                allowance.amount.clone()
                            }
                        } else {
                            allowance.amount.clone()
                        };
                        if expected_allowance != current_allowance {
                            return Err(ApproveError::AllowanceChanged { current_allowance });
                        }
                    }
                    table
                        .arrival_queue
                        .remove(&(allowance.arrived_at, key.clone()));
                    if amount == Tokens::zero() {
                        if let Some(expires_at) = e.get().expires_at {
                            table.expiration_queue.remove(&(expires_at, key.clone()));
                        }
                        e.remove();
                        return Ok(amount);
                    }
                    table.arrival_queue.insert((now, key.clone()));
                    allowance.amount = amount;
                    allowance.arrived_at = now;
                    let old_expiration = std::mem::replace(&mut allowance.expires_at, expires_at);

                    if expires_at != old_expiration {
                        if let Some(old_expiration) = old_expiration {
                            table
                                .expiration_queue
                                .remove(&(old_expiration, key.clone()));
                        }
                        if let Some(expires_at) = expires_at {
                            table.expiration_queue.insert((expires_at, key));
                        }
                    }
                    Ok(e.get().amount.clone())
                }
            }
        })
    }

    fn get_num_approvals(&self) -> usize {
        self.allowances.len()
    }

    fn use_allowance(
        &mut self,
        account: &AccountId,
        spender: &AccountId,
        amount: Tokens,
        now: TimeStamp,
    ) -> Result<Tokens, InsufficientAllowance<Tokens>> {
        self.with_postconditions_check(|table| {
            let key = K::from((account, spender));

            match table.allowances.entry(key.clone()) {
                Entry::Vacant(_) => Err(InsufficientAllowance(Tokens::zero())),
                Entry::Occupied(mut e) => {
                    if e.get().expires_at.unwrap_or_else(remote_future) <= now {
                        Err(InsufficientAllowance(Tokens::zero()))
                    } else {
                        let allowance = e.get_mut();
                        if allowance.amount < amount {
                            return Err(InsufficientAllowance(allowance.amount.clone()));
                        }
                        allowance.amount = allowance
                            .amount
                            .checked_sub(&amount)
                            .expect("Underflow when using allowance");
                        let rest = allowance.amount.clone();
                        if rest.is_zero() {
                            if let Some(expires_at) = e.get().expires_at {
                                table.expiration_queue.remove(&(expires_at, key.clone()));
                            }
                            table.arrival_queue.remove(&(e.get().arrived_at, key));
                            e.remove();
                        }
                        Ok(rest)
                    }
                }
            }
        })
    }

    fn select_approvals_to_trim(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)> {
        let mut result = vec![];
        for (_expiration, key) in &self.arrival_queue {
            if result.len() >= n {
                break;
            }
            result.push(key.clone().into());
        }
        result
    }
}

impl<K, AccountId, Tokens> PrunableApprovals for AllowanceTable<K, AccountId, Tokens>
where
    K: Ord + Clone,
{
    fn prune(&mut self, now: TimeStamp, limit: usize) -> usize {
        self.with_postconditions_check(|table| {
            let mut pruned = 0;
            for _ in 0..limit {
                match table.expiration_queue.first() {
                    Some((ts, _key)) => {
                        if *ts > now {
                            return pruned;
                        }
                    }
                    None => {
                        return pruned;
                    }
                }
                if let Some((_, key)) = table.expiration_queue.pop_first() {
                    if let Some(allowance) = table.allowances.get(&key) {
                        if allowance.expires_at.unwrap_or_else(remote_future) <= now {
                            table
                                .arrival_queue
                                .remove(&(allowance.arrived_at, key.clone()));
                            table.allowances.remove(&key);
                            pruned += 1;
                        }
                    }
                }
            }
            pruned
        })
    }

    fn len(&self) -> usize {
        self.allowances.len()
    }
}

pub fn remote_future() -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(u64::MAX)
}
