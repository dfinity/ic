use crate::timestamp::TimeStamp;
use crate::tokens::Tokens;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BinaryHeap};
use std::marker::PhantomData;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsufficientAllowance(pub Tokens);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredApproval {
    pub now: TimeStamp,
}

pub trait Approvals {
    type AccountId;
    type SpenderId;

    /// Returns the current spender's allowance for the account.
    fn allowance(
        &self,
        account: &Self::AccountId,
        spender: &Self::SpenderId,
        now: TimeStamp,
    ) -> Allowance;

    /// Increases the spender's allowance for the account by the specified amount.
    fn approve(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::SpenderId,
        amount: Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<Tokens, ExpiredApproval>;

    /// Decreases the spender's allowance for the account by the specified amount.
    ///
    /// If the total allowance goes negative, the table resets it to zero.
    fn decrease_allowance(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::SpenderId,
        by: Tokens,
        new_expiration: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<Tokens, ExpiredApproval>;

    /// Consumes amount from the spender's allowance for the account.
    ///
    /// This method behaves like [decrease_amount] but bails out if the
    /// allowance goes negative.
    fn use_allowance(
        &mut self,
        account: &Self::AccountId,
        spender: &Self::SpenderId,
        amount: Tokens,
        now: TimeStamp,
    ) -> Result<Tokens, InsufficientAllowance>;
}

#[allow(clippy::len_without_is_empty)]
pub trait PrunableApprovals {
    fn len(&self) -> usize;

    fn prune(&mut self, now: TimeStamp, limit: usize) -> usize;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowance {
    pub amount: Tokens,
    pub expires_at: Option<TimeStamp>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AllowanceTable<K, AccountId, SpenderId>
where
    K: Ord,
{
    allowances: BTreeMap<K, Allowance>,
    expiration_queue: BinaryHeap<Reverse<(TimeStamp, K)>>,
    #[serde(skip)]
    #[serde(default)]
    _marker: PhantomData<fn(&AccountId, &SpenderId) -> K>,
}

impl<K: Ord, AccountId, SpenderId> Default for AllowanceTable<K, AccountId, SpenderId> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, AccountId, SpenderId> AllowanceTable<K, AccountId, SpenderId>
where
    K: Ord,
{
    pub fn new() -> Self {
        Self {
            allowances: BTreeMap::new(),
            expiration_queue: BinaryHeap::new(),
            _marker: PhantomData,
        }
    }
}

impl<K, AccountId, SpenderId> Approvals for AllowanceTable<K, AccountId, SpenderId>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a SpenderId)> + Clone,
{
    type AccountId = AccountId;
    type SpenderId = SpenderId;

    fn allowance(&self, account: &AccountId, spender: &SpenderId, now: TimeStamp) -> Allowance {
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
        spender: &SpenderId,
        amount: Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<Tokens, ExpiredApproval> {
        if expires_at.unwrap_or_else(remote_future) <= now {
            return Err(ExpiredApproval { now });
        }

        let key = K::from((account, spender));

        match self.allowances.entry(key.clone()) {
            Entry::Vacant(e) => {
                if let Some(expires_at) = expires_at {
                    self.expiration_queue.push(Reverse((expires_at, key)));
                }
                e.insert(Allowance { amount, expires_at });
                Ok(amount)
            }
            Entry::Occupied(mut e) => {
                let old_expiration = if e.get().expires_at.unwrap_or_else(remote_future) <= now {
                    // Overwrite the allowance if the previous approval expired.
                    let allowance = e.get_mut();
                    allowance.amount = amount;
                    std::mem::replace(&mut allowance.expires_at, expires_at)
                } else {
                    let allowance = e.get_mut();
                    allowance.amount = allowance.amount.saturating_add(amount);
                    std::mem::replace(&mut allowance.expires_at, expires_at)
                };

                if expires_at != old_expiration {
                    if let Some(expires_at) = expires_at {
                        self.expiration_queue.push(Reverse((expires_at, key)));
                    }
                }
                Ok(e.get().amount)
            }
        }
    }

    fn decrease_allowance(
        &mut self,
        account: &AccountId,
        spender: &SpenderId,
        amount: Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<Tokens, ExpiredApproval> {
        if expires_at.unwrap_or_else(remote_future) <= now {
            return Err(ExpiredApproval { now });
        }

        let key = K::from((account, spender));

        match self.allowances.entry(key.clone()) {
            Entry::Vacant(_) => Ok(Tokens::ZERO),
            Entry::Occupied(mut e) => {
                if e.get().expires_at.unwrap_or_else(remote_future) <= now {
                    // The approval expired, removing it.
                    e.remove();
                    return Ok(Tokens::ZERO);
                } else {
                    let allowance = e.get_mut();
                    allowance.amount = allowance.amount.saturating_sub(amount);
                    let old_expiration = std::mem::replace(&mut allowance.expires_at, expires_at);

                    if allowance.amount == Tokens::ZERO {
                        e.remove();
                        return Ok(Tokens::ZERO);
                    }

                    if expires_at != old_expiration {
                        if let Some(expires_at) = expires_at {
                            self.expiration_queue.push(Reverse((expires_at, key)));
                        }
                    }
                };

                Ok(e.get().amount)
            }
        }
    }

    fn use_allowance(
        &mut self,
        account: &AccountId,
        spender: &SpenderId,
        amount: Tokens,
        now: TimeStamp,
    ) -> Result<Tokens, InsufficientAllowance> {
        let key = K::from((account, spender));

        match self.allowances.entry(key) {
            Entry::Vacant(_) => Err(InsufficientAllowance(Tokens::ZERO)),
            Entry::Occupied(mut e) => {
                if e.get().expires_at.unwrap_or_else(remote_future) <= now {
                    Err(InsufficientAllowance(Tokens::ZERO))
                } else {
                    let allowance = e.get_mut();
                    if allowance.amount < amount {
                        return Err(InsufficientAllowance(allowance.amount));
                    }
                    allowance.amount -= amount;
                    let rest = allowance.amount;
                    if rest == Tokens::ZERO {
                        e.remove();
                    }
                    Ok(rest)
                }
            }
        }
    }
}

impl<K, AccountId, SpenderId> PrunableApprovals for AllowanceTable<K, AccountId, SpenderId>
where
    K: Ord,
{
    fn prune(&mut self, now: TimeStamp, limit: usize) -> usize {
        let mut pruned = 0;
        for _ in 0..limit {
            match self.expiration_queue.peek() {
                Some(Reverse((ts, _key))) => {
                    println!("{:?}", ts);
                    if *ts > now {
                        return pruned;
                    }
                }
                None => {
                    return pruned;
                }
            }
            if let Some(Reverse((_, key))) = self.expiration_queue.pop() {
                if let Some(allowance) = self.allowances.get(&key) {
                    if allowance.expires_at.unwrap_or_else(remote_future) <= now {
                        self.allowances.remove(&key);
                        pruned += 1;
                    }
                }
            }
        }
        pruned
    }

    fn len(&self) -> usize {
        self.allowances.len()
    }
}

fn remote_future() -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(u64::MAX)
}
