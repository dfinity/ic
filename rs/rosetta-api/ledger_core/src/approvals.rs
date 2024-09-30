use crate::timestamp::TimeStamp;
use crate::tokens::{CheckedSub, TokensType, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct InsufficientAllowance<Tokens>(pub Tokens);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ApproveError<Tokens> {
    AllowanceChanged { current_allowance: Tokens },
    ExpiredApproval { now: TimeStamp },
    SelfApproval,
}

// The implementations of this trait should store the allowance data
// for (account, spender) pairs and the expirations and arrivals
// of the allowances. The functions of the trait are meant to be simple
// `insert` and `remove` type functions that can be implemented with
// regular BTreeMaps or using the stable structures.
pub trait AllowancesData {
    type AccountId;
    type Tokens;

    fn get_allowance(
        &self,
        account_spender: &(Self::AccountId, Self::AccountId),
    ) -> Option<Allowance<Self::Tokens>>;

    fn set_allowance(
        &mut self,
        account_spender: (Self::AccountId, Self::AccountId),
        allowance: Allowance<Self::Tokens>,
    );

    fn remove_allowance(&mut self, account_spender: &(Self::AccountId, Self::AccountId));

    fn insert_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    );

    fn remove_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    );

    fn insert_arrival(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    );

    fn remove_arrival(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    );

    #[allow(clippy::type_complexity)]
    fn first_expiry(&self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))>;

    #[allow(clippy::type_complexity)]
    fn pop_first_expiry(&mut self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))>;

    fn oldest_arrivals(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)>;

    fn len_allowances(&self) -> usize;

    fn len_expirations(&self) -> usize;

    fn len_arrivals(&self) -> usize;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HeapAllowancesData<AccountId, Tokens>
where
    AccountId: Ord,
{
    allowances: BTreeMap<(AccountId, AccountId), Allowance<Tokens>>,
    expiration_queue: BTreeSet<(TimeStamp, (AccountId, AccountId))>,
    #[serde(default = "Default::default")]
    arrival_queue: BTreeSet<(TimeStamp, (AccountId, AccountId))>,
}
impl<AccountId, Tokens> Default for HeapAllowancesData<AccountId, Tokens>
where
    AccountId: Ord,
{
    fn default() -> Self {
        Self {
            allowances: BTreeMap::new(),
            expiration_queue: BTreeSet::new(),
            arrival_queue: BTreeSet::new(),
        }
    }
}

impl<AccountId, Tokens> AllowancesData for HeapAllowancesData<AccountId, Tokens>
where
    AccountId: Ord + Clone,
    Tokens: TokensType,
{
    type AccountId = AccountId;
    type Tokens = Tokens;

    fn get_allowance(
        &self,
        account_spender: &(Self::AccountId, Self::AccountId),
    ) -> Option<Allowance<Self::Tokens>> {
        self.allowances.get(account_spender).cloned()
    }

    fn set_allowance(
        &mut self,
        account_spender: (Self::AccountId, Self::AccountId),
        allowance: Allowance<Self::Tokens>,
    ) {
        self.allowances.insert(account_spender, allowance);
    }

    fn remove_allowance(&mut self, account_spender: &(Self::AccountId, Self::AccountId)) {
        self.allowances.remove(account_spender);
    }

    fn insert_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        self.expiration_queue.insert((timestamp, account_spender));
    }

    fn remove_expiry(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        self.expiration_queue.remove(&(timestamp, account_spender));
    }

    fn insert_arrival(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        self.arrival_queue.insert((timestamp, account_spender));
    }

    fn remove_arrival(
        &mut self,
        timestamp: TimeStamp,
        account_spender: (Self::AccountId, Self::AccountId),
    ) {
        self.arrival_queue.remove(&(timestamp, account_spender));
    }

    fn first_expiry(&self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))> {
        self.expiration_queue.first().cloned()
    }

    fn pop_first_expiry(&mut self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))> {
        self.expiration_queue.pop_first()
    }

    fn oldest_arrivals(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)> {
        let mut result = vec![];
        for (_t, key) in &self.arrival_queue {
            if result.len() >= n {
                break;
            }
            result.push(key.clone());
        }
        result
    }

    fn len_allowances(&self) -> usize {
        self.allowances.len()
    }

    fn len_expirations(&self) -> usize {
        self.expiration_queue.len()
    }

    fn len_arrivals(&self) -> usize {
        self.arrival_queue.len()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AllowanceTable<AD: AllowancesData> {
    allowances_data: AD,
}

impl<AD> Default for AllowanceTable<AD>
where
    AD: Default + AllowancesData,
    AD::AccountId: Ord + Clone,
    AD::Tokens: TokensType,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<AD> AllowanceTable<AD>
where
    AD: Default + AllowancesData,
    AD::AccountId: Ord + Clone,
    AD::Tokens: TokensType,
{
    pub fn new() -> Self {
        Self {
            allowances_data: Default::default(),
        }
    }

    fn check_postconditions(&self) {
        debug_assert!(
            self.allowances_data.len_expirations() <= self.allowances_data.len_allowances(),
            "expiration queue length ({}) larger than allowances length ({})",
            self.allowances_data.len_expirations(),
            self.allowances_data.len_allowances()
        );
        debug_assert!(
            self.allowances_data.len_arrivals() == self.allowances_data.len_allowances(),
            "arrival_queue length ({}) should be equal to allowances length ({})",
            self.allowances_data.len_arrivals(),
            self.allowances_data.len_allowances()
        );
    }

    fn with_postconditions_check<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let r = f(self);
        self.check_postconditions();
        r
    }

    /// Returns the current spender's allowance for the account.
    pub fn allowance(
        &self,
        account: &AD::AccountId,
        spender: &AD::AccountId,
        now: TimeStamp,
    ) -> Allowance<AD::Tokens> {
        match self
            .allowances_data
            .get_allowance(&(account.clone(), spender.clone()))
        {
            Some(allowance) if allowance.expires_at.unwrap_or_else(remote_future) > now => {
                allowance.clone()
            }
            _ => Allowance::default(),
        }
    }

    /// Changes the spender's allowance for the account to the specified amount and expiration.
    pub fn approve(
        &mut self,
        account: &AD::AccountId,
        spender: &AD::AccountId,
        amount: AD::Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
        expected_allowance: Option<AD::Tokens>,
    ) -> Result<AD::Tokens, ApproveError<AD::Tokens>> {
        self.with_postconditions_check(|table| {
            if account == spender {
                return Err(ApproveError::SelfApproval);
            }

            if expires_at.unwrap_or_else(remote_future) <= now {
                return Err(ApproveError::ExpiredApproval { now });
            }

            let key = (account.clone(), spender.clone());

            match table.allowances_data.get_allowance(&key) {
                None => {
                    if let Some(expected_allowance) = expected_allowance {
                        if !expected_allowance.is_zero() {
                            return Err(ApproveError::AllowanceChanged {
                                current_allowance: AD::Tokens::zero(),
                            });
                        }
                    }
                    if amount == AD::Tokens::zero() {
                        return Ok(amount);
                    }
                    if let Some(expires_at) = expires_at {
                        table.allowances_data.insert_expiry(expires_at, key.clone());
                    }
                    table.allowances_data.insert_arrival(now, key.clone());
                    table.allowances_data.set_allowance(
                        key,
                        Allowance {
                            amount: amount.clone(),
                            expires_at,
                            arrived_at: now,
                        },
                    );
                    Ok(amount)
                }
                Some(old_allowance) => {
                    if let Some(expected_allowance) = expected_allowance {
                        let current_allowance = if let Some(expires_at) = old_allowance.expires_at {
                            if expires_at <= now {
                                AD::Tokens::zero()
                            } else {
                                old_allowance.amount.clone()
                            }
                        } else {
                            old_allowance.amount.clone()
                        };
                        if expected_allowance != current_allowance {
                            return Err(ApproveError::AllowanceChanged { current_allowance });
                        }
                    }
                    table
                        .allowances_data
                        .remove_arrival(old_allowance.arrived_at, key.clone());
                    if amount == AD::Tokens::zero() {
                        if let Some(expires_at) = old_allowance.expires_at {
                            table.allowances_data.remove_expiry(expires_at, key.clone());
                        }
                        table.allowances_data.remove_allowance(&key);
                        return Ok(amount);
                    }
                    table.allowances_data.insert_arrival(now, key.clone());
                    table.allowances_data.set_allowance(
                        key.clone(),
                        Allowance {
                            amount: amount.clone(),
                            expires_at,
                            arrived_at: now,
                        },
                    );

                    if expires_at != old_allowance.expires_at {
                        if let Some(old_expiration) = old_allowance.expires_at {
                            table
                                .allowances_data
                                .remove_expiry(old_expiration, key.clone());
                        }
                        if let Some(expires_at) = expires_at {
                            table.allowances_data.insert_expiry(expires_at, key);
                        }
                    }
                    Ok(amount)
                }
            }
        })
    }

    /// Returns the number of approvals.
    pub fn get_num_approvals(&self) -> usize {
        self.allowances_data.len_allowances()
    }

    /// Consumes amount from the spender's allowance for the account.
    /// Returns an error if the allowance would go negative.
    pub fn use_allowance(
        &mut self,
        account: &AD::AccountId,
        spender: &AD::AccountId,
        amount: AD::Tokens,
        now: TimeStamp,
    ) -> Result<AD::Tokens, InsufficientAllowance<AD::Tokens>> {
        self.with_postconditions_check(|table| {
            let key = (account.clone(), spender.clone());

            match table.allowances_data.get_allowance(&key) {
                None => Err(InsufficientAllowance(AD::Tokens::zero())),
                Some(old_allowance) => {
                    if old_allowance.expires_at.unwrap_or_else(remote_future) <= now {
                        Err(InsufficientAllowance(AD::Tokens::zero()))
                    } else {
                        if old_allowance.amount < amount {
                            return Err(InsufficientAllowance(old_allowance.amount));
                        }
                        let mut new_allowance = old_allowance.clone();
                        new_allowance.amount = old_allowance
                            .amount
                            .checked_sub(&amount)
                            .expect("Underflow when using allowance");
                        let rest = new_allowance.amount.clone();
                        if rest.is_zero() {
                            if let Some(expires_at) = old_allowance.expires_at {
                                table.allowances_data.remove_expiry(expires_at, key.clone());
                            }
                            table
                                .allowances_data
                                .remove_arrival(old_allowance.arrived_at, key.clone());
                            table.allowances_data.remove_allowance(&key);
                        } else {
                            table.allowances_data.set_allowance(key, new_allowance);
                        }
                        Ok(rest)
                    }
                }
            }
        })
    }

    /// Returns a vector of pairs (account, spender) of size min(n, approvals_size)
    /// that represent approvals selected for trimming.
    pub fn select_approvals_to_trim(&self, n: usize) -> Vec<(AD::AccountId, AD::AccountId)> {
        self.allowances_data.oldest_arrivals(n)
    }

    /// Prunes allowances that are expired, removes at most `limit` allowances.
    pub fn prune(&mut self, now: TimeStamp, limit: usize) -> usize {
        self.with_postconditions_check(|table| {
            let mut pruned = 0;
            for _ in 0..limit {
                match table.allowances_data.first_expiry() {
                    Some((ts, _key)) => {
                        if ts > now {
                            return pruned;
                        }
                    }
                    None => {
                        return pruned;
                    }
                }
                if let Some((_, (account, spender))) = table.allowances_data.pop_first_expiry() {
                    let key = (account, spender);
                    if let Some(allowance) = table.allowances_data.get_allowance(&key) {
                        if allowance.expires_at.unwrap_or_else(remote_future) <= now {
                            table
                                .allowances_data
                                .remove_arrival(allowance.arrived_at, key.clone());
                            table.allowances_data.remove_allowance(&key);
                            pruned += 1;
                        }
                    }
                }
            }
            pruned
        })
    }

    pub fn len(&self) -> usize {
        self.allowances_data.len_allowances()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn remote_future() -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(u64::MAX)
}
