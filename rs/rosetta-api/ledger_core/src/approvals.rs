use crate::timestamp::TimeStamp;
use crate::tokens::{CheckedSub, TokensType, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

pub trait AllowancesData {
    type AccountId: Ord + Clone;
    type Tokens: TokensType;

    fn get_allowance(
        &self,
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) -> Option<Allowance<Self::Tokens>>;

    fn set_allowance(
        &mut self,
        account_spender: (&Self::AccountId, &Self::AccountId),
        allowance: &Allowance<Self::Tokens>,
    );

    fn remove_allowance(&mut self, account_spender: (&Self::AccountId, &Self::AccountId));

    fn insert_expiry(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    );

    fn remove_expiry(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    );

    fn insert_arrival(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    );

    fn remove_arrival(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    );

    fn first_expiry(&self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))>;

    fn oldest_arrivals(&self, n: usize) -> Vec<(Self::AccountId, Self::AccountId)>;

    fn len_allowances(&self) -> usize;

    fn len_expirations(&self) -> usize;

    fn len_arrivals(&self) -> usize;
}

#[derive(Serialize, Deserialize, Debug)]
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
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) -> Option<Allowance<Self::Tokens>> {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.allowances.get(&asp).cloned()
    }

    fn set_allowance(
        &mut self,
        account_spender: (&Self::AccountId, &Self::AccountId),
        allowance: &Allowance<Self::Tokens>,
    ) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.allowances.insert(asp, allowance.clone());
    }

    fn remove_allowance(&mut self, account_spender: (&Self::AccountId, &Self::AccountId)) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.allowances.remove(&asp);
    }

    fn insert_expiry(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.expiration_queue.insert((*timestamp, asp));
    }

    fn remove_expiry(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.expiration_queue.remove(&(*timestamp, asp));
    }

    fn insert_arrival(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.arrival_queue.insert((*timestamp, asp));
    }

    fn remove_arrival(
        &mut self,
        timestamp: &TimeStamp,
        account_spender: (&Self::AccountId, &Self::AccountId),
    ) {
        let asp = (account_spender.0.clone(), account_spender.1.clone());
        self.arrival_queue.remove(&(*timestamp, asp));
    }

    fn first_expiry(&self) -> Option<(TimeStamp, (Self::AccountId, Self::AccountId))> {
        self.expiration_queue.first().cloned()
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct AllowanceTable<S: AllowancesData> {
    allowances_data: S,
}

impl<S> Default for AllowanceTable<S>
where
    S: Default + AllowancesData,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> AllowanceTable<S>
where
    S: Default + AllowancesData,
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

    pub fn allowance(
        &self,
        account: &S::AccountId,
        spender: &S::AccountId,
        now: TimeStamp,
    ) -> Allowance<S::Tokens> {
        match self.allowances_data.get_allowance((account, spender)) {
            Some(allowance) if allowance.expires_at.unwrap_or_else(remote_future) > now => {
                allowance.clone()
            }
            _ => Allowance::default(),
        }
    }

    pub fn approve(
        &mut self,
        account: &S::AccountId,
        spender: &S::AccountId,
        amount: S::Tokens,
        expires_at: Option<TimeStamp>,
        now: TimeStamp,
        expected_allowance: Option<S::Tokens>,
    ) -> Result<S::Tokens, ApproveError<S::Tokens>> {
        self.with_postconditions_check(|table| {
            if account == spender {
                return Err(ApproveError::SelfApproval);
            }

            if expires_at.unwrap_or_else(remote_future) <= now {
                return Err(ApproveError::ExpiredApproval { now });
            }

            let key = (account, spender);

            match table.allowances_data.get_allowance(key.clone()) {
                None => {
                    if let Some(expected_allowance) = expected_allowance {
                        if !expected_allowance.is_zero() {
                            return Err(ApproveError::AllowanceChanged {
                                current_allowance: S::Tokens::zero(),
                            });
                        }
                    }
                    if amount == S::Tokens::zero() {
                        return Ok(amount);
                    }
                    if let Some(expires_at) = expires_at {
                        table
                            .allowances_data
                            .insert_expiry(&expires_at, key.clone());
                    }
                    table.allowances_data.insert_arrival(&now, key.clone());
                    table.allowances_data.set_allowance(
                        key,
                        &Allowance {
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
                                S::Tokens::zero()
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
                        .remove_arrival(&old_allowance.arrived_at, key.clone());
                    if amount == S::Tokens::zero() {
                        if let Some(expires_at) = old_allowance.expires_at {
                            table
                                .allowances_data
                                .remove_expiry(&expires_at, key.clone());
                        }
                        table.allowances_data.remove_allowance(key);
                        return Ok(amount);
                    }
                    table.allowances_data.insert_arrival(&now, key.clone());
                    let new_allowance = Allowance {
                        amount: amount.clone(),
                        expires_at,
                        arrived_at: now,
                    };

                    if expires_at != old_allowance.expires_at {
                        if let Some(old_expiration) = old_allowance.expires_at {
                            table
                                .allowances_data
                                .remove_expiry(&old_expiration, key.clone());
                        }
                        if let Some(expires_at) = expires_at {
                            table.allowances_data.insert_expiry(&expires_at, key);
                        }
                    }
                    table.allowances_data.set_allowance(key, &new_allowance);
                    Ok(amount)
                }
            }
        })
    }

    pub fn get_num_approvals(&self) -> usize {
        self.allowances_data.len_allowances()
    }

    pub fn use_allowance(
        &mut self,
        account: &S::AccountId,
        spender: &S::AccountId,
        amount: S::Tokens,
        now: TimeStamp,
    ) -> Result<S::Tokens, InsufficientAllowance<S::Tokens>> {
        self.with_postconditions_check(|table| {
            let key = (account, spender);

            match table.allowances_data.get_allowance(key.clone()) {
                None => Err(InsufficientAllowance(S::Tokens::zero())),
                Some(old_allowance) => {
                    if old_allowance.expires_at.unwrap_or_else(remote_future) <= now {
                        Err(InsufficientAllowance(S::Tokens::zero()))
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
                                table
                                    .allowances_data
                                    .remove_expiry(&expires_at, key.clone());
                            }
                            table
                                .allowances_data
                                .remove_arrival(&old_allowance.arrived_at, key.clone());
                            table.allowances_data.remove_allowance(key);
                        } else {
                            table.allowances_data.set_allowance(key, &new_allowance);
                        }
                        Ok(rest)
                    }
                }
            }
        })
    }

    pub fn select_approvals_to_trim(&self, n: usize) -> Vec<(S::AccountId, S::AccountId)> {
        self.allowances_data.oldest_arrivals(n)
    }

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
                if let Some((_, (account, spender))) = table.remove_first_expiry() {
                    let key = (&account, &spender);
                    if let Some(allowance) = table.allowances_data.get_allowance(key) {
                        if allowance.expires_at.unwrap_or_else(remote_future) <= now {
                            table
                                .allowances_data
                                .remove_arrival(&allowance.arrived_at, key.clone());
                            table.allowances_data.remove_allowance(key);
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

    fn remove_first_expiry(&mut self) -> Option<(TimeStamp, (S::AccountId, S::AccountId))> {
        let expiry = self.allowances_data.first_expiry();
        if let Some((timestamp, (account, spender))) = expiry {
            self.allowances_data
                .remove_expiry(&timestamp, (&account, &spender));
            return Some((timestamp, (account, spender)));
        }
        None
    }
}

fn remote_future() -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(u64::MAX)
}
