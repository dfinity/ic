use candid::{CandidType, Principal};
use ic_agent::identity::Identity;
use ic_base_types::CanisterId;
use ic_icrc1::Operation;
use ic_icrc1_test_utils::{ArgWithCaller, LedgerEndpointArg};
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::TokensType;
use ic_ledger_suite_state_machine_helpers::{
    AllowanceProvider, BalanceProvider, get_all_ledger_and_archive_blocks, parse_metric,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Instant, SystemTime};

#[cfg(test)]
mod tests;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ApprovalKey<AccountId>(AccountId, AccountId);

impl<AccountId: Clone> From<(&AccountId, &AccountId)> for ApprovalKey<AccountId> {
    fn from((account, spender): (&AccountId, &AccountId)) -> Self {
        Self(account.clone(), spender.clone())
    }
}

impl<AccountId> From<ApprovalKey<AccountId>> for (AccountId, AccountId) {
    fn from(key: ApprovalKey<AccountId>) -> Self {
        (key.0, key.1)
    }
}

pub trait ConsumableBlock {
    fn creation_timestamp(&self) -> u64;
}

pub trait BlockConsumer<BlockType> {
    fn consume_blocks(&mut self, block: &[BlockType]);
}

impl<Token: TokensType> ConsumableBlock for ic_icrc1::Block<Token> {
    fn creation_timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl ConsumableBlock for icp_ledger::Block {
    fn creation_timestamp(&self) -> u64 {
        self.timestamp.as_nanos_since_unix_epoch()
    }
}
pub trait InMemoryLedgerState {
    type AccountId;
    type Tokens;

    fn get_allowance(
        &self,
        from: &Self::AccountId,
        spender: &Self::AccountId,
    ) -> Option<Allowance<Self::Tokens>>;

    fn process_approve(
        &mut self,
        from: &Self::AccountId,
        spender: &Self::AccountId,
        amount: &Self::Tokens,
        expected_allowance: &Option<Self::Tokens>,
        expires_at: &Option<u64>,
        fee: &Option<Self::Tokens>,
        now: TimeStamp,
    );
    fn process_burn(
        &mut self,
        from: &Self::AccountId,
        spender: &Option<Self::AccountId>,
        amount: &Self::Tokens,
        index: usize,
    );
    fn process_mint(&mut self, to: &Self::AccountId, amount: &Self::Tokens);
    fn process_transfer(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        spender: &Option<Self::AccountId>,
        amount: &Self::Tokens,
        fee: &Option<Self::Tokens>,
    );
    fn validate_invariants(&self);
}

pub struct InMemoryLedger<AccountId, Tokens>
where
    AccountId: Hash + Eq,
{
    balances: HashMap<AccountId, Tokens>,
    allowances: HashMap<ApprovalKey<AccountId>, Allowance<Tokens>>,
    total_supply: Tokens,
    fee_collector: Option<AccountId>,
    burns_without_spender: Option<BurnsWithoutSpender<AccountId>>,
    transactions: u64,
    latest_block_timestamp: Option<u64>,
}

impl<AccountId, Tokens: std::fmt::Debug> PartialEq for InMemoryLedger<AccountId, Tokens>
where
    AccountId: Hash + Eq + std::fmt::Debug,
    Tokens: PartialEq + std::fmt::Debug,
{
    fn eq(&self, other: &Self) -> bool {
        if self.balances.len() != other.balances.len() {
            println!(
                "Mismatch in number of balances: {} vs {}",
                self.balances.len(),
                other.balances.len()
            );
            return false;
        }
        if self.allowances.len() != other.allowances.len() {
            println!(
                "Mismatch in number of allowances: {} vs {}",
                self.allowances.len(),
                other.allowances.len()
            );
            return false;
        }
        if self.total_supply != other.total_supply {
            println!(
                "Mismatch in total supply: {:?} vs {:?}",
                self.total_supply, other.total_supply
            );
            return false;
        }
        if self.fee_collector != other.fee_collector {
            println!(
                "Mismatch in fee collector: {:?} vs {:?}",
                self.fee_collector, other.fee_collector
            );
            return false;
        }
        if self.burns_without_spender != other.burns_without_spender {
            println!(
                "Mismatch in burns without spender: {:?} vs {:?}",
                self.burns_without_spender, other.burns_without_spender
            );
            return false;
        }
        if !self.balances.iter().all(|(account_id, balance)| {
            other.balances.get(account_id).map_or_else(
                || {
                    println!(
                        "Mismatch in balance for account {account_id:?}: {balance:?} vs None"
                    );
                    false
                },
                |other_balance| {
                    if *balance != *other_balance {
                        println!(
                            "Mismatch in balance for account {account_id:?}: {balance:?} vs {other_balance:?}"
                        );
                        false
                    } else {
                        true
                    }
                },
            )
        }) {
            return false;
        }
        if !self.allowances.iter().all(|(account_id_pair, allowance)| {
            other.allowances.get(account_id_pair).map_or_else(
                || {
                    println!(
                        "Mismatch in allowance for account pair {account_id_pair:?}: {allowance:?} vs None"
                    );
                    false
                },
                |other_allowance| {
                    if *allowance != *other_allowance {
                        println!(
                            "Mismatch in allowance for account pair {account_id_pair:?}: {allowance:?} vs {other_allowance:?}"
                        );
                        false
                    } else {
                        true
                    }
                },
            )
        }) {
            return false;
        }
        true
    }
}

impl<AccountId, Tokens> InMemoryLedgerState for InMemoryLedger<AccountId, Tokens>
where
    AccountId: Eq + PartialEq + Ord + Clone + Hash + std::fmt::Debug,
    Tokens: TokensType + Default,
{
    type AccountId = AccountId;
    type Tokens = Tokens;

    fn get_allowance(
        &self,
        from: &Self::AccountId,
        spender: &Self::AccountId,
    ) -> Option<Allowance<Self::Tokens>> {
        let key = ApprovalKey::from((from, spender));
        self.allowances.get(&key).cloned()
    }

    fn process_approve(
        &mut self,
        from: &Self::AccountId,
        spender: &Self::AccountId,
        amount: &Self::Tokens,
        expected_allowance: &Option<Self::Tokens>,
        expires_at: &Option<u64>,
        fee: &Option<Self::Tokens>,
        now: TimeStamp,
    ) {
        self.burn_fee(from, fee);
        self.set_allowance(from, spender, amount, expected_allowance, expires_at, now);
        self.transactions += 1;
    }

    fn process_burn(
        &mut self,
        from: &Self::AccountId,
        spender: &Option<Self::AccountId>,
        amount: &Self::Tokens,
        index: usize,
    ) {
        let spender: &Option<Self::AccountId> = &spender.clone().or_else(|| {
            if let Some(burns_without_spender) = &self.burns_without_spender {
                if burns_without_spender.burn_indexes.contains(&index) {
                    Some(burns_without_spender.minter.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        self.decrease_balance(from, amount);
        self.decrease_total_supply(amount);
        if let Some(spender) = spender
            && from != spender
        {
            self.decrease_allowance(from, spender, amount, None);
        }
        self.transactions += 1;
    }

    fn process_mint(&mut self, to: &Self::AccountId, amount: &Self::Tokens) {
        self.increase_balance(to, amount);
        self.increase_total_supply(amount);
        self.transactions += 1;
    }

    fn process_transfer(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        spender: &Option<Self::AccountId>,
        amount: &Self::Tokens,
        fee: &Option<Self::Tokens>,
    ) {
        self.decrease_balance(from, amount);
        self.collect_fee(from, fee);
        if let Some(fee) = fee
            && let Some(spender) = spender
            && from != spender
        {
            self.decrease_allowance(from, spender, amount, Some(fee));
        }
        self.increase_balance(to, amount);
        self.transactions += 1;
    }

    fn validate_invariants(&self) {
        let mut balances_total = Self::Tokens::default();
        for amount in self.balances.values() {
            balances_total = balances_total.checked_add(amount).unwrap();
            assert_ne!(amount, &Tokens::zero());
        }
        assert_eq!(self.total_supply, balances_total);
        for allowance in self.allowances.values() {
            assert_ne!(&allowance.amount, &Tokens::zero());
        }
    }
}

impl<AccountId, Tokens> Default for InMemoryLedger<AccountId, Tokens>
where
    AccountId: PartialEq + Ord + Clone + Hash,
    Tokens: TokensType,
{
    fn default() -> Self {
        InMemoryLedger {
            balances: HashMap::new(),
            allowances: HashMap::new(),
            total_supply: Tokens::zero(),
            fee_collector: None,
            burns_without_spender: None,
            transactions: 0,
            latest_block_timestamp: None,
        }
    }
}

impl<AccountId, Tokens> InMemoryLedger<AccountId, Tokens>
where
    AccountId: PartialEq + Ord + Clone + Hash + std::fmt::Debug,
    Tokens: TokensType,
{
    fn decrease_allowance(
        &mut self,
        from: &AccountId,
        spender: &AccountId,
        amount: &Tokens,
        fee: Option<&Tokens>,
    ) {
        let key = ApprovalKey::from((from, spender));
        let old_allowance = self
            .allowances
            .get(&key)
            .unwrap_or_else(|| panic!("Allowance not found",));
        let mut new_allowance_value = old_allowance
            .amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic!("Insufficient allowance",));
        if let Some(fee) = fee {
            new_allowance_value = new_allowance_value
                .checked_sub(fee)
                .unwrap_or_else(|| panic!("Insufficient allowance",));
        }
        if new_allowance_value.is_zero() {
            self.allowances.remove(&key);
        } else {
            self.allowances.insert(
                key,
                Allowance {
                    amount: new_allowance_value,
                    expires_at: old_allowance.expires_at,
                    arrived_at: old_allowance.arrived_at,
                },
            );
        }
    }

    fn decrease_balance(&mut self, from: &AccountId, amount: &Tokens) {
        let old_balance = self
            .balances
            .get(from)
            .unwrap_or_else(|| panic!("Account not found",));
        let new_balance = old_balance
            .checked_sub(amount)
            .unwrap_or_else(|| panic!("Insufficient balance",));
        if new_balance.is_zero() {
            self.balances.remove(from);
        } else {
            self.balances.insert(from.clone(), new_balance);
        }
    }

    fn decrease_total_supply(&mut self, amount: &Tokens) {
        self.total_supply = self
            .total_supply
            .checked_sub(amount)
            .unwrap_or_else(|| panic!("Total supply underflow",));
    }

    fn set_allowance(
        &mut self,
        from: &AccountId,
        spender: &AccountId,
        amount: &Tokens,
        expected_allowance: &Option<Tokens>,
        expires_at: &Option<u64>,
        arrived_at: TimeStamp,
    ) {
        let key = ApprovalKey::from((from, spender));
        if let Some(expected_allowance) = expected_allowance {
            match self.allowances.get(&key) {
                None => {
                    // No in-memory allowance, so the expected allowance should be zero
                    assert!(
                        expected_allowance.is_zero(),
                        "Expected allowance of ({expected_allowance:?}) for key {key:?} does not match in-memory allowance (None, interpreted as 0)"
                    );
                }
                Some(in_memory_allowance) => {
                    // An in-memory allowance is set
                    let in_memory_allowance_amount = match &in_memory_allowance.expires_at {
                        // If the in-memory allowance has no expiration, use the amount as-is
                        None => &in_memory_allowance.amount.clone(),
                        Some(expires_at) => {
                            &if expires_at >= &arrived_at {
                                // If the in-memory allowance has not expired, use the amount as-is
                                in_memory_allowance.amount.clone()
                            } else {
                                // If the in-memory allowance has expired, interpret as zero
                                Tokens::zero()
                            }
                        }
                    };
                    assert_eq!(
                        in_memory_allowance_amount, expected_allowance,
                        "Expected allowance of ({expected_allowance:?}) for key {key:?} does not match in-memory allowance ({in_memory_allowance_amount:?})"
                    );
                }
            }
        }
        if amount == &Tokens::zero() {
            self.allowances.remove(&key);
        } else {
            self.allowances.insert(
                key,
                Allowance {
                    amount: amount.clone(),
                    expires_at: expires_at.map(TimeStamp::from_nanos_since_unix_epoch),
                    arrived_at,
                },
            );
        }
    }

    fn increase_balance(&mut self, to: &AccountId, amount: &Tokens) {
        let new_balance = match self.balances.get(to) {
            None => amount.clone(),
            Some(old_balance) => old_balance
                .checked_add(amount)
                .unwrap_or_else(|| panic!("Balance overflow")),
        };
        if !new_balance.is_zero() {
            self.balances.insert(to.clone(), new_balance);
        }
    }

    fn increase_total_supply(&mut self, amount: &Tokens) {
        self.total_supply = self
            .total_supply
            .checked_add(amount)
            .unwrap_or_else(|| panic!("Total supply overflow"));
    }

    fn collect_fee(&mut self, from: &AccountId, amount: &Option<Tokens>) {
        if let Some(amount) = amount {
            self.decrease_balance(from, amount);
            if let Some(fee_collector) = &self.fee_collector {
                self.increase_balance(&fee_collector.clone(), amount);
            } else {
                self.decrease_total_supply(amount);
            }
        }
    }

    fn burn_fee(&mut self, from: &AccountId, amount: &Option<Tokens>) {
        if let Some(amount) = amount {
            self.decrease_balance(from, amount);
            self.decrease_total_supply(amount);
        }
    }

    fn prune_expired_allowances(&mut self, now: TimeStamp) {
        let expired_allowances: Vec<ApprovalKey<AccountId>> = self
            .allowances
            .iter()
            .filter_map(|(key, allowance)| {
                if let Some(expires_at) = allowance.expires_at
                    && now >= expires_at
                {
                    return Some(key.clone());
                }
                None
            })
            .collect();
        for key in expired_allowances {
            self.allowances.remove(&key);
        }
    }
}

impl<Tokens> BlockConsumer<ic_icrc1::Block<Tokens>> for InMemoryLedger<Account, Tokens>
where
    Tokens: Default + TokensType + PartialEq + std::fmt::Debug + std::fmt::Display,
{
    fn consume_blocks(&mut self, blocks: &[ic_icrc1::Block<Tokens>]) {
        for (index, block) in blocks.iter().enumerate() {
            if let Some(fee_collector) = block.fee_collector {
                self.fee_collector = Some(fee_collector);
            }
            match &block.transaction.operation {
                Operation::Mint { to, amount, fee } => {
                    assert!(fee.is_none());
                    self.process_mint(to, amount);
                }
                Operation::Transfer {
                    from,
                    to,
                    spender,
                    amount,
                    fee,
                } => self.process_transfer(
                    from,
                    to,
                    spender,
                    amount,
                    &fee.clone().or(block.effective_fee.clone()),
                ),
                Operation::Burn {
                    from,
                    spender,
                    amount,
                    fee,
                } => {
                    assert!(fee.is_none());
                    self.process_burn(from, spender, amount, index);
                }
                Operation::Approve {
                    from,
                    spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    fee,
                } => self.process_approve(
                    from,
                    spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    &fee.clone().or(block.effective_fee.clone()),
                    TimeStamp::from_nanos_since_unix_epoch(block.timestamp),
                ),
                Operation::FeeCollector { .. } => {
                    panic!("FeeCollector107 not implemented")
                }
            }
        }
        self.post_process_ledger_blocks(blocks);
    }
}

impl BlockConsumer<icp_ledger::Block>
    for InMemoryLedger<AccountIdentifier, ic_ledger_core::Tokens>
{
    fn consume_blocks(&mut self, blocks: &[icp_ledger::Block]) {
        for (index, block) in blocks.iter().enumerate() {
            match &block.transaction.operation {
                icp_ledger::Operation::Mint { to, amount } => self.process_mint(to, amount),
                icp_ledger::Operation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                    spender,
                } => self.process_transfer(from, to, spender, amount, &Some(*fee)),
                icp_ledger::Operation::Burn {
                    from,
                    amount,
                    spender,
                } => self.process_burn(from, spender, amount, index),
                icp_ledger::Operation::Approve {
                    from,
                    spender,
                    allowance,
                    expected_allowance,
                    expires_at,
                    fee,
                } => self.process_approve(
                    from,
                    spender,
                    allowance,
                    expected_allowance,
                    &expires_at.map(|ea| ea.as_nanos_since_unix_epoch()),
                    &Some(*fee),
                    block.timestamp,
                ),
            }
        }
        self.post_process_ledger_blocks(blocks);
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum AllowancesRecentlyPurged {
    Yes,
    No,
}

impl<AccountId, Tokens> InMemoryLedger<AccountId, Tokens>
where
    AccountId: Ord
        + Clone
        + Copy
        + CandidType
        + From<Account>
        + Hash
        + Eq
        + std::fmt::Debug
        + AllowanceProvider
        + BalanceProvider,
    Tokens: Default + TokensType + PartialEq + std::fmt::Debug + std::fmt::Display,
{
    pub fn new(burns_without_spender: Option<BurnsWithoutSpender<AccountId>>) -> Self {
        InMemoryLedger {
            burns_without_spender,
            ..Default::default()
        }
    }

    fn post_process_ledger_blocks<T: ConsumableBlock>(&mut self, blocks: &[T]) {
        if !blocks.is_empty() {
            self.validate_invariants();
            let latest_block_timestamp = blocks.last().unwrap().creation_timestamp();
            self.prune_expired_allowances(TimeStamp::from_nanos_since_unix_epoch(
                latest_block_timestamp,
            ));
            self.latest_block_timestamp = Some(latest_block_timestamp);
        }
    }

    pub fn apply_arg_with_caller(
        &mut self,
        arg: &ArgWithCaller,
        timestamp: TimeStamp,
        minter_principal: Principal,
        fee: Option<Tokens>,
    ) {
        match &arg.arg {
            LedgerEndpointArg::ApproveArg(approve_arg) => {
                let from = &AccountId::from(Account {
                    owner: arg.caller.sender().unwrap(),
                    subaccount: approve_arg.from_subaccount,
                });
                self.process_approve(
                    from,
                    &AccountId::from(approve_arg.spender),
                    &Tokens::try_from(approve_arg.amount.clone()).unwrap(),
                    &approve_arg
                        .expected_allowance
                        .clone()
                        .map(|ea| Tokens::try_from(ea).unwrap()),
                    &approve_arg.expires_at,
                    &fee,
                    timestamp,
                );
            }
            LedgerEndpointArg::TransferArg(transfer_arg) => {
                let owner = arg.caller.sender().unwrap();
                let from = &AccountId::from(Account {
                    owner,
                    subaccount: transfer_arg.from_subaccount,
                });
                let to = &AccountId::from(transfer_arg.to);
                if owner == minter_principal {
                    self.process_mint(to, &Tokens::try_from(transfer_arg.amount.clone()).unwrap());
                } else if transfer_arg.to.owner == minter_principal {
                    self.process_burn(
                        from,
                        &None,
                        &Tokens::try_from(transfer_arg.amount.clone()).unwrap(),
                        0,
                    );
                } else {
                    self.process_transfer(
                        from,
                        to,
                        &None,
                        &Tokens::try_from(transfer_arg.amount.clone()).unwrap(),
                        &fee,
                    )
                }
            }
            LedgerEndpointArg::TransferFromArg(transfer_from_arg) => {
                let owner = arg.caller.sender().unwrap();
                let spender = AccountId::from(Account {
                    owner,
                    subaccount: transfer_from_arg.spender_subaccount,
                });
                let from = &AccountId::from(transfer_from_arg.from);
                let to = &AccountId::from(transfer_from_arg.to);
                self.process_transfer(
                    from,
                    to,
                    &Some(spender),
                    &Tokens::try_from(transfer_from_arg.amount.clone()).unwrap(),
                    &fee,
                )
            }
        }
        self.latest_block_timestamp = Some(timestamp.as_nanos_since_unix_epoch());
        self.validate_invariants();
    }

    pub fn verify_balances_and_allowances(
        &self,
        env: &StateMachine,
        ledger_id: CanisterId,
        num_ledger_blocks: u64,
        allowances_recently_purged: AllowancesRecentlyPurged,
    ) {
        let actual_num_approvals = parse_metric(env, ledger_id, "ledger_num_approvals");
        let actual_num_balances = parse_metric(env, ledger_id, "ledger_balance_store_entries");
        println!(
            "total_blocks in ledger: {}, total InMemoryLedger transactions: {}",
            num_ledger_blocks, self.transactions
        );
        println!(
            "number of approvals in ledger: {}, number of approvals in InMemoryLedger: {}",
            actual_num_approvals,
            self.allowances.len()
        );
        println!(
            "number of balances in ledger: {}, number of balances in InMemoryLedger: {}",
            actual_num_balances,
            self.balances.len()
        );
        println!("Checking {actual_num_balances} balances and {actual_num_approvals} allowances");
        let mut balances_checked = 0;
        let now = Instant::now();
        for (account, balance) in self.balances.iter() {
            let actual_balance = AccountId::get_balance(env, ledger_id, *account);

            assert_eq!(
                &Tokens::try_from(actual_balance.clone()).unwrap(),
                balance,
                "Mismatch in balance for account {account:?} ({balance} vs {actual_balance})"
            );
            if balances_checked % 100000 == 0 && balances_checked > 0 {
                println!(
                    "Checked {} balances in {:?}",
                    balances_checked,
                    now.elapsed()
                );
            }
            balances_checked += 1;
        }
        println!(
            "{} balances checked in {:?}",
            balances_checked,
            now.elapsed()
        );
        let now = Instant::now();
        let mut allowances_checked = 0;
        let mut expiration_in_future_count = 0;
        let mut expiration_in_past_count = 0;
        let mut no_expiration_count = 0;
        let latest_ledger_block_timestamp = self
            .latest_block_timestamp
            .expect("latest ledger block timestamp should be set");
        let current_ledger_timestamp = env
            .time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        for (approval, allowance) in self.allowances.iter() {
            let (from, spender): (AccountId, AccountId) = approval.clone().into();
            assert!(
                !allowance.amount.is_zero(),
                "Expected allowance is zero! Should not happen... from: {:?}, spender: {:?}",
                &from,
                &spender
            );
            let actual_allowance = AccountId::get_allowance(env, ledger_id, from, spender);
            if let Some(in_memory_expires_at) = allowance.expires_at
                && in_memory_expires_at.as_nanos_since_unix_epoch() < current_ledger_timestamp
            {
                assert_eq!(
                    Tokens::zero(),
                    Tokens::try_from(actual_allowance.allowance.clone()).unwrap(),
                    "Expected amount of expired actual allowance to be zero, but it is not: {:?}",
                    &actual_allowance
                );
                assert!(
                    actual_allowance.expires_at.is_none(),
                    "Expected expired actual allowance to have no expires_at, but it has one: {:?}",
                    &actual_allowance
                );
                allowances_checked += 1;
                continue;
            }
            match actual_allowance.expires_at {
                None => {
                    no_expiration_count += 1;
                }
                Some(expires_at) => {
                    if expires_at > latest_ledger_block_timestamp {
                        expiration_in_future_count += 1;
                    } else {
                        // This should never happen, since the allowance returned from the ledger
                        // should have an amount of 0, and no expires_at.
                        expiration_in_past_count += 1;
                    }
                }
            }
            assert_eq!(
                allowance.amount,
                Tokens::try_from(actual_allowance.allowance.clone()).unwrap(),
                "Mismatch in allowance for approval from {:?} spender {:?}: {:?} ({:?} vs {:?}) at {:?}",
                &from,
                &spender,
                approval,
                allowance,
                actual_allowance,
                env.time()
            );
            assert_eq!(
                allowance.expires_at.map(|t| t.as_nanos_since_unix_epoch()),
                actual_allowance.expires_at,
                "Mismatch in allowance expiration for approval from {:?} spender {:?}: {:?} ({:?} vs {:?}) at {:?}",
                &from,
                &spender,
                approval,
                allowance,
                actual_allowance,
                env.time()
            );
            if allowances_checked % 10000 == 0 && allowances_checked > 0 {
                println!(
                    "Checked {} allowances in {:?}",
                    allowances_checked,
                    now.elapsed()
                );
            }
            allowances_checked += 1;
        }
        println!(
            "{} allowances checked in {:?}",
            allowances_checked,
            now.elapsed()
        );
        println!(
            "allowances with no expiration: {no_expiration_count}, expiration in future: {expiration_in_future_count}, expiration in past: {expiration_in_past_count}"
        );
        assert_eq!(
            self.transactions, num_ledger_blocks,
            "Mismatch in number of transactions (InMemoryLedger: {}, vs StateMachine ledger: {})",
            self.transactions, num_ledger_blocks
        );
        assert_eq!(
            self.balances.len() as u64,
            actual_num_balances,
            "Mismatch in number of balances (InMemoryLedger: {}, vs StateMachine ledger: {})",
            self.balances.len(),
            actual_num_balances
        );
        // The metric value for the number of allowances does not check if any allowances have
        // expired since the last transactions was processed, and the current time. Therefore, for
        // this test, only compare the number of expected allowances with the ledger metric if
        // allowances were recently purged, i.e., if a transaction was recently processed.
        if allowances_recently_purged == AllowancesRecentlyPurged::Yes {
            assert_eq!(
                self.allowances.len() as u64,
                actual_num_approvals,
                "Mismatch in number of approvals (InMemoryLedger: {}, vs StateMachine ledger: {})",
                self.allowances.len(),
                actual_num_approvals,
            );
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct BurnsWithoutSpender<AccountId> {
    pub minter: AccountId,
    pub burn_indexes: Vec<usize>,
}

pub fn verify_ledger_state<Tokens>(
    env: &StateMachine,
    ledger_id: CanisterId,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    allowances_recently_purged: AllowancesRecentlyPurged,
) where
    Tokens: Default + TokensType + PartialEq + std::fmt::Debug + std::fmt::Display,
{
    println!("verifying state of ledger {ledger_id}");
    let blocks = get_all_ledger_and_archive_blocks::<Tokens>(env, ledger_id, None, None);
    println!("retrieved all ledger and archive blocks");
    let mut expected_ledger_state = InMemoryLedger::new(burns_without_spender);
    expected_ledger_state.consume_blocks(&blocks);
    println!("recreated expected ledger state");
    expected_ledger_state.verify_balances_and_allowances(
        env,
        ledger_id,
        blocks.len() as u64,
        allowances_recently_purged,
    );
    println!("ledger state verified successfully");
}
