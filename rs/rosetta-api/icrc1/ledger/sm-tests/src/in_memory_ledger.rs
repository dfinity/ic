use super::{get_all_ledger_and_archive_blocks, get_allowance, Tokens};
use crate::metrics::parse_metric;
use candid::{Decode, Encode, Nat};
use ic_base_types::CanisterId;
use ic_crypto_sha2::Sha256;
use ic_icrc1::Operation;
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::{TokensType, Zero};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ApprovalKey(Account, Account);

impl From<(&Account, &Account)> for ApprovalKey {
    fn from((account, spender): (&Account, &Account)) -> Self {
        Self(*account, *spender)
    }
}

impl From<ApprovalKey> for (Account, Account) {
    fn from(key: ApprovalKey) -> Self {
        (key.0, key.1)
    }
}

trait InMemoryLedgerState {
    type AccountId;
    type Tokens;

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

pub struct InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord,
{
    pub balances: HashMap<AccountId, Tokens>,
    pub allowances: HashMap<K, Allowance<Tokens>>,
    pub total_supply: Tokens,
    pub fee_collector: Option<AccountId>,
    pub burns_without_spender: Option<BurnsWithoutSpender<AccountId>>,
}

impl<K, AccountId, Tokens> InMemoryLedgerState for InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone + Hash,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone + Hash + std::fmt::Debug,
    Tokens: TokensType + Default,
{
    type AccountId = AccountId;
    type Tokens = Tokens;

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
        if let Some(spender) = spender {
            if from != spender {
                self.decrease_allowance(from, spender, amount, None);
            }
        }
    }

    fn process_mint(&mut self, to: &Self::AccountId, amount: &Self::Tokens) {
        self.increase_balance(to, amount);
        self.increase_total_supply(amount);
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
        if let Some(fee) = fee {
            if let Some(spender) = spender {
                if from != spender {
                    self.decrease_allowance(from, spender, amount, Some(fee));
                }
            }
        }
        self.increase_balance(to, amount);
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

impl<K, AccountId, Tokens> Default for InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone + Hash,
    K: Into<(AccountId, AccountId)>,
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
        }
    }
}

impl<K, AccountId, Tokens> InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone + Hash,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone + Hash,
    Tokens: TokensType,
{
    fn decrease_allowance(
        &mut self,
        from: &AccountId,
        spender: &AccountId,
        amount: &Tokens,
        fee: Option<&Tokens>,
    ) {
        let key = K::from((from, spender));
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
        let key = K::from((from, spender));
        if let Some(expected_allowance) = expected_allowance {
            let current_allowance = self
                .allowances
                .get(&key)
                .unwrap_or_else(|| panic!("No current allowance but expected allowance set"));
            if current_allowance.amount != *expected_allowance {
                panic!("Expected allowance does not match current allowance");
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
        let expired_allowances: Vec<K> = self
            .allowances
            .iter()
            .filter_map(|(key, allowance)| {
                if let Some(expires_at) = allowance.expires_at {
                    if now >= expires_at {
                        return Some(key.clone());
                    }
                }
                None
            })
            .collect();
        for key in expired_allowances {
            self.allowances.remove(&key);
        }
    }
}

impl InMemoryLedger<ApprovalKey, Account, Tokens> {
    fn new_from_icrc1_ledger_blocks(
        blocks: &[ic_icrc1::Block<Tokens>],
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    ) -> InMemoryLedger<ApprovalKey, Account, Tokens> {
        let mut state = InMemoryLedger {
            burns_without_spender,
            ..Default::default()
        };
        for (index, block) in blocks.iter().enumerate() {
            if let Some(fee_collector) = block.fee_collector {
                state.fee_collector = Some(fee_collector);
                println!("Fee collector: {}", account_hash(&fee_collector));
            }
            match &block.transaction.operation {
                Operation::Mint { to, amount } => state.process_mint(to, amount),
                Operation::Transfer {
                    from,
                    to,
                    spender,
                    amount,
                    fee,
                } => {
                    state.process_transfer(from, to, spender, amount, &fee.or(block.effective_fee))
                }
                Operation::Burn {
                    from,
                    spender,
                    amount,
                } => state.process_burn(from, spender, amount, index),
                Operation::Approve {
                    from,
                    spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    fee,
                } => state.process_approve(
                    from,
                    spender,
                    amount,
                    expected_allowance,
                    expires_at,
                    &fee.or(block.effective_fee),
                    TimeStamp::from_nanos_since_unix_epoch(block.timestamp),
                ),
            }
            state.validate_invariants();
        }
        state.prune_expired_allowances(TimeStamp::from_nanos_since_unix_epoch(
            blocks.last().unwrap().timestamp,
        ));
        state
    }
}

pub struct BurnsWithoutSpender<AccountId> {
    pub minter: AccountId,
    pub burn_indexes: Vec<usize>,
}

pub fn verify_ledger_state(
    env: &StateMachine,
    ledger_id: CanisterId,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
) {
    println!("verifying state of ledger {}", ledger_id);
    let blocks = get_all_ledger_and_archive_blocks(env, ledger_id);
    println!("retrieved all ledger and archive blocks");
    let expected_ledger_state =
        InMemoryLedger::new_from_icrc1_ledger_blocks(&blocks, burns_without_spender);
    println!("recreated expected ledger state");
    let actual_num_approvals = parse_metric(env, ledger_id, "ledger_num_approvals");
    let actual_num_balances = parse_metric(env, ledger_id, "ledger_balance_store_entries");
    assert_eq!(
        expected_ledger_state.balances.len() as u64,
        actual_num_balances,
        "Mismatch in number of balances ({} vs {})",
        expected_ledger_state.balances.len(),
        actual_num_balances
    );
    assert_eq!(
        expected_ledger_state.allowances.len() as u64,
        actual_num_approvals,
        "Mismatch in number of approvals ({} vs {})",
        expected_ledger_state.allowances.len(),
        actual_num_approvals
    );
    println!(
        "Checking {} balances and {} allowances",
        actual_num_balances, actual_num_approvals
    );
    for (account, balance) in expected_ledger_state.balances.iter() {
        let actual_balance = Decode!(
            &env.query(ledger_id, "icrc1_balance_of", Encode!(account).unwrap())
                .expect("failed to query balance")
                .bytes(),
            Nat
        )
        .expect("failed to decode balance_of response");

        assert_eq!(
            &Tokens::try_from(actual_balance.clone()).unwrap(),
            balance,
            "Mismatch in balance for account {:?} ({} vs {})",
            account,
            balance,
            actual_balance
        );
    }
    for (approval, allowance) in expected_ledger_state.allowances.iter() {
        let (from, spender): (Account, Account) = approval.clone().into();
        assert!(
            !allowance.amount.is_zero(),
            "Expected allowance is zero! Should not happen... from: {}, spender: {}",
            account_hash(&from),
            account_hash(&spender)
        );
        let actual_allowance = get_allowance(env, ledger_id, from, spender);
        assert_eq!(
            allowance.amount,
            Tokens::try_from(actual_allowance.allowance.clone()).unwrap(),
            "Mismatch in allowance for approval from {} spender {}: {:?} ({:?} vs {:?})",
            account_hash(&from),
            account_hash(&spender),
            approval,
            allowance,
            actual_allowance
        );
    }
    println!("ledger state verified successfully");
}

fn account_hash(account: &Account) -> String {
    let mut hasher = Sha256::new();
    account.hash(&mut hasher);
    let hash = hasher.finish();
    String::from(&hex::encode(hash)[..8])
}

#[cfg(test)]
mod tests {
    use crate::in_memory_ledger::{ApprovalKey, InMemoryLedger, InMemoryLedgerState, Tokens};
    use ic_ledger_core::approvals::Allowance;
    use ic_ledger_core::timestamp::TimeStamp;
    use ic_ledger_core::tokens::CheckedSub;
    use ic_types::PrincipalId;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_increase_balance_and_total_supply_with_mint() {
        const MINT_AMOUNT: u64 = 1_000_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        in_memory_ledger.process_mint(&to, &amount);
        in_memory_ledger.validate_invariants();
        assert_eq!(in_memory_ledger.balances.len(), 1);
        assert!(in_memory_ledger.allowances.is_empty());
        assert_eq!(in_memory_ledger.total_supply, amount);
        let actual_balance = in_memory_ledger.balances.get(&to);
        assert_eq!(Some(&amount), actual_balance);
        assert_eq!(in_memory_ledger.total_supply, amount);
    }

    #[test]
    fn should_decrease_balance_with_burn() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const BURN_AMOUNT: u64 = 500_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let burn_amount = Tokens::from(BURN_AMOUNT);
        in_memory_ledger.process_mint(&to, &amount);
        in_memory_ledger.validate_invariants();
        let expected_balance = amount.checked_sub(&burn_amount).unwrap();

        in_memory_ledger.process_burn(&to, &None, &burn_amount, 0);
        assert_eq!(in_memory_ledger.total_supply, expected_balance);
        assert_eq!(in_memory_ledger.balances.len(), 1);
        assert!(in_memory_ledger.allowances.is_empty());
        let actual_balance = in_memory_ledger.balances.get(&to);
        assert_eq!(Some(&expected_balance), actual_balance);
    }

    #[test]
    fn should_remove_balance_with_burn() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const BURN_AMOUNT: u64 = MINT_AMOUNT;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let burn_amount = Tokens::from(BURN_AMOUNT);
        let expected_total_supply = Tokens::from(0u64);
        in_memory_ledger.process_mint(&to, &amount);
        in_memory_ledger.validate_invariants();

        in_memory_ledger.process_burn(&to, &None, &burn_amount, 0);
        in_memory_ledger.validate_invariants();
        assert_eq!(in_memory_ledger.total_supply, expected_total_supply);
        assert!(in_memory_ledger.balances.is_empty());
        assert!(in_memory_ledger.allowances.is_empty());
        let actual_balance = in_memory_ledger.balances.get(&to);
        assert_eq!(None, actual_balance);
    }

    #[test]
    fn should_increase_and_decrease_balance_with_transfer() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const TRANSFER_AMOUNT: u64 = 200_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let transfer_amount = Tokens::from(TRANSFER_AMOUNT);
        let fee = Tokens::from(10_000u64);
        in_memory_ledger.process_mint(&account1, &amount);
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_transfer(
            &account1,
            &account2,
            &None,
            &transfer_amount,
            &Some(fee),
        );
        in_memory_ledger.validate_invariants();
        let expected_balance1 = amount
            .checked_sub(&transfer_amount)
            .unwrap()
            .checked_sub(&fee)
            .unwrap();

        assert_eq!(
            in_memory_ledger.total_supply,
            amount.checked_sub(&fee).unwrap()
        );
        assert_eq!(in_memory_ledger.balances.len(), 2);
        assert!(in_memory_ledger.allowances.is_empty());
        let actual_balance1 = in_memory_ledger.balances.get(&account1);
        assert_eq!(Some(&expected_balance1), actual_balance1);
        let actual_balance2 = in_memory_ledger.balances.get(&account2);
        assert_eq!(Some(&transfer_amount), actual_balance2);
    }

    #[test]
    fn should_remove_balances_with_transfer() {
        const MINT_AMOUNT: u64 = 10_000;
        const TRANSFER_AMOUNT: u64 = 0;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let transfer_amount = Tokens::from(TRANSFER_AMOUNT);
        let fee = Tokens::from(10_000u64);
        in_memory_ledger.process_mint(&account1, &amount);
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_transfer(
            &account1,
            &account2,
            &None,
            &transfer_amount,
            &Some(fee),
        );
        in_memory_ledger.validate_invariants();

        assert_eq!(in_memory_ledger.total_supply, Tokens::from(0u64));
        assert!(in_memory_ledger.balances.is_empty());
    }

    #[test]
    fn should_increase_allowance_with_approve() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const APPROVE_AMOUNT: u64 = 200_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let approve_amount = Tokens::from(APPROVE_AMOUNT);
        let fee = Tokens::from(10_000u64);
        in_memory_ledger.process_mint(&account1, &amount);
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_approve(
            &account1,
            &account2,
            &approve_amount,
            &None,
            &None,
            &Some(fee),
            TimeStamp::from_nanos_since_unix_epoch(0),
        );
        in_memory_ledger.validate_invariants();
        let expected_balance1 = amount.checked_sub(&fee).unwrap();

        assert_eq!(
            in_memory_ledger.total_supply,
            amount.checked_sub(&fee).unwrap()
        );
        assert_eq!(in_memory_ledger.balances.len(), 1);
        assert_eq!(in_memory_ledger.allowances.len(), 1);
        let actual_balance1 = in_memory_ledger.balances.get(&account1);
        assert_eq!(Some(&expected_balance1), actual_balance1);
        let allowance_key = ApprovalKey::from((&account1, &account2));
        let account2_allowance = in_memory_ledger.allowances.get(&allowance_key);
        let expected_allowance2: Allowance<Tokens> = Allowance {
            amount: approve_amount,
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        };
        assert_eq!(account2_allowance, Some(&expected_allowance2));
    }

    #[test]
    fn should_reset_allowance_with_second_approve() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const APPROVE_AMOUNT: u64 = 200_000;
        const ANOTHER_APPROVE_AMOUNT: u64 = 700_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let approve_amount = Tokens::from(APPROVE_AMOUNT);
        let another_approve_amount = Tokens::from(ANOTHER_APPROVE_AMOUNT);
        let fee = Tokens::from(10_000u64);
        in_memory_ledger.process_mint(&account1, &amount);
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_approve(
            &account1,
            &account2,
            &approve_amount,
            &None,
            &None,
            &Some(fee),
            TimeStamp::from_nanos_since_unix_epoch(0),
        );
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_approve(
            &account1,
            &account2,
            &another_approve_amount,
            &None,
            &None,
            &Some(fee),
            TimeStamp::from_nanos_since_unix_epoch(1),
        );
        in_memory_ledger.validate_invariants();
        let expected_balance1 = amount.checked_sub(&fee).unwrap().checked_sub(&fee).unwrap();

        assert_eq!(
            in_memory_ledger.total_supply,
            amount.checked_sub(&fee).unwrap().checked_sub(&fee).unwrap()
        );
        assert_eq!(in_memory_ledger.balances.len(), 1);
        assert_eq!(in_memory_ledger.allowances.len(), 1);
        let actual_balance1 = in_memory_ledger.balances.get(&account1);
        assert_eq!(Some(&expected_balance1), actual_balance1);
        let allowance_key = ApprovalKey::from((&account1, &account2));
        let account2_allowance = in_memory_ledger.allowances.get(&allowance_key);
        let expected_allowance2: Allowance<Tokens> = Allowance {
            amount: another_approve_amount,
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        };
        assert_eq!(account2_allowance, Some(&expected_allowance2));
    }

    #[test]
    fn should_increase_and_decrease_balance_with_transfer_from() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const APPROVE_AMOUNT: u64 = 300_000;
        const TRANSFER_AMOUNT: u64 = 200_000;
        let mut in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens> =
            InMemoryLedger::default();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let account3 = Account {
            owner: PrincipalId::new_user_test_id(966).0,
            subaccount: None,
        };
        let amount = Tokens::from(MINT_AMOUNT);
        let transfer_amount = Tokens::from(TRANSFER_AMOUNT);
        let approve_amount = Tokens::from(APPROVE_AMOUNT);
        let fee = Tokens::from(10_000u64);
        in_memory_ledger.process_mint(&account1, &amount);
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_approve(
            &account1,
            &account2,
            &approve_amount,
            &None,
            &None,
            &Some(fee),
            TimeStamp::from_nanos_since_unix_epoch(0),
        );
        in_memory_ledger.validate_invariants();
        in_memory_ledger.process_transfer(
            &account1,
            &account3,
            &Some(account2),
            &transfer_amount,
            &Some(fee),
        );
        in_memory_ledger.validate_invariants();
        let expected_balance1 = amount
            .checked_sub(&transfer_amount)
            .unwrap()
            .checked_sub(&fee)
            .unwrap()
            .checked_sub(&fee)
            .unwrap();

        assert_eq!(
            in_memory_ledger.total_supply,
            amount.checked_sub(&fee).unwrap().checked_sub(&fee).unwrap()
        );
        assert_eq!(in_memory_ledger.balances.len(), 2);
        assert_eq!(in_memory_ledger.allowances.len(), 1);
        let actual_balance1 = in_memory_ledger.balances.get(&account1);
        assert_eq!(Some(&expected_balance1), actual_balance1);
        let actual_balance3 = in_memory_ledger.balances.get(&account3);
        assert_eq!(Some(&transfer_amount), actual_balance3);
    }
}
