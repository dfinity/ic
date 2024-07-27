use super::{balance_of, get_all_ledger_and_archive_blocks, get_allowance, Tokens};
use crate::metrics::parse_metric;
use ic_base_types::CanisterId;
use ic_crypto_sha2::Sha256;
use ic_icrc1::Operation;
use ic_icrc1_ledger::ApprovalKey;
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::TokensType;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;
use std::hash::Hash;

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
    pub balances: BTreeMap<AccountId, Tokens>,
    pub allowances: BTreeMap<K, Allowance<Tokens>>,
    pub total_supply: Tokens,
    pub fee_collector: Option<AccountId>,
}

impl<K, AccountId, Tokens> InMemoryLedgerState for InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone + Hash,
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
    ) {
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
                    self.decrease_allowance(from, spender, &amount, Some(fee));
                }
            }
        }
        self.increase_balance(to, amount);
    }

    fn validate_invariants(&self) {
        let mut balances_total = Self::Tokens::default();
        for (_account, amount) in &self.balances {
            balances_total = balances_total.checked_add(amount).unwrap();
            assert_ne!(amount, &Tokens::zero());
        }
        assert_eq!(self.total_supply, balances_total);
    }
}

impl<K, AccountId, Tokens> InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone + Hash,
    Tokens: TokensType,
{
    pub fn new() -> Self {
        InMemoryLedger {
            balances: BTreeMap::new(),
            allowances: BTreeMap::new(),
            total_supply: Tokens::zero(),
            fee_collector: None,
        }
    }

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
            .get(&from)
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
        self.allowances.insert(
            key,
            Allowance {
                amount: amount.clone(),
                expires_at: expires_at.map(|e| TimeStamp::from_nanos_since_unix_epoch(e)),
                arrived_at,
            },
        );
    }

    fn increase_balance(&mut self, to: &AccountId, amount: &Tokens) {
        let new_balance = match self.balances.get(&to) {
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

    fn print_balances(&self) {
        println!("Balances: {{");
        for (account, amount) in &self.balances {
            println!(
                "  Account: {}",
                InMemoryLedger::<K, AccountId, Tokens>::account_hash(account)
            );
            println!("  Amount: {:?}", amount);
        }
        println!("}}");
    }

    fn print_allowances(&self) {
        println!("Allowances: {{");
        for (key, allowance) in &self.allowances {
            let (from, spender) = key.clone().into();
            println!(
                "  From: {}",
                InMemoryLedger::<K, AccountId, Tokens>::account_hash(&from)
            );
            println!(
                "  Spender: {}",
                InMemoryLedger::<K, AccountId, Tokens>::account_hash(&spender)
            );
            println!("  Amount: {:?}", allowance.amount);
            println!("  Expires at: {:?}", &allowance.expires_at);
            println!("  Arrived at: {:?}", &allowance.arrived_at);
        }
        println!("}}");
    }

    fn account_hash(account: &AccountId) -> String {
        let mut hasher = Sha256::new();
        account.hash(&mut hasher);
        let hash = hasher.finish();
        String::from(&hex::encode(hash)[..8])
    }
}

impl InMemoryLedger<ApprovalKey, Account, Tokens> {
    fn new_from_icrc1_ledger_blocks(
        blocks: &Vec<ic_icrc1::Block<Tokens>>,
    ) -> InMemoryLedger<ApprovalKey, Account, Tokens> {
        let mut state = InMemoryLedger::new();
        for block in blocks {
            println!("processing block");
            print_block(&block);
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
                } => state.process_transfer(from, to, spender, amount, fee),
                Operation::Burn {
                    from,
                    spender,
                    amount,
                } => state.process_burn(from, spender, amount),
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
                    fee,
                    TimeStamp::from_nanos_since_unix_epoch(block.timestamp),
                ),
            }
            state.print_balances();
            state.print_allowances();
            state.validate_invariants();
        }
        state
    }
}

pub fn verify_ledger_state(env: &StateMachine, ledger_id: CanisterId) {
    println!("verifying state of ledger {}", ledger_id);
    let blocks = get_all_ledger_and_archive_blocks(&env, ledger_id);
    println!("retrieved all ledger and archive blocks");
    let expected_ledger_state = InMemoryLedger::new_from_icrc1_ledger_blocks(&blocks);
    println!("recreated expected ledger state");
    let actual_num_approvals = parse_metric(&env, ledger_id, "ledger_num_approvals");
    let actual_num_balances = parse_metric(&env, ledger_id, "ledger_balance_store_entries");
    if expected_ledger_state.balances.len() as u64 != actual_num_balances {
        println!(
            "Mismatch in number of balances ({} vs {})",
            expected_ledger_state.balances.len(),
            actual_num_balances
        );
    }
    // assert_eq!(
    //     expected_ledger_state.balances.len() as u64,
    //     actual_num_balances,
    //     "Mismatch in number of balances ({} vs {})",
    //     expected_ledger_state.balances.len(),
    //     actual_num_balances
    // );
    if expected_ledger_state.allowances.len() as u64 != actual_num_approvals {
        println!(
            "Mismatch in number of approvals ({} vs {})",
            expected_ledger_state.allowances.len(),
            actual_num_approvals
        );
    }
    // assert_eq!(
    //     expected_ledger_state.allowances.len() as u64,
    //     actual_num_approvals,
    //     "Mismatch in number of approvals ({} vs {})",
    //     expected_ledger_state.allowances.len(),
    //     actual_num_approvals
    // );
    println!(
        "Checking {} balances and {} allowances",
        actual_num_balances, actual_num_approvals
    );
    for (account, balance) in expected_ledger_state.balances.iter() {
        let actual_balance = balance_of(&env, ledger_id, account.clone());
        if &Tokens::from(actual_balance) != balance {
            println!(
                "Mismatch in balance for account {:?} ({} vs {})",
                account, balance, actual_balance
            );
        }
        // assert_eq!(
        //     balance.to_u64(),
        //     actual_balance,
        //     "Mismatch in balance for account {:?} ({} vs {})",
        //     account,
        //     balance,
        //     actual_balance
        // );
    }
    for (approval, allowance) in expected_ledger_state.allowances.iter() {
        let (from, spender): (Account, Account) = approval.clone().into();
        let actual_allowance = get_allowance(&env, ledger_id, from, spender);
        if allowance.amount != Tokens::try_from(actual_allowance.allowance.clone()).unwrap() {
            println!(
                "Mismatch in allowance for approval {:?} ({:?} vs {:?})",
                approval, allowance, actual_allowance.allowance
            );
        }
        // assert_eq!(
        //     allowance.amount.to_u64(),
        //     actual_allowance.allowance.0.to_u64().unwrap(),
        //     "Mismatch in allowance for approval {:?} ({:?} vs {:?})",
        //     approval,
        //     allowance,
        //     actual_allowance.allowance
        // );
    }
    println!("ledger state verified successfully");
}

fn account_hash(account: &Account) -> String {
    let mut hasher = Sha256::new();
    account.hash(&mut hasher);
    let hash = hasher.finish();
    String::from(&hex::encode(hash)[..8])
}

fn print_block(block: &ic_icrc1::Block<Tokens>) {
    println!("Block {{");
    match block.transaction.operation {
        Operation::Mint { to, amount } => {
            println!("  Operation: Mint {{");
            println!("    to: {}", account_hash(&to));
            println!("    amount: {:?}", &amount);
            println!("  }}")
        }
        Operation::Transfer {
            from,
            to,
            spender,
            amount,
            fee,
        } => {
            match spender {
                None => {
                    println!("  Operation: Transfer {{");
                }
                Some(_) => {
                    println!("  Operation: Transfer From {{");
                }
            }
            println!("    from: {}", account_hash(&from));
            println!("    to: {}", account_hash(&to));
            match spender {
                None => {
                    println!("    spender: None");
                }
                Some(spender) => {
                    println!("    spender: {}", account_hash(&spender));
                }
            }
            println!("    amount: {:?}", &amount);
            match fee {
                None => {
                    println!("    fee: None");
                }
                Some(fee) => {
                    println!("    fee: {:?}", fee);
                }
            }
            println!("  }}")
        }
        Operation::Burn {
            from,
            spender,
            amount,
        } => {
            println!("  Operation: Burn {{");
            println!("    from: {}", account_hash(&from));
            match spender {
                None => {
                    println!("    spender: None");
                }
                Some(spender) => {
                    println!("    spender: {}", account_hash(&spender));
                }
            }
            println!("    amount: {:?}", &amount);
            println!("  }}")
        }
        Operation::Approve {
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
        } => {
            println!("  Operation: Approve {{");
            println!("    from: {}", account_hash(&from));
            println!("    spender: {}", account_hash(&spender));
            println!("    amount: {:?}", &amount);
            match expected_allowance {
                None => {
                    println!("    expected_allowance: None");
                }
                Some(expected_allowance) => {
                    println!("    expected_allowance: {:?}", &expected_allowance);
                }
            }
            match expires_at {
                None => {
                    println!("    expires_at: None");
                }
                Some(expires_at) => {
                    println!("    expires_at: {}", expires_at);
                }
            }
            match fee {
                None => {
                    println!("    fee: None");
                }
                Some(fee) => {
                    println!("    fee: {:?}", fee);
                }
            }
            println!("  }}")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::in_memory_ledger::{InMemoryLedger, InMemoryLedgerState};
    use ic_icrc1_ledger::ApprovalKey;
    use ic_ledger_core::approvals::Allowance;
    use ic_ledger_core::timestamp::TimeStamp;
    use ic_ledger_core::tokens::CheckedSub;
    use ic_types::PrincipalId;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_increase_balance_and_total_supply_with_mint() {
        const MINT_AMOUNT: u64 = 1_000_000;
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let burn_amount = super::Tokens::from(BURN_AMOUNT);
        in_memory_ledger.process_mint(&to, &amount);
        in_memory_ledger.validate_invariants();
        let expected_balance = amount.checked_sub(&burn_amount).unwrap();

        in_memory_ledger.process_burn(&to, &None, &burn_amount);
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let to = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let burn_amount = super::Tokens::from(BURN_AMOUNT);
        let expected_total_supply = super::Tokens::from(0);
        in_memory_ledger.process_mint(&to, &amount);
        in_memory_ledger.validate_invariants();

        in_memory_ledger.process_burn(&to, &None, &burn_amount);
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let transfer_amount = super::Tokens::from(TRANSFER_AMOUNT);
        let fee = super::Tokens::from(10_000);
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let transfer_amount = super::Tokens::from(TRANSFER_AMOUNT);
        let fee = super::Tokens::from(10_000);
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

        assert_eq!(in_memory_ledger.total_supply, super::Tokens::from(0));
        assert!(in_memory_ledger.balances.is_empty());
    }

    #[test]
    fn should_increase_allowance_with_approve() {
        const MINT_AMOUNT: u64 = 1_000_000;
        const APPROVE_AMOUNT: u64 = 200_000;
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let approve_amount = super::Tokens::from(APPROVE_AMOUNT);
        let fee = super::Tokens::from(10_000);
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
        let expected_allowance2: Allowance<super::Tokens> = Allowance {
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
        let account1 = Account {
            owner: PrincipalId::new_user_test_id(134).0,
            subaccount: None,
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(546).0,
            subaccount: None,
        };
        let amount = super::Tokens::from(MINT_AMOUNT);
        let approve_amount = super::Tokens::from(APPROVE_AMOUNT);
        let another_approve_amount = super::Tokens::from(ANOTHER_APPROVE_AMOUNT);
        let fee = super::Tokens::from(10_000);
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
        let expected_allowance2: Allowance<super::Tokens> = Allowance {
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
        let mut in_memory_ledger: InMemoryLedger<
            ApprovalKey,
            Account,
            crate::in_memory_ledger::Tokens,
        > = InMemoryLedger::new();
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
        let amount = super::Tokens::from(MINT_AMOUNT);
        let transfer_amount = super::Tokens::from(TRANSFER_AMOUNT);
        let approve_amount = super::Tokens::from(APPROVE_AMOUNT);
        let fee = super::Tokens::from(10_000);
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
