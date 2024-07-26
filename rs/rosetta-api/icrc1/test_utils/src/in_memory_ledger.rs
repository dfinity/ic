use ic_icrc1::Operation;
use ic_icrc1_ledger::ApprovalKey;
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

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
}

pub struct InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord,
{
    pub balances: BTreeMap<AccountId, Tokens>,
    pub allowances: BTreeMap<K, Allowance<Tokens>>,
    pub total_supply: Tokens,
}

impl<K, AccountId, Tokens> InMemoryLedgerState for InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone,
    Tokens: TokensType,
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
        if let Some(fee) = fee {
            self.decrease_balance(from, fee);
            self.decrease_total_supply(fee);
        }
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
        if let Some(fee) = fee {
            self.decrease_balance(from, fee);
            self.decrease_total_supply(fee);
            if let Some(spender) = spender {
                if from != spender {
                    self.decrease_allowance(from, spender, &amount, Some(fee));
                }
            }
        }
        self.increase_balance(to, amount);
    }
}

impl<K, AccountId, Tokens> InMemoryLedger<K, AccountId, Tokens>
where
    K: Ord + for<'a> From<(&'a AccountId, &'a AccountId)> + Clone,
    K: Into<(AccountId, AccountId)>,
    AccountId: PartialEq + Ord + Clone,
    Tokens: TokensType,
{
    pub fn new() -> Self {
        InMemoryLedger {
            balances: BTreeMap::new(),
            allowances: BTreeMap::new(),
            total_supply: Tokens::zero(),
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
        if new_allowance_value > Tokens::zero() {
            self.allowances.insert(
                key,
                Allowance {
                    amount: new_allowance_value,
                    expires_at: old_allowance.expires_at,
                    arrived_at: old_allowance.arrived_at,
                },
            );
        } else {
            self.allowances.remove(&key);
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
        if new_balance > Tokens::zero() {
            self.balances.insert(from.clone(), new_balance);
        } else {
            self.balances.remove(from);
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
        self.balances.insert(to.clone(), new_balance);
    }

    fn increase_total_supply(&mut self, amount: &Tokens) {
        self.total_supply = self
            .total_supply
            .checked_add(amount)
            .unwrap_or_else(|| panic!("Total supply overflow"));
    }
}

impl InMemoryLedger<ApprovalKey, Account, Tokens> {
    pub fn new_from_icrc1_ledger_blocks(
        blocks: &Vec<ic_icrc1::Block<Tokens>>,
    ) -> InMemoryLedger<ApprovalKey, Account, Tokens> {
        let mut state = InMemoryLedger::new();
        for block in blocks {
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
        }
        state
    }
}
