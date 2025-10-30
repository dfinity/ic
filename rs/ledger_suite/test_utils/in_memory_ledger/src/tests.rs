use crate::{ApprovalKey, InMemoryLedger, InMemoryLedgerState};
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_types::PrincipalId;
#[cfg(feature = "icp-tokens")]
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::account::Account;

const ACCOUNT_ID_1: u64 = 134;
const ACCOUNT_ID_2: u64 = 256;
const ACCOUNT_ID_3: u64 = 378;
const MINT_AMOUNT: u64 = 1_000_000u64;
const BURN_AMOUNT: u64 = 500_000u64;
const TRANSFER_AMOUNT: u64 = 200_000u64;
const APPROVE_AMOUNT: u64 = 250_000u64;
const ANOTHER_APPROVE_AMOUNT: u64 = 700_000u64;
const ZERO_AMOUNT: u64 = 0u64;
const FEE_AMOUNT: u64 = 10_000u64;
const TIMESTAMP_NOW: u64 = 0;
const TIMESTAMP_LATER: u64 = 1;
const TIMESTAMP_EVEN_LATER: u64 = 2;

#[cfg(not(any(feature = "u256-tokens", feature = "icp-tokens")))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(all(feature = "u256-tokens", not(feature = "icp-tokens")))]
type Tokens = ic_icrc1_tokens_u256::U256;

#[cfg(feature = "icp-tokens")]
type Tokens = ic_ledger_core::Tokens;

#[cfg(feature = "icp-tokens")]
type AccountType = AccountIdentifier;

#[cfg(not(feature = "icp-tokens"))]
type AccountType = Account;

struct LedgerBuilder {
    ledger: InMemoryLedger<AccountType, Tokens>,
}

impl LedgerBuilder {
    fn new() -> Self {
        Self {
            ledger: InMemoryLedger::default(),
        }
    }

    fn with_mint(mut self, to: &AccountType, amount: &Tokens) -> Self {
        self.ledger.process_mint(to, amount);
        self.ledger.validate_invariants();
        self
    }

    fn with_burn(
        mut self,
        from: &AccountType,
        spender: &Option<AccountType>,
        amount: &Tokens,
    ) -> Self {
        let irrelevant_index = 0;
        self.ledger
            .process_burn(from, spender, amount, irrelevant_index);
        self.ledger.validate_invariants();
        self
    }

    fn with_transfer(
        mut self,
        from: &AccountType,
        to: &AccountType,
        spender: &Option<AccountType>,
        amount: &Tokens,
        fee: &Option<Tokens>,
    ) -> Self {
        self.ledger.process_transfer(from, to, spender, amount, fee);
        self.ledger.validate_invariants();
        self
    }

    fn with_approve(
        mut self,
        from: &AccountType,
        spender: &AccountType,
        amount: &Tokens,
        expected_allowance: &Option<Tokens>,
        expires_at: &Option<u64>,
        fee: &Option<Tokens>,
        now: TimeStamp,
    ) -> Self {
        self.ledger.process_approve(
            from,
            spender,
            amount,
            expected_allowance,
            expires_at,
            fee,
            now,
        );
        self.ledger.validate_invariants();
        self
    }

    fn build(self) -> InMemoryLedger<AccountType, Tokens> {
        self.ledger
    }
}

#[test]
fn should_increase_balance_and_total_supply_with_mint() {
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .build();

    assert_eq!(ledger.balances.len(), 1);
    assert!(ledger.allowances.is_empty());
    assert_eq!(ledger.total_supply, Tokens::from(MINT_AMOUNT));
    let actual_balance = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&Tokens::from(MINT_AMOUNT)), actual_balance);
    assert_eq!(ledger.total_supply, Tokens::from(MINT_AMOUNT));
}

#[test]
fn should_decrease_balance_with_burn() {
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_burn(
            &account_from_u64(ACCOUNT_ID_1),
            &None,
            &Tokens::from(BURN_AMOUNT),
        )
        .build();

    let expected_balance = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(BURN_AMOUNT))
        .unwrap();

    assert_eq!(ledger.total_supply, expected_balance);
    assert_eq!(ledger.balances.len(), 1);
    assert!(ledger.allowances.is_empty());
    let actual_balance = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance), actual_balance);
}

#[test]
fn should_remove_balance_with_burn() {
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_burn(
            &account_from_u64(ACCOUNT_ID_1),
            &None,
            &Tokens::from(MINT_AMOUNT),
        )
        .build();

    assert_eq!(&ledger.total_supply, &Tokens::from(ZERO_AMOUNT));
    assert!(ledger.balances.is_empty());
    assert!(ledger.allowances.is_empty());
    let actual_balance = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(None, actual_balance);
}

#[test]
fn should_increase_and_decrease_balance_with_transfer() {
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_transfer(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &None,
            &Tokens::from(TRANSFER_AMOUNT),
            &Some(Tokens::from(FEE_AMOUNT)),
        )
        .build();

    let expected_balance1 = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(TRANSFER_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();

    assert_eq!(
        ledger.total_supply,
        Tokens::from(MINT_AMOUNT)
            .checked_sub(&Tokens::from(FEE_AMOUNT))
            .unwrap()
    );
    assert_eq!(ledger.balances.len(), 2);
    assert!(ledger.allowances.is_empty());
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let actual_balance2 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_2));
    assert_eq!(Some(&Tokens::from(TRANSFER_AMOUNT)), actual_balance2);
}

#[test]
fn should_remove_balances_with_transfer() {
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(FEE_AMOUNT))
        .with_transfer(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &None,
            &Tokens::from(ZERO_AMOUNT),
            &Some(Tokens::from(FEE_AMOUNT)),
        )
        .build();

    assert_eq!(ledger.total_supply, Tokens::from(ZERO_AMOUNT));
    assert!(ledger.balances.is_empty());
}

#[test]
fn should_increase_allowance_with_approve() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .build();

    let expected_balance1 = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();
    assert_eq!(ledger.total_supply, expected_balance1);
    assert_eq!(ledger.balances.len(), 1);
    assert_eq!(ledger.allowances.len(), 1);
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    let expected_allowance2: Allowance<Tokens> = Allowance {
        amount: Tokens::from(APPROVE_AMOUNT),
        expires_at: None,
        arrived_at: now,
    };
    assert_eq!(account2_allowance, Some(&expected_allowance2));
}

#[test]
fn should_reset_allowance_with_second_approve() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let later = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_LATER);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(ANOTHER_APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            later,
        )
        .build();

    let expected_balance1 = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();
    assert_eq!(ledger.total_supply, expected_balance1);
    assert_eq!(ledger.balances.len(), 1);
    assert_eq!(ledger.allowances.len(), 1);
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    let expected_allowance2: Allowance<Tokens> = Allowance {
        amount: Tokens::from(ANOTHER_APPROVE_AMOUNT),
        expires_at: None,
        arrived_at: later,
    };
    assert_eq!(account2_allowance, Some(&expected_allowance2));
}

#[test]
fn should_remove_allowance_when_set_to_zero() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let later = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_LATER);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(ZERO_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            later,
        )
        .build();

    let expected_balance1 = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();
    assert_eq!(ledger.total_supply, expected_balance1);
    assert_eq!(ledger.balances.len(), 1);
    assert!(ledger.allowances.is_empty());
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    assert_eq!(account2_allowance, None);
}

#[test]
fn should_set_allowance_with_expected_allowance_and_no_existing_allowance() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &Some(Tokens::from(0u64)),
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .build();

    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    let expected_allowance2: Allowance<Tokens> = Allowance {
        amount: Tokens::from(APPROVE_AMOUNT),
        expires_at: None,
        arrived_at: now,
    };
    assert_eq!(account2_allowance, Some(&expected_allowance2));
}

#[test]
fn should_set_allowance_with_expected_allowance_and_existing_allowance() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(ANOTHER_APPROVE_AMOUNT),
            &Some(Tokens::from(APPROVE_AMOUNT)),
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .build();

    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    let expected_allowance2: Allowance<Tokens> = Allowance {
        amount: Tokens::from(ANOTHER_APPROVE_AMOUNT),
        expires_at: None,
        arrived_at: now,
    };
    assert_eq!(account2_allowance, Some(&expected_allowance2));
}

#[test]
fn should_set_allowance_with_expected_allowance_and_expired_existing_allowance() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let even_later = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_EVEN_LATER);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &Some(TIMESTAMP_LATER),
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(ANOTHER_APPROVE_AMOUNT),
            &Some(Tokens::from(0u64)),
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            even_later,
        )
        .build();

    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    let expected_allowance2: Allowance<Tokens> = Allowance {
        amount: Tokens::from(ANOTHER_APPROVE_AMOUNT),
        expires_at: None,
        arrived_at: even_later,
    };
    assert_eq!(account2_allowance, Some(&expected_allowance2));
}

#[test]
#[should_panic(expected = "does not match in-memory allowance")]
fn should_panic_if_expected_allowance_different_than_existing_allowance() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &Some(Tokens::from(0u64)),
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &Some(Tokens::from(0u64)),
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .build();
}

#[test]
fn should_remove_allowance_when_used_up() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT)
                .checked_add(&Tokens::from(FEE_AMOUNT))
                .unwrap(),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_transfer(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_3),
            &Some(account_from_u64(ACCOUNT_ID_2)),
            &Tokens::from(APPROVE_AMOUNT),
            &Some(Tokens::from(FEE_AMOUNT)),
        )
        .build();

    let expected_total_supply = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();
    let expected_balance1 = expected_total_supply
        .checked_sub(&Tokens::from(APPROVE_AMOUNT))
        .unwrap();
    assert_eq!(ledger.total_supply, expected_total_supply);
    assert_eq!(ledger.balances.len(), 2);
    assert!(ledger.allowances.is_empty());
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let actual_balance3 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_3));
    assert_eq!(Some(&Tokens::from(APPROVE_AMOUNT)), actual_balance3);
    let allowance_key = ApprovalKey::from((
        &account_from_u64(ACCOUNT_ID_1),
        &account_from_u64(ACCOUNT_ID_2),
    ));
    let account2_allowance = ledger.allowances.get(&allowance_key);
    assert_eq!(account2_allowance, None);
}

#[test]
fn should_increase_and_decrease_balance_with_transfer_from() {
    let now = TimeStamp::from_nanos_since_unix_epoch(TIMESTAMP_NOW);
    let ledger = LedgerBuilder::new()
        .with_mint(&account_from_u64(ACCOUNT_ID_1), &Tokens::from(MINT_AMOUNT))
        .with_approve(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_2),
            &Tokens::from(APPROVE_AMOUNT),
            &None,
            &None,
            &Some(Tokens::from(FEE_AMOUNT)),
            now,
        )
        .with_transfer(
            &account_from_u64(ACCOUNT_ID_1),
            &account_from_u64(ACCOUNT_ID_3),
            &Some(account_from_u64(ACCOUNT_ID_2)),
            &Tokens::from(TRANSFER_AMOUNT),
            &Some(Tokens::from(FEE_AMOUNT)),
        )
        .build();

    let expected_balance1 = Tokens::from(MINT_AMOUNT)
        .checked_sub(&Tokens::from(TRANSFER_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap()
        .checked_sub(&Tokens::from(FEE_AMOUNT))
        .unwrap();

    assert_eq!(
        ledger.total_supply,
        Tokens::from(MINT_AMOUNT)
            .checked_sub(&Tokens::from(FEE_AMOUNT))
            .unwrap()
            .checked_sub(&Tokens::from(FEE_AMOUNT))
            .unwrap()
    );
    assert_eq!(ledger.balances.len(), 2);
    assert_eq!(ledger.allowances.len(), 1);
    let actual_balance1 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_1));
    assert_eq!(Some(&expected_balance1), actual_balance1);
    let actual_balance3 = ledger.balances.get(&account_from_u64(ACCOUNT_ID_3));
    assert_eq!(Some(&Tokens::from(TRANSFER_AMOUNT)), actual_balance3);
}

fn account_from_u64(account_id: u64) -> AccountType {
    AccountType::from(Account {
        owner: PrincipalId::new_user_test_id(account_id).0,
        subaccount: None,
    })
}
