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
    in_memory_ledger.process_transfer(&account1, &account2, &None, &transfer_amount, &Some(fee));
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
    in_memory_ledger.process_transfer(&account1, &account2, &None, &transfer_amount, &Some(fee));
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
