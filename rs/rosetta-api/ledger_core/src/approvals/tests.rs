use std::collections::HashSet;

use super::*;
use crate::timestamp::TimeStamp;
use crate::tokens::Tokens;
use std::cmp;

fn ts(n: u64) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(n)
}

fn tokens(n: u64) -> Tokens {
    Tokens::from_e8s(n)
}

#[derive(PartialEq, Eq, Hash, Clone, Default, PartialOrd, Ord)]
struct Account(u64);

type TestAllowanceTable = AllowanceTable<HeapAllowancesData<Account, Tokens>>;

#[test]
fn allowance_table_default() {
    assert_eq!(
        TestAllowanceTable::default().allowance(&Account(1), &Account(1), ts(1)),
        Allowance::default()
    );
}

#[test]
fn allowance_table_not_cumulative() {
    let mut table = TestAllowanceTable::default();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(1)),
        Allowance::default()
    );

    table
        .approve(&Account(1), &Account(2), tokens(5), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(1)),
        Allowance {
            amount: tokens(5),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    table
        .approve(&Account(1), &Account(2), tokens(15), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(1)),
        Allowance {
            amount: tokens(15),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(10),
            Some(ts(5)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(1)),
        Allowance {
            amount: tokens(10),
            expires_at: Some(ts(5)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance::default()
    );
}

#[test]
fn allowance_use_approval() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Account(2), tokens(100), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table
            .use_allowance(&Account(1), &Account(2), tokens(40), ts(1))
            .unwrap(),
        tokens(60)
    );

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(60),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    assert_eq!(
        table
            .use_allowance(&Account(1), &Account(2), tokens(100), ts(1))
            .unwrap_err(),
        InsufficientAllowance(tokens(60))
    );

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(60),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );
}

#[test]
fn allowance_table_pruning() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Account(3), tokens(100), None, ts(1), None)
        .unwrap();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 2);

    assert_eq!(table.prune(ts(200), 0), 0);
    assert_eq!(table.prune(ts(200), 1), 1);

    assert_eq!(table.len(), 1);
}

#[test]
fn allowance_table_pruning_obsolete_expirations() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(150),
            Some(ts(300)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 1);

    assert_eq!(table.prune(ts(200), 100), 0);

    assert_eq!(table.len(), 1);

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(200)),
        Allowance {
            amount: tokens(150),
            expires_at: Some(ts(300)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );
}

#[test]
fn allowance_table_pruning_expired_approvals() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    table
        .approve(
            &Account(1),
            &Account(3),
            tokens(150),
            Some(ts(300)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 2);

    assert_eq!(table.prune(ts(200), 100), 1);

    assert_eq!(table.len(), 1);

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(200)),
        Allowance {
            amount: tokens(0),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        }
    );
    assert_eq!(
        table.allowance(&Account(1), &Account(3), ts(200)),
        Allowance {
            amount: tokens(150),
            expires_at: Some(ts(300)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );
}

#[test]
fn allowance_table_pruning_used_allowance() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 1);

    table
        .use_allowance(&Account(1), &Account(2), tokens(100), ts(1))
        .unwrap();
    assert_eq!(table.len(), 0);
}

#[test]
fn allowance_table_pruning_zero_allowance() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 1);

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(0),
            Some(ts(100)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(table.len(), 0);
}

#[test]
fn expected_allowance_checked() {
    let mut table = TestAllowanceTable::default();

    assert_eq!(
        table
            .approve(
                &Account(1),
                &Account(2),
                tokens(100),
                None,
                ts(1),
                Some(tokens(100))
            )
            .unwrap_err(),
        ApproveError::AllowanceChanged {
            current_allowance: tokens(0)
        }
    );

    table
        .approve(&Account(1), &Account(2), tokens(100), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(100),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    table
        .approve(&Account(1), &Account(2), tokens(200), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(200),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    assert_eq!(
        table
            .approve(
                &Account(1),
                &Account(2),
                tokens(300),
                None,
                ts(1),
                Some(tokens(100))
            )
            .unwrap_err(),
        ApproveError::AllowanceChanged {
            current_allowance: tokens(200)
        }
    );

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(300),
            None,
            ts(1),
            Some(tokens(200)),
        )
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(300),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );

    // Approve new spender while expecting 0 tokens allowance.
    table
        .approve(
            &Account(1),
            &Account(3),
            tokens(100),
            None,
            ts(1),
            Some(tokens(0)),
        )
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(3), ts(5)),
        Allowance {
            amount: tokens(100),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(1),
        }
    );
}

#[test]
fn disallow_self_approval() {
    let mut table = TestAllowanceTable::default();

    assert_eq!(
        table
            .approve(
                &Account(1),
                &Account(1),
                tokens(100),
                None,
                ts(1),
                Some(tokens(100))
            )
            .unwrap_err(),
        ApproveError::SelfApproval
    );
}

#[test]
fn allowance_table_remove_zero_allowance() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Account(2), tokens(100), None, ts(1), None)
        .unwrap();

    assert_eq!(table.len(), 1);

    table
        .approve(&Account(1), &Account(2), tokens(0), None, ts(1), None)
        .unwrap();

    assert_eq!(table.len(), 0);

    table
        .approve(&Account(1), &Account(3), tokens(0), None, ts(1), None)
        .unwrap();

    assert_eq!(table.len(), 0);
}

#[test]
fn allowance_table_select_approvals_for_trimming() {
    let mut table = TestAllowanceTable::default();

    let approvals_len = 10;
    for i in 1..approvals_len + 1 {
        let expiration = if i > 5 { None } else { Some(ts(20 - i)) };
        table
            .approve(
                &Account(0),
                &Account(i),
                tokens(100),
                expiration,
                ts(i),
                None,
            )
            .unwrap();
    }

    for i in 0..approvals_len + 2 {
        let remove = table.select_approvals_to_trim(i as usize);
        let remove_set: HashSet<(Account, Account)> = remove.into_iter().collect();
        assert_eq!(remove_set.len(), cmp::min(i, approvals_len) as usize);

        for spender in 1..i + 1 {
            assert!(
                i > approvals_len || remove_set.contains(&(Account(0), Account(spender))),
                "approval for spender {} should be selected for trimming",
                spender
            );
        }
    }

    fn spender_id(approval_key: &(Account, Account)) -> u64 {
        approval_key.1 .0
    }

    let remove = table.select_approvals_to_trim(1);
    assert_eq!(remove.len(), 1);
    assert_eq!(spender_id(&remove[0]), 1);

    // Update the approval to change its place in the prune queue.
    table
        .approve(
            &Account(0),
            &Account(1),
            tokens(100),
            Some(ts(15)),
            ts(14),
            None,
        )
        .unwrap();

    let remove = table.select_approvals_to_trim(1);
    assert_eq!(remove.len(), 1);
    assert_eq!(spender_id(&remove[0]), 2);

    // Use up the allowance to remove it from the prune queue.
    table
        .use_allowance(&Account(0), &Account(2), tokens(100), ts(1))
        .unwrap();

    let remove = table.select_approvals_to_trim(1);
    assert_eq!(remove.len(), 1);
    assert_eq!(spender_id(&remove[0]), 3);

    // Reset the allowance to zero; the approval should be removed from the queue.
    table
        .approve(&Account(0), &Account(3), tokens(0), None, ts(15), None)
        .unwrap();

    let remove = table.select_approvals_to_trim(1);
    assert_eq!(remove.len(), 1);
    assert_eq!(spender_id(&remove[0]), 4);
    // approvals for 2 and 3 were removed
    assert_eq!(
        table.select_approvals_to_trim(100).len(),
        approvals_len as usize - 2
    );
}

#[test]
fn arrival_table_updated_correctly() {
    let mut table = TestAllowanceTable::default();

    // Adding approvals for the same (account, spender) pair more than 2 times
    // resulted in the arrival_queue not being updated correctly. The old elements
    // were left in the queue instead of being replaced by new elements.
    // If not fixed, this would trigger the debug_assert in check_postconditions.
    // Fixed in https://gitlab.com/dfinity-lab/public/ic/-/merge_requests/15265
    // Released as https://dashboard.internetcomputer.org/proposal/125000
    for i in 0..6 {
        table
            .approve(&Account(1), &Account(2), tokens(i), None, ts(i), None)
            .unwrap();
    }
}

#[test]
fn expected_allowance_not_checked_against_expired() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(5),
            Some(ts(2)),
            ts(1),
            None,
        )
        .unwrap();

    assert_eq!(
        table
            .approve(
                &Account(1),
                &Account(2),
                tokens(100),
                None,
                ts(1),
                Some(tokens(0))
            )
            .unwrap_err(),
        ApproveError::AllowanceChanged {
            current_allowance: tokens(5)
        }
    );

    table
        .approve(
            &Account(1),
            &Account(2),
            tokens(100),
            None,
            ts(2),
            Some(tokens(0)),
        )
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(3)),
        Allowance {
            amount: tokens(100),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(2),
        }
    );
}

#[test]
fn expected_allowance_if_zero_no_approval() {
    let mut table = TestAllowanceTable::default();

    // If there were no approvals present, we used to always accept 0 approvals
    // without checking the expected_allowance.
    assert_eq!(
        table
            .approve(
                &Account(1),
                &Account(2),
                tokens(0),
                None,
                ts(1),
                Some(tokens(4))
            )
            .unwrap_err(),
        ApproveError::AllowanceChanged {
            current_allowance: tokens(0)
        }
    );
}
