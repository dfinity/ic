use std::collections::HashSet;

use super::*;
use crate::timestamp::TimeStamp;
use crate::tokens::Tokens;
use serde::{Deserialize, Serialize};
use std::cmp;

fn ts(n: u64) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(n)
}

fn tokens(n: u64) -> Tokens {
    Tokens::from_e8s(n)
}

#[derive(PartialEq, Eq, Hash)]
struct Account(u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Key(u64, u64);

impl From<(&Account, &Account)> for Key {
    fn from((a, s): (&Account, &Account)) -> Self {
        Self(a.0, s.0)
    }
}

impl From<Key> for (Account, Account) {
    fn from(key: Key) -> Self {
        (Account(key.0), Account(key.1))
    }
}

type TestAllowanceTable = AllowanceTable<Key, Account, Tokens>;

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
            expires_at: None
        }
    );

    table
        .approve(&Account(1), &Account(2), tokens(15), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(1)),
        Allowance {
            amount: tokens(15),
            expires_at: None
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
            expires_at: Some(ts(5))
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
            expires_at: None
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
            expires_at: None
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
            expires_at: Some(ts(300))
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
            expires_at: None
        }
    );
    assert_eq!(
        table.allowance(&Account(1), &Account(3), ts(200)),
        Allowance {
            amount: tokens(150),
            expires_at: Some(ts(300))
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
            expires_at: None
        }
    );

    table
        .approve(&Account(1), &Account(2), tokens(200), None, ts(1), None)
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Account(2), ts(5)),
        Allowance {
            amount: tokens(200),
            expires_at: None
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
            expires_at: None
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
            expires_at: None
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
        let expiration = if i > 5 { None } else { Some(ts(i)) };
        table
            .approve(
                &Account(0),
                &Account(i),
                tokens(100),
                expiration,
                ts(0),
                None,
            )
            .unwrap();
    }

    for i in 0..approvals_len + 2 {
        let remove = table.select_approvals_to_trim(i as usize);
        let remove_set: HashSet<(Account, Account)> = remove.into_iter().collect();
        assert_eq!(remove_set.len(), cmp::min(i, approvals_len) as usize);
    }
}
