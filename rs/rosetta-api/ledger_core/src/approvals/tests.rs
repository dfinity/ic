use super::*;
use crate::timestamp::TimeStamp;
use crate::tokens::Tokens;
use serde::{Deserialize, Serialize};

fn ts(n: u64) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(n)
}

fn tokens(n: u64) -> Tokens {
    Tokens::from_e8s(n)
}

struct Account(u64);
struct Spender(u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Key(u64, u64);

impl From<(&Account, &Spender)> for Key {
    fn from((a, s): (&Account, &Spender)) -> Self {
        Self(a.0, s.0)
    }
}

type TestAllowanceTable = AllowanceTable<Key, Account, Spender>;

#[test]
fn allowance_table_default() {
    assert_eq!(
        TestAllowanceTable::default().allowance(&Account(1), &Spender(1), ts(1)),
        Allowance::default()
    );
}

#[test]
fn allowance_table_cumulative() {
    let mut table = TestAllowanceTable::default();

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(1)),
        Allowance::default()
    );

    table
        .approve(&Account(1), &Spender(1), tokens(5), None, ts(1))
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(1)),
        Allowance {
            amount: tokens(5),
            expires_at: None
        }
    );

    table
        .approve(&Account(1), &Spender(1), tokens(15), None, ts(1))
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(1)),
        Allowance {
            amount: tokens(20),
            expires_at: None
        }
    );

    table
        .approve(&Account(1), &Spender(1), tokens(10), Some(ts(5)), ts(1))
        .unwrap();

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(1)),
        Allowance {
            amount: tokens(30),
            expires_at: Some(ts(5))
        }
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance::default()
    );
}

#[test]
fn allowance_use_approval() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Spender(1), tokens(100), None, ts(1))
        .unwrap();

    assert_eq!(
        table
            .use_allowance(&Account(1), &Spender(1), tokens(40), ts(1))
            .unwrap(),
        tokens(60)
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance {
            amount: tokens(60),
            expires_at: None
        }
    );

    assert_eq!(
        table
            .use_allowance(&Account(1), &Spender(1), tokens(100), ts(1))
            .unwrap_err(),
        InsufficientAllowance(tokens(60))
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance {
            amount: tokens(60),
            expires_at: None
        }
    );
}

#[test]
fn decrease_allowance() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Spender(1), tokens(100), None, ts(1))
        .unwrap();

    assert_eq!(
        table
            .decrease_allowance(&Account(1), &Spender(1), tokens(40), Some(ts(100)), ts(1))
            .unwrap(),
        tokens(60)
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance {
            amount: tokens(60),
            expires_at: Some(ts(100)),
        }
    );

    assert_eq!(
        table
            .decrease_allowance(&Account(1), &Spender(1), tokens(40), None, ts(1))
            .unwrap(),
        tokens(20)
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance {
            amount: tokens(20),
            expires_at: None,
        }
    );

    assert_eq!(
        table
            .decrease_allowance(&Account(1), &Spender(1), tokens(40), None, ts(1))
            .unwrap(),
        tokens(0)
    );

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(5)),
        Allowance::default()
    );
}

#[test]
fn allowance_table_pruning() {
    let mut table = TestAllowanceTable::default();

    table
        .approve(&Account(1), &Spender(1), tokens(100), None, ts(1))
        .unwrap();

    table
        .approve(&Account(1), &Spender(2), tokens(100), Some(ts(100)), ts(1))
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
        .approve(&Account(1), &Spender(1), tokens(100), Some(ts(100)), ts(1))
        .unwrap();

    table
        .approve(&Account(1), &Spender(1), tokens(100), Some(ts(300)), ts(1))
        .unwrap();

    assert_eq!(table.len(), 1);

    assert_eq!(table.prune(ts(200), 100), 0);

    assert_eq!(table.len(), 1);

    assert_eq!(
        table.allowance(&Account(1), &Spender(1), ts(200)),
        Allowance {
            amount: tokens(200),
            expires_at: Some(ts(300))
        }
    );
}
