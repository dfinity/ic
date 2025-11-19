use crate::{InitArgs, Ledger, StorableAllowance};
use ic_base_types::PrincipalId;
use ic_canister_log::Sink;
use ic_icrc1::{Operation, Transaction};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_canister_core::ledger::{LedgerContext, LedgerTransaction, TxApplyError};
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_suite_state_machine_tests::MINTER;
use ic_ledger_suite_state_machine_tests_constants::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, DECIMAL_PLACES, FEE, INT_META_KEY,
    INT_META_VALUE, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY,
    TEXT_META_VALUE, TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_stable_structures::Storable;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;
use proptest::prelude::*;
use proptest::strategy::Strategy;

use std::time::Duration;

#[derive(Clone)]
struct DummyLogger;

impl Sink for DummyLogger {
    fn append(&self, _entry: ic_canister_log::LogEntry) {}
}

fn test_account_id(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n).into(),
        subaccount: None,
    }
}

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

fn tokens(n: u64) -> Tokens {
    Tokens::from(n)
}

#[cfg(not(feature = "u256-tokens"))]
fn tokens_to_u64(n: ic_icrc1_tokens_u64::U64) -> u64 {
    n.to_u64()
}

#[cfg(feature = "u256-tokens")]
fn tokens_to_u64(n: ic_icrc1_tokens_u256::U256) -> u64 {
    n.try_as_u64().expect("failed to convert to u64")
}

fn ts(n: u64) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(n)
}

fn default_init_args() -> InitArgs {
    InitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: [].to_vec(),
        transfer_fee: FEE.into(),
        decimals: Some(DECIMAL_PLACES),
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    }
}

#[test]
fn test_approvals_are_not_cumulative() {
    let now = ts(12345678);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(100_000)).unwrap();

    let approved_amount = tokens(150_000);
    let fee = tokens(10_000);

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: approved_amount,
            expected_allowance: None,
            expires_at: None,
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(ctx.balances().account_balance(&spender), tokens(0));

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: approved_amount,
            expires_at: None,
            arrived_at: ts(0),
        },
    );

    let new_allowance = tokens(200_000);

    let expiration = now + Duration::from_secs(300);
    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: new_allowance,
            expected_allowance: None,
            expires_at: Some(expiration.as_nanos_since_unix_epoch()),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000));
    assert_eq!(ctx.balances().account_balance(&spender), tokens(0));
    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: new_allowance,
            expires_at: Some(expiration),
            arrived_at: ts(0),
        }
    );
}

#[test]
fn test_approval_transfer_from() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let to = test_account_id(3);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();
    let fee = tokens(10_000);

    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(0)
        }
    );

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: tokens(150_000),
            expected_allowance: None,
            expires_at: None,
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(190_000));

    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&to), tokens(100_000));
    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000));

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(40_000),
            expires_at: None,
            arrived_at: ts(0),
        },
    );

    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(40_000)
        }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(40_000),
            expires_at: None,
            arrived_at: ts(0),
        },
    );
    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000),);
    assert_eq!(ctx.balances().account_balance(&to), tokens(100_000),);
}

#[test]
fn test_approval_expiration_override() {
    let now = ts(1000);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();

    let approve = |amount: u64, expires_at: Option<TimeStamp>| Operation::Approve {
        from,
        spender,
        amount: tokens(amount),
        expected_allowance: None,
        expires_at: expires_at.map(|e| e.as_nanos_since_unix_epoch()),
        fee: Some(tokens(10_000)),
    };
    let tr = Transaction {
        operation: approve(100_000, Some(ts(2000))),
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(100_000),
            expires_at: Some(ts(2000)),
            arrived_at: ts(0),
        },
    );

    let tr = Transaction {
        operation: approve(200_000, Some(ts(1500))),
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(200_000),
            expires_at: Some(ts(1500)),
            arrived_at: ts(0),
        },
    );

    let tr = Transaction {
        operation: approve(300_000, Some(ts(2500))),
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(300_000),
            expires_at: Some(ts(2500)),
            arrived_at: ts(0),
        },
    );

    // The expiration is in the past, the allowance is rejected.
    let tr = Transaction {
        operation: approve(100_000, Some(ts(500))),
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::ExpiredApproval { now }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(300_000),
            expires_at: Some(ts(2500)),
            arrived_at: ts(0),
        },
    );
}

#[test]
fn test_approval_no_fee_on_reject() {
    let now = ts(1000);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(20_000)).unwrap();

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: tokens(1_000),
            expected_allowance: None,
            expires_at: Some(1),
            fee: Some(tokens(10_000)),
        },
        created_at_time: Some(1000),
        memo: None,
    };

    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::ExpiredApproval { now }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance::default(),
    );

    assert_eq!(ctx.balances().account_balance(&from), tokens(20_000));
}

#[test]
fn test_self_transfer_from() {
    let now = ts(1000);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let to = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(100_000)).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &from, now),
        Allowance::default(),
    );

    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(from),
            amount: tokens(20_000),
            fee: Some(tokens(10_000)),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(70_000));
    assert_eq!(ctx.balances().account_balance(&to), tokens(20_000));
}

#[test]
fn test_approval_allowance_covers_fee() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let to = test_account_id(3);

    ctx.balances_mut().mint(&from, tokens(20_000)).unwrap();

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: tokens(10_000),
            expected_allowance: None,
            expires_at: None,
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    let fee = tokens(10_000);
    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(10_000),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(10_000)
        }
    );

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: tokens(20_000),
            expected_allowance: None,
            expires_at: None,
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    let tr = Transaction {
        operation: Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(10_000),
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(0));
    assert_eq!(ctx.balances().account_balance(&to), tokens(10_000));

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(0),
            expires_at: None,
            arrived_at: ts(0),
        },
    );
}

#[test]
fn test_burn_smoke() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();

    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 200_000);

    let tr = Transaction {
        operation: Operation::Burn {
            from,
            spender: None,
            amount: tokens(100_000),
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(100_000));
    assert_eq!(ctx.balances().total_supply(), tokens(100_000));
}

#[test]
fn test_approval_burn_from() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);
    let spender = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();
    let fee = tokens(10_000);

    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 200_000);

    let tr = Transaction {
        operation: Operation::Burn {
            from,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: Tokens::ZERO
        }
    );

    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 200_000);

    let tr = Transaction {
        operation: Operation::Approve {
            from,
            spender,
            amount: tokens(150_000),
            expected_allowance: None,
            expires_at: None,
            fee: Some(fee),
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(190_000));
    assert_eq!(ctx.balances().total_supply(), tokens(190_000));

    let tr = Transaction {
        operation: Operation::Burn {
            from,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    tr.apply(&mut ctx, now, Tokens::ZERO).unwrap();

    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 90_000);

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(50_000),
            expires_at: None,
            arrived_at: ts(0),
        },
    );

    let tr = Transaction {
        operation: Operation::Burn {
            from,
            spender: Some(spender),
            amount: tokens(100_000),
            fee: None,
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(50_000)
        }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(50_000),
            expires_at: None,
            arrived_at: ts(0),
        },
    );
    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 90_000);
}

#[cfg(not(feature = "u256-tokens"))]
fn arb_token() -> impl Strategy<Value = Tokens> {
    any::<u64>().prop_map(Tokens::new)
}

#[cfg(feature = "u256-tokens")]
fn arb_token() -> impl Strategy<Value = Tokens> {
    (any::<u128>(), any::<u128>()).prop_map(|(hi, lo)| Tokens::from_words(hi, lo))
}

#[test_strategy::proptest]
fn allowance_serialization(#[strategy(arb_allowance())] allowance: Allowance<Tokens>) {
    let storable_allowance: StorableAllowance = allowance.clone().into();
    let new_allowance: Allowance<Tokens> =
        StorableAllowance::from_bytes(storable_allowance.to_bytes()).into();
    prop_assert_eq!(new_allowance.amount, allowance.amount);
    prop_assert_eq!(new_allowance.expires_at, allowance.expires_at);
    prop_assert_eq!(
        new_allowance.arrived_at,
        TimeStamp::from_nanos_since_unix_epoch(0)
    );
}

fn arb_timestamp() -> impl Strategy<Value = TimeStamp> {
    any::<u64>().prop_map(TimeStamp::from_nanos_since_unix_epoch)
}
fn arb_opt_expiration() -> impl Strategy<Value = Option<TimeStamp>> {
    proptest::option::of(any::<u64>().prop_map(TimeStamp::from_nanos_since_unix_epoch))
}
fn arb_allowance() -> impl Strategy<Value = Allowance<Tokens>> {
    (arb_token(), arb_opt_expiration(), arb_timestamp()).prop_map(
        |(amount, expires_at, arrived_at)| Allowance {
            amount,
            expires_at,
            arrived_at,
        },
    )
}

#[test]
fn test_burn_fee_error() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let from = test_account_id(1);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();

    assert_eq!(tokens_to_u64(ctx.balances().total_supply()), 200_000);

    let tr = Transaction {
        operation: Operation::Burn {
            from,
            spender: None,
            amount: tokens(1_000),
            fee: Some(tokens(10_000)),
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::BurnOrMintFee
    );
}

#[test]
fn test_mint_fee_error() {
    let now = ts(1);

    let mut ctx = Ledger::from_init_args(DummyLogger, default_init_args(), now);

    let to = test_account_id(1);

    let tr = Transaction {
        operation: Operation::Mint {
            to,
            amount: tokens(1_000),
            fee: Some(tokens(10_000)),
        },
        created_at_time: None,
        memo: None,
    };
    assert_eq!(
        tr.apply(&mut ctx, now, Tokens::ZERO).unwrap_err(),
        TxApplyError::BurnOrMintFee
    );
}
