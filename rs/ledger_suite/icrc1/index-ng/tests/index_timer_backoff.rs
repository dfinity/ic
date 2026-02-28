use crate::common::{default_archive_options, install_index_ng, install_ledger};
use candid::{Nat, Principal};
use ic_agent::Identity;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::InitArg;
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_suite_state_machine_helpers::{retrieve_metrics, send_transfer};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use std::time::Duration;

mod common;

const INITIAL_BALANCE: u64 = 1_000_000_000_000;
const TRANSFER_AMOUNT: u64 = 1_000_000;

/// Parse the `index_last_wait_time` metric (in nanoseconds) from the
/// Prometheus metrics endpoint exposed by the index canister and
/// return the value as a [Duration].
fn get_last_wait_time(env: &StateMachine, index_id: CanisterId) -> Duration {
    let metrics = retrieve_metrics(env, index_id);
    for line in &metrics {
        // Skip comment lines and lines that don't start with the metric name.
        if line.starts_with('#') || !line.starts_with("index_last_wait_time") {
            continue;
        }
        // The Prometheus text format is: metric_name [labels] value [timestamp]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let nanos: u64 = parts[1].parse::<f64>().unwrap_or_else(|e| {
                panic!(
                    "metric value should be a valid number, got {:?} in line {:?}: {}",
                    parts[1], line, e
                )
            }) as u64;
            return Duration::from_nanos(nanos);
        }
    }
    panic!("index_last_wait_time metric not found in: {:?}", metrics);
}

fn send_tx(env: &StateMachine, ledger_id: CanisterId, from: Account, to: Account) {
    send_transfer(
        env,
        ledger_id,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(TRANSFER_AMOUNT),
        },
    )
    .expect("transfer should succeed");
}

/// Advance time by `step` and execute a single tick. Repeat `n` times.
fn advance(env: &StateMachine, step: Duration, n: u64) {
    for _ in 0..n {
        env.advance_time(step);
        env.tick();
    }
}

#[test]
fn should_adapt_timer_interval_to_ledger_activity() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .build();

    let a1 = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };
    let a2 = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: None,
    };

    let ledger_id = install_ledger(
        &env,
        vec![(a1, INITIAL_BALANCE)],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );

    let index_id = install_index_ng(
        &env,
        InitArg {
            ledger_id: Principal::from(ledger_id),
            retrieve_blocks_from_ledger_interval_seconds: None,
        },
    );

    // ---------------------------------------------------------------
    // Phase 1: Initial sync — verify the timer starts at 1 s
    // ---------------------------------------------------------------
    // The index was installed with the default interval of 1 s.
    // The ledger has one block (the mint from the initial balance).
    // Advance 1 s and tick to let the first timer fire and sync.
    advance(&env, Duration::from_secs(1), 1);

    // The timer found 1 block (the mint) and halved: 1s / 2 = 0.5s,
    // clamped to the minimum of 1 s.
    let wait_time = get_last_wait_time(&env, index_id);
    assert_eq!(
        wait_time,
        Duration::from_secs(1),
        "After initial sync the timer should be at the minimum of 1 s, got {:?}",
        wait_time
    );

    // ---------------------------------------------------------------
    // Phase 2: Idle — verify the timer doubles until it hits 64 s
    // ---------------------------------------------------------------
    // With no new transactions the timer should back off:
    // 1 → 2 → 4 → 8 → 16 → 32 → 64.
    // The total time for all these fires is:
    //   1 + 2 + 4 + 8 + 16 + 32 + 64 = 127 s.
    // After the fire at 64 s, compute_wait_time(0) doubles to 128 s,
    // which is clamped to the maximum of 64 s.
    advance(&env, Duration::from_secs(1), 130);

    let wait_time = get_last_wait_time(&env, index_id);
    assert_eq!(
        wait_time,
        Duration::from_secs(64),
        "After prolonged idle the timer should have backed off to the maximum of 64 s, got {:?}",
        wait_time
    );

    // ---------------------------------------------------------------
    // Phase 3: New transactions — verify the timer speeds up again
    // ---------------------------------------------------------------
    // Send a transaction every second. This ensures that each time the
    // timer fires, there are pending blocks and it halves its interval.
    // Starting from 64 s, it takes 64 + 32 + 16 + 8 + 4 + 2 = 126 s
    // to reach 1 s.
    for _ in 0..130 {
        send_tx(&env, ledger_id, a1, a2);
        advance(&env, Duration::from_secs(1), 1);
    }

    let wait_time = get_last_wait_time(&env, index_id);
    assert_eq!(
        wait_time,
        Duration::from_secs(1),
        "After continuous transaction activity the timer should speed back up to 1 s, got {:?}",
        wait_time
    );

    // ---------------------------------------------------------------
    // Phase 4: Steady transaction rate — verify the timer oscillates
    // ---------------------------------------------------------------
    // We send one transaction every 24 seconds. The halve/double
    // algorithm causes the timer to oscillate between two values in
    // steady state:
    //   - Timer at 16 s fires, finds a block → halves to 8 s.
    //   - Timer at 8 s fires, no block yet → doubles to 16 s.
    //   - Cycle length: 8 + 16 = 24 s, which matches the tx interval.
    //
    // We run enough rounds for the timer to stabilize and then collect
    // the wait time after each round to verify the oscillation.
    let tx_interval_secs = 24u64;
    let stabilization_rounds = 20u64;
    for _ in 0..stabilization_rounds {
        send_tx(&env, ledger_id, a1, a2);
        advance(&env, Duration::from_secs(1), tx_interval_secs);
    }

    // Collect the wait times over several more rounds to verify
    // the oscillation between 8 s and 16 s.
    let mut observed_wait_times = std::collections::BTreeSet::new();
    let observation_rounds = 10u64;
    for _ in 0..observation_rounds {
        send_tx(&env, ledger_id, a1, a2);
        // Advance one second at a time and sample after every tick so
        // we capture both the post-sync and post-idle wait times.
        for _ in 0..tx_interval_secs {
            advance(&env, Duration::from_secs(1), 1);
            observed_wait_times.insert(get_last_wait_time(&env, index_id));
        }
    }

    let expected: std::collections::BTreeSet<Duration> =
        [Duration::from_secs(8), Duration::from_secs(16)]
            .into_iter()
            .collect();
    assert_eq!(
        observed_wait_times, expected,
        "With transactions every {} s the timer should oscillate between 8 s and 16 s, \
         but observed: {:?}",
        tx_interval_secs, observed_wait_times
    );
}
