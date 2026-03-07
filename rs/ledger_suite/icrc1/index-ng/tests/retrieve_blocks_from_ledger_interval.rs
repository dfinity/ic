use crate::common::{
    STARTING_CYCLES_PER_CANISTER, default_archive_options, index_ng_wasm, install_index_ng,
    install_ledger, wait_until_sync_is_completed,
};
use candid::{CandidType, Deserialize, Encode, Principal};
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_icrc1_index_ng::{IndexArg, InitArg, UpgradeArg};
use ic_icrc1_test_utils::minter_identity;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder, UserError};
use ic_types::{Cycles, Time};
use proptest::prelude::Strategy;
use proptest::test_runner::TestRunner;
use std::time::{Duration, SystemTime};

mod common;

// Corresponds to ic_icrc1_index_ng::MIN_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS
const MIN_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS: u64 = 1;
// Corresponds to ic_icrc1_index_ng::MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS
const MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS: u64 = 10;
const GENESIS: Time = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);

struct TimerIntervals {
    legacy_interval: Option<u64>,
    min_interval_seconds: Option<u64>,
    max_interval_seconds: Option<u64>,
}

fn install_and_upgrade(
    install_intervals: &TimerIntervals,
    upgrade_intervals: &TimerIntervals,
) -> Result<(), UserError> {
    let env = &StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .with_time(GENESIS)
        .build();
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );
    let args = IndexArg::Init(ic_icrc1_index_ng::InitArg {
        ledger_id: Principal::from(ledger_id),
        #[allow(deprecated)]
        retrieve_blocks_from_ledger_interval_seconds: install_intervals.legacy_interval,
        min_retrieve_blocks_from_ledger_interval_seconds: install_intervals.min_interval_seconds,
        max_retrieve_blocks_from_ledger_interval_seconds: install_intervals.max_interval_seconds,
    });
    let index_id = env.install_canister_with_cycles(
        index_ng_wasm(),
        Encode!(&args).unwrap(),
        None,
        Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        #[allow(deprecated)]
        retrieve_blocks_from_ledger_interval_seconds: upgrade_intervals.legacy_interval,
        min_retrieve_blocks_from_ledger_interval_seconds: upgrade_intervals.min_interval_seconds,
        max_retrieve_blocks_from_ledger_interval_seconds: upgrade_intervals.max_interval_seconds,
    });
    env.upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    Ok(())
}

fn max_value_for_interval() -> u64 {
    (u64::MAX - GENESIS.as_nanos_since_unix_epoch()) / 1_000_000_000
}

#[test]
fn should_install_and_upgrade_with_large_interval_value() {
    // Large values for retrieve_blocks_from_ledger_interval_seconds are clamped
    // to the adaptive timer's [MIN, MAX] range. They should no longer cause errors.
    let large_value = max_value_for_interval() - 1;
    let install_and_upgrade_combinations =
        [(Some(large_value), Some(1)), (Some(1), Some(large_value))];
    for (install_interval, upgrade_interval) in &install_and_upgrade_combinations {
        assert_eq!(
            install_and_upgrade(
                &TimerIntervals {
                    legacy_interval: None,
                    min_interval_seconds: None,
                    max_interval_seconds: *install_interval,
                },
                &TimerIntervals {
                    legacy_interval: None,
                    min_interval_seconds: None,
                    max_interval_seconds: *upgrade_interval,
                }
            ),
            Ok(()),
            "install_interval: {install_interval:?}, upgrade_interval: {upgrade_interval:?}"
        );
    }
}

#[test]
fn should_install_and_upgrade_with_valid_values() {
    /// Returns true iff the given timer intervals form a valid configuration,
    /// using `default_min` and `default_max` as fallbacks for `None` values.
    fn is_valid_config(intervals: &TimerIntervals, default_min: u64, default_max: u64) -> bool {
        let effective_min = intervals.min_interval_seconds.unwrap_or(default_min);
        let effective_max = intervals.max_interval_seconds.unwrap_or(default_max);
        effective_min >= 1 && effective_min <= effective_max
    }

    // Generate optional values in [1, MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS]. This
    // range ensures that when any value is None and falls back to its default (1 or 10),
    // the resulting configuration has a reasonable chance of being valid.
    let opt_val = || proptest::option::of(1u64..=MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS);

    let mut runner = TestRunner::new(proptest::test_runner::Config::with_cases(4));
    runner
        .run(
            &(opt_val(), opt_val(), opt_val(), opt_val())
                .prop_filter(
                    "init and upgrade configs must be valid",
                    |(i_min, i_max, u_min, u_max)| {
                        let init = TimerIntervals {
                            legacy_interval: None,
                            min_interval_seconds: *i_min,
                            max_interval_seconds: *i_max,
                        };
                        if !is_valid_config(
                            &init,
                            MIN_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS,
                            MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS,
                        ) {
                            return false;
                        }
                        // For upgrade, None means "keep the value from init". If init was
                        // also None, fall back to the global default.
                        let upgrade_default_min =
                            i_min.unwrap_or(MIN_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS);
                        let upgrade_default_max =
                            i_max.unwrap_or(MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS);
                        let upgrade = TimerIntervals {
                            legacy_interval: None,
                            min_interval_seconds: *u_min,
                            max_interval_seconds: *u_max,
                        };
                        is_valid_config(&upgrade, upgrade_default_min, upgrade_default_max)
                    },
                )
                .no_shrink(),
            |(i_min, i_max, u_min, u_max)| {
                assert_eq!(
                    install_and_upgrade(
                        &TimerIntervals {
                            legacy_interval: None,
                            min_interval_seconds: i_min,
                            max_interval_seconds: i_max,
                        },
                        &TimerIntervals {
                            legacy_interval: None,
                            min_interval_seconds: u_min,
                            max_interval_seconds: u_max,
                        },
                    ),
                    Ok(()),
                    "init: min={i_min:?}, max={i_max:?}; \
                     upgrade: min={u_min:?}, max={u_max:?}"
                );
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn should_fail_to_install_with_invalid_values() {
    let invalid_values = [
        // Min interval greater than max interval
        TimerIntervals {
            legacy_interval: None,
            min_interval_seconds: Some(MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL_SECONDS + 1),
            max_interval_seconds: None,
        },
        // Min interval equal to zero
        TimerIntervals {
            legacy_interval: None,
            min_interval_seconds: Some(0),
            max_interval_seconds: None,
        },
        // Legacy interval specified together with one, the other, or both of the new interval fields.
        TimerIntervals {
            legacy_interval: Some(5),
            min_interval_seconds: Some(1),
            max_interval_seconds: None,
        },
        TimerIntervals {
            legacy_interval: Some(5),
            min_interval_seconds: None,
            max_interval_seconds: Some(10),
        },
        TimerIntervals {
            legacy_interval: Some(5),
            min_interval_seconds: Some(1),
            max_interval_seconds: Some(10),
        },
    ];

    let env = &StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .with_time(GENESIS)
        .build();
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );

    for intervals in &invalid_values {
        let args = IndexArg::Init(InitArg {
            ledger_id: Principal::from(ledger_id),
            #[allow(deprecated)]
            retrieve_blocks_from_ledger_interval_seconds: intervals.legacy_interval,
            min_retrieve_blocks_from_ledger_interval_seconds: intervals.min_interval_seconds,
            max_retrieve_blocks_from_ledger_interval_seconds: intervals.max_interval_seconds,
        });
        let err = env
            .install_canister_with_cycles(
                index_ng_wasm(),
                Encode!(&args).unwrap(),
                None,
                Cycles::new(STARTING_CYCLES_PER_CANISTER),
            )
            .expect_err("index installation with invalid intervals should fail");
        err.assert_contains(ErrorCode::CanisterCalledTrap, "interval");
    }

    let args = IndexArg::Init(InitArg {
        ledger_id: Principal::from(ledger_id),
        #[allow(deprecated)]
        retrieve_blocks_from_ledger_interval_seconds: None,
        min_retrieve_blocks_from_ledger_interval_seconds: None,
        max_retrieve_blocks_from_ledger_interval_seconds: None,
    });
    let index_id = env
        .install_canister_with_cycles(
            index_ng_wasm(),
            Encode!(&args).unwrap(),
            None,
            Cycles::new(STARTING_CYCLES_PER_CANISTER),
        )
        .expect("index installation with valid intervals should succeed");

    wait_until_sync_is_completed(env, index_id, ledger_id);

    for intervals in &invalid_values {
        let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
            ledger_id: None,
            #[allow(deprecated)]
            retrieve_blocks_from_ledger_interval_seconds: intervals.legacy_interval,
            min_retrieve_blocks_from_ledger_interval_seconds: intervals.min_interval_seconds,
            max_retrieve_blocks_from_ledger_interval_seconds: intervals.max_interval_seconds,
        });
        let err = env
            .upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())
            .expect_err("index installation with invalid intervals should fail");
        err.assert_contains(ErrorCode::CanisterCalledTrap, "interval");
    }
}

#[test]
fn should_install_and_upgrade_without_build_index_interval_field_set() {
    #[derive(Clone, Debug, CandidType, Deserialize)]
    enum OldIndexArg {
        Init(OldInitArg),
        Upgrade(OldUpgradeArg),
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct OldInitArg {
        pub ledger_id: Principal,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct OldUpgradeArg {
        pub ledger_id: Option<Principal>,
    }

    let env = &StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .build();
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );
    let args = OldIndexArg::Init(OldInitArg {
        ledger_id: ledger_id.into(),
    });
    let index_id = env
        .install_canister_with_cycles(
            index_ng_wasm(),
            Encode!(&args).unwrap(),
            None,
            Cycles::new(STARTING_CYCLES_PER_CANISTER),
        )
        .unwrap();

    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = OldIndexArg::Upgrade(OldUpgradeArg { ledger_id: None });
    env.upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())
        .unwrap();

    wait_until_sync_is_completed(env, index_id, ledger_id);
}

#[test]
fn should_consume_expected_amount_of_cycles() {
    // The initially installed index polls the ledger every second. In the reinstalled index with
    // adaptive timing, the timer backs off exponentially when idle (no blocks):
    // 1s -> 2s -> 4s -> 8s -> up to 10s max. In this case, it is expected that the reinstalled
    // index consumes around 88% less cycles compared to the initially installed index over a long
    // idle period, since the adaptive timer will spend most of the time at the max interval of 10s.
    const IDLE_TIME_IN_SECS: u64 = 30; // 1+2+4+8+10 = 25s for a full backoff cycle.
    let assert_cost = |initial_consumption: &CycleConsumption,
                       reinstall_consumption: &CycleConsumption| {
        for (initial, reinstall) in [
            (initial_consumption.ledger, reinstall_consumption.ledger),
            (initial_consumption.index, reinstall_consumption.index),
        ] {
            let relative_difference = abs_relative_difference(initial, reinstall);
            assert!(
                0.8 < relative_difference && relative_difference < 0.85,
                "initial cycles: {}, cycles after reinstall: {}, relative_difference: {}",
                initial,
                reinstall,
                relative_difference
            )
        }
    };

    let env = &StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_subnet_size(28)
        .build();
    env.set_time(SystemTime::from(GENESIS));
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        MINTER_PRINCIPAL,
    );
    // Install the index with min and max intervals set to 1s to mimic the current default mainnet behavior.
    let index_id = install_index_ng(
        env,
        InitArg {
            ledger_id: Principal::from(ledger_id),
            #[allow(deprecated)]
            retrieve_blocks_from_ledger_interval_seconds: None,
            min_retrieve_blocks_from_ledger_interval_seconds: Some(1),
            max_retrieve_blocks_from_ledger_interval_seconds: Some(1),
        },
    );

    let initial_cycle_consumption =
        idle_ledger_and_index_cycles_consumption(env, ledger_id, index_id, IDLE_TIME_IN_SECS);

    // Reinstall the index with default min and max intervals.
    let reinstall_arg = IndexArg::Init(InitArg {
        ledger_id: Principal::from(ledger_id),
        #[allow(deprecated)]
        retrieve_blocks_from_ledger_interval_seconds: None,
        min_retrieve_blocks_from_ledger_interval_seconds: None,
        max_retrieve_blocks_from_ledger_interval_seconds: None,
    });
    env.reinstall_canister(index_id, index_ng_wasm(), Encode!(&reinstall_arg).unwrap())
        .unwrap();

    let reinstall_cycle_consumption =
        idle_ledger_and_index_cycles_consumption(env, ledger_id, index_id, IDLE_TIME_IN_SECS);

    (assert_cost)(&initial_cycle_consumption, &reinstall_cycle_consumption);
}

struct CycleConsumption {
    ledger: i128,
    index: i128,
}

fn abs_relative_difference(subject: i128, reference: i128) -> f64 {
    subject.abs_diff(reference) as f64 / (subject as f64)
}

fn idle_ledger_and_index_cycles_consumption(
    pocket_ic: &StateMachine,
    ledger_canister_id: CanisterId,
    index_canister_id: CanisterId,
    secs: u64,
) -> CycleConsumption {
    let initial_ledger_cycle_balance = pocket_ic.cycle_balance(ledger_canister_id);
    let initial_index_cycle_balance = pocket_ic.cycle_balance(index_canister_id);

    for _ in 0..secs {
        pocket_ic.advance_time(Duration::from_secs(1));
        pocket_ic.tick();
    }

    let ledger_cycle_balance = pocket_ic.cycle_balance(ledger_canister_id);
    let index_cycle_balance = pocket_ic.cycle_balance(index_canister_id);

    let ledger_cycles_burned = initial_ledger_cycle_balance
        .checked_sub(ledger_cycle_balance)
        .expect("ledger cycles should not have increased");
    let index_cycles_burned = initial_index_cycle_balance
        .checked_sub(index_cycle_balance)
        .expect("index cycles should not have increased");

    assert!(ledger_cycles_burned > 0);
    assert!(index_cycles_burned > 0);

    CycleConsumption {
        ledger: ledger_cycles_burned as i128,
        index: index_cycles_burned as i128,
    }
}
