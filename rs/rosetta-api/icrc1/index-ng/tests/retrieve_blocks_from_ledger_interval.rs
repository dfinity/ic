use crate::common::{
    default_archive_options, index_ng_wasm, install_index_ng, install_ledger,
    wait_until_sync_is_completed, MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT, STARTING_CYCLES_PER_CANISTER,
};
use candid::{CandidType, Deserialize, Encode, Principal};
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_icrc1_index_ng::{IndexArg, InitArg, UpgradeArg};
use ic_icrc1_test_utils::minter_identity;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder, Time, UserError};
use std::time::{Duration, SystemTime};

mod common;

/// Corresponds to ic_icrc1_index_ng::DEFAULT_MAX_WAIT_TIME_IN_SECS
const DEFAULT_MAX_WAIT_TIME_IN_SECS: u64 = 1;
const GENESIS: Time = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
const IDLE_TIME_IN_SECS: u64 = 60;
const INDEX_SYNC_TIME_TO_ADVANCE: Duration = Duration::from_secs(60);
const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);

fn install_and_upgrade(
    install_interval: Option<u64>,
    upgrade_interval: Option<u64>,
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
        retrieve_blocks_from_ledger_interval_seconds: install_interval,
    });
    let index_id = env.install_canister_with_cycles(
        index_ng_wasm(),
        Encode!(&args).unwrap(),
        None,
        ic_state_machine_tests::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: upgrade_interval,
    });
    env.upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())?;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    Ok(())
}

fn max_value_for_interval() -> u64 {
    (u64::MAX - GENESIS.as_nanos_since_unix_epoch()) / 1_000_000_000
}

fn max_index_sync_time() -> u64 {
    (MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT as u64)
        .checked_mul(INDEX_SYNC_TIME_TO_ADVANCE.as_secs())
        .unwrap()
}

#[test]
fn should_fail_to_install_and_upgrade_with_invalid_value() {
    let minimum_invalid_value_for_interval = max_value_for_interval() + 1;
    let invalid_install_and_upgrade_combinations = [
        (Some(minimum_invalid_value_for_interval), Some(1)),
        (Some(1), Some(minimum_invalid_value_for_interval)),
    ];
    for (install_interval, upgrade_interval) in &invalid_install_and_upgrade_combinations {
        let err = install_and_upgrade(*install_interval, *upgrade_interval)
            .expect_err("should fail to install with invalid interval");
        let code = err.code();
        assert_eq!(code, ErrorCode::CanisterCalledTrap);
        let description = err.description();
        assert!(description.contains("delay out of bounds"));
    }
}

#[test]
fn should_install_and_upgrade_with_valid_values() {
    let max_seconds_for_timer = max_value_for_interval() - max_index_sync_time();
    let build_index_interval_values = [
        None,
        Some(0u64),
        Some(1u64),
        Some(10u64),
        Some(max_seconds_for_timer),
    ];

    // Installing and upgrading with valid values should succeed
    for install_interval in &build_index_interval_values {
        for upgrade_interval in &build_index_interval_values {
            assert_eq!(
                install_and_upgrade(*install_interval, *upgrade_interval),
                Ok(()),
                "install_interval: {:?}, upgrade_interval: {:?}",
                install_interval,
                upgrade_interval
            );
        }
    }
}

#[test]
fn should_install_and_upgrade_without_build_index_interval_field_set() {
    #[derive(CandidType, Debug, Deserialize, Clone)]
    enum OldIndexArg {
        Init(OldInitArg),
        Upgrade(OldUpgradeArg),
    }

    #[derive(CandidType, Debug, Deserialize, Clone)]
    struct OldInitArg {
        pub ledger_id: Principal,
    }

    #[derive(CandidType, Debug, Deserialize, Clone)]
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
            ic_state_machine_tests::Cycles::new(STARTING_CYCLES_PER_CANISTER),
        )
        .unwrap();

    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_arg = OldIndexArg::Upgrade(OldUpgradeArg { ledger_id: None });
    env.upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())
        .unwrap();

    wait_until_sync_is_completed(env, index_id, ledger_id);
}

struct CyclesConsumptionParameters {
    initial_interval: Option<u64>,
    upgrade_interval: Option<u64>,
    assert_cost: fn(&CycleConsumption, &CycleConsumption),
}

#[test]
fn should_consume_expected_amount_of_cycles() {
    let assert_same_amount_of_cycles_consumed =
        |initial_consumption: &CycleConsumption, upgrade_consumption: &CycleConsumption| {
            assert!(
                abs_relative_difference(initial_consumption.ledger, upgrade_consumption.ledger)
                    < 0.01,
                "initial ledger cycles consumed: {}, cycles consumed after upgrade: {}",
                initial_consumption.ledger,
                upgrade_consumption.ledger
            );
            assert!(
                abs_relative_difference(initial_consumption.index, upgrade_consumption.index)
                    < 0.01,
                "initial index cycles consumed: {}, cycles consumed after upgrade: {}",
                initial_consumption.index,
                upgrade_consumption.index
            );
        };
    for &CyclesConsumptionParameters {
        initial_interval,
        upgrade_interval,
        assert_cost,
    } in &[
        // should consume the same amount of cycles when the interval stays the same
        CyclesConsumptionParameters {
            initial_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            upgrade_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            assert_cost: assert_same_amount_of_cycles_consumed,
        },
        CyclesConsumptionParameters {
            initial_interval: None,
            upgrade_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            assert_cost: assert_same_amount_of_cycles_consumed,
        },
        CyclesConsumptionParameters {
            initial_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            upgrade_interval: None,
            assert_cost: assert_same_amount_of_cycles_consumed,
        },
        CyclesConsumptionParameters {
            initial_interval: None,
            upgrade_interval: None,
            assert_cost: assert_same_amount_of_cycles_consumed,
        },
        // should consume half the amount of cycles when the interval is doubled
        CyclesConsumptionParameters {
            initial_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            upgrade_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS * 2),
            assert_cost: |initial_consumption, upgrade_consumption| {
                for (initial, upgrade) in [
                    (initial_consumption.ledger, upgrade_consumption.ledger),
                    (initial_consumption.index, upgrade_consumption.index),
                ] {
                    let relative_difference = abs_relative_difference(initial, upgrade);
                    assert!(
                        0.4 < relative_difference && relative_difference < 0.5,
                        "initial cycles: {}, cycles after upgrade: {}",
                        initial,
                        upgrade
                    )
                }
            },
        },
        // should consume cycles within 30% of hard-coded value when the interval is set to 1 sec
        CyclesConsumptionParameters {
            initial_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            upgrade_interval: Some(DEFAULT_MAX_WAIT_TIME_IN_SECS),
            assert_cost: |initial, upgrade| {
                const EXPECTED_LEDGER_CYCLES_CONSUMPTION: i128 = 124_445_767;
                const EXPECTED_INDEX_CYCLES_CONSUMPTION: i128 = 449_388_554;
                for ledger_consumption in [initial.ledger, upgrade.ledger] {
                    assert!(
                        abs_relative_difference(
                            EXPECTED_LEDGER_CYCLES_CONSUMPTION,
                            ledger_consumption
                        ) < 0.3,
                        "ledger cycles consumed 30% more/less than expected: {}, expected: {}",
                        ledger_consumption,
                        EXPECTED_LEDGER_CYCLES_CONSUMPTION
                    );
                }
                for index_consumption in [initial.index, upgrade.index] {
                    assert!(
                        abs_relative_difference(
                            EXPECTED_INDEX_CYCLES_CONSUMPTION,
                            index_consumption
                        ) < 0.3,
                        "index cycles consumed 30% more/less than expected: {}, expected: {}",
                        index_consumption,
                        EXPECTED_INDEX_CYCLES_CONSUMPTION
                    );
                }
            },
        },
    ] {
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
        let index_id = install_index_ng(
            env,
            InitArg {
                ledger_id: Principal::from(ledger_id),
                retrieve_blocks_from_ledger_interval_seconds: initial_interval,
            },
        );

        let initial_cycle_consumption =
            idle_ledger_and_index_cycles_consumption(env, ledger_id, index_id, IDLE_TIME_IN_SECS);

        let upgrade_arg = IndexArg::Upgrade(UpgradeArg {
            ledger_id: None,
            retrieve_blocks_from_ledger_interval_seconds: upgrade_interval,
        });
        env.upgrade_canister(index_id, index_ng_wasm(), Encode!(&upgrade_arg).unwrap())
            .unwrap();

        let upgrade_cycle_consumption =
            idle_ledger_and_index_cycles_consumption(env, ledger_id, index_id, IDLE_TIME_IN_SECS);

        (assert_cost)(&initial_cycle_consumption, &upgrade_cycle_consumption);
    }
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
