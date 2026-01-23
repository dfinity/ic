use crate::common::{
    default_archive_options, index_ng_wasm, install_index_ng, install_ledger, ledger_wasm, status,
    wait_until_sync_is_completed, MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT, STARTING_CYCLES_PER_CANISTER,
};
use candid::{CandidType, Deserialize, Encode, Principal};
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_icrc1_index_ng::{IndexArg, InitArg, UpgradeArg};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_suite_state_machine_tests::index::{self, IndexTestConfig, arb_account};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::{Cycles, Time};
use icrc_ledger_types::icrc1::account::Account;
use num_traits::ToPrimitive;
use std::time::{Duration, SystemTime};

mod common;

/// Corresponds to ic_icrc1_index_ng::DEFAULT_MAX_WAIT_TIME_IN_SECS
const DEFAULT_MAX_WAIT_TIME_IN_SECS: u64 = 1;
const GENESIS: Time = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
const IDLE_TIME_IN_SECS: u64 = 10;
const INDEX_SYNC_TIME_TO_ADVANCE_SECS: u64 = 60;
const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);

fn config() -> IndexTestConfig {
    IndexTestConfig {
        genesis_nanos: GENESIS.as_nanos_since_unix_epoch(),
        default_interval_secs: DEFAULT_MAX_WAIT_TIME_IN_SECS,
    }
}

fn max_index_sync_time() -> u64 {
    (MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT as u64) * INDEX_SYNC_TIME_TO_ADVANCE_SECS
}

fn encode_init_args(ledger_id: CanisterId, interval: Option<u64>) -> IndexArg {
    IndexArg::Init(InitArg {
        ledger_id: Principal::from(ledger_id),
        retrieve_blocks_from_ledger_interval_seconds: interval,
    })
}

fn encode_upgrade_args(interval: Option<u64>) -> IndexArg {
    IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: interval,
    })
}

fn install_ledger_for_test(
    env: &StateMachine,
    _ledger_wasm: Vec<u8>,
    initial_balances: Vec<(Account, u64)>,
) -> CanisterId {
    install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    )
}

fn index_num_blocks_synced(env: &StateMachine, index_id: CanisterId) -> u64 {
    status(env, index_id)
        .num_blocks_synced
        .0
        .to_u64()
        .expect("should retrieve num_blocks_synced from index")
}

#[test]
fn should_fail_to_install_and_upgrade_with_invalid_value() {
    index::test_should_fail_to_install_and_upgrade_with_invalid_value(
        &config(),
        ledger_wasm(),
        index_ng_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        wait_until_sync_is_completed,
    );
}

#[test]
fn should_install_and_upgrade_with_valid_values() {
    index::test_should_install_and_upgrade_with_valid_values(
        &config(),
        max_index_sync_time(),
        ledger_wasm(),
        index_ng_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        wait_until_sync_is_completed,
    );
}

#[test]
fn should_sync_according_to_interval() {
    index::test_should_sync_according_to_interval(
        &config(),
        ledger_wasm(),
        index_ng_wasm(),
        encode_init_args,
        encode_upgrade_args,
        install_ledger_for_test,
        index_num_blocks_synced,
        arb_account(),
    );
}

/// Test backward compatibility with old init args that don't have the interval field.
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

// =============================================
// Cycles consumption tests (ICRC1-specific)
// These tests require SubnetType::Application
// =============================================

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
                const EXPECTED_LEDGER_CYCLES_CONSUMPTION: i128 = 126_800_287;
                const EXPECTED_INDEX_CYCLES_CONSUMPTION: i128 = 474_143_016;
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
