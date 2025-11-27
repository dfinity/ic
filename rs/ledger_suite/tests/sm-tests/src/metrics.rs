use crate::{
    ARCHIVE_TRIGGER_THRESHOLD, DECIMAL_PLACES, InitArgs, MINTER, NUM_BLOCKS_TO_ARCHIVE,
    default_approve_args, init_args, send_approval, setup, transfer,
};
use candid::{CandidType, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_suite_state_machine_helpers::{parse_metric, retrieve_metrics};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc2::approve::ApproveArgs;

pub enum LedgerSuiteType {
    ICP,
    ICRC,
}

pub fn assert_existence_of_index_heap_memory_bytes_metric<T>(
    index_wasm: Vec<u8>,
    encode_init_args: fn(Principal) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "heap_memory_bytes";

    let env = StateMachine::new();
    let ledger_id = CanisterId::from_u64(100);
    let args = encode_init_args(Principal::from(ledger_id));

    let index_id = env
        .install_canister(index_wasm, Encode!(&args).unwrap(), None)
        .unwrap();

    assert_existence_of_metric(&env, index_id, METRIC);
}

pub fn assert_existence_of_ledger_num_archives_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "ledger_num_archives";

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    assert_existence_of_metric(&env, canister_id, METRIC);
}

pub fn assert_existence_of_heap_memory_bytes_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "heap_memory_bytes";

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    assert_existence_of_metric(&env, canister_id, METRIC);
}

pub fn assert_existence_of_ledger_total_transactions_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    ledger_suite_type: LedgerSuiteType,
) where
    T: CandidType,
{
    fn ledger_archived_transactions_metric_name(ledger_suite_type: &LedgerSuiteType) -> String {
        match ledger_suite_type {
            LedgerSuiteType::ICP => "ledger_archived_blocks".to_string(),
            LedgerSuiteType::ICRC => "ledger_archived_transactions".to_string(),
        }
    }

    fn ledger_total_transactions_metric_name(ledger_suite_type: &LedgerSuiteType) -> String {
        match ledger_suite_type {
            LedgerSuiteType::ICP => "ledger_total_blocks".to_string(),
            LedgerSuiteType::ICRC => "ledger_total_transactions".to_string(),
        }
    }

    fn ledger_transactions_metric_name(ledger_suite_type: &LedgerSuiteType) -> String {
        match ledger_suite_type {
            LedgerSuiteType::ICP => "ledger_blocks".to_string(),
            LedgerSuiteType::ICRC => "ledger_transactions".to_string(),
        }
    }

    const NUM_MINT_TRANSACTIONS: u64 = ARCHIVE_TRIGGER_THRESHOLD + 1;

    let (env, ledger_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let p1 = PrincipalId::new_user_test_id(1);

    for _ in 0..NUM_MINT_TRANSACTIONS {
        transfer(&env, ledger_id, MINTER, p1.0, 10_000_000).expect("mint failed");
    }

    assert_eq!(
        NUM_MINT_TRANSACTIONS,
        parse_metric(
            &env,
            ledger_id,
            &ledger_total_transactions_metric_name(&ledger_suite_type)
        )
    );
    assert_eq!(
        NUM_MINT_TRANSACTIONS - NUM_BLOCKS_TO_ARCHIVE,
        parse_metric(
            &env,
            ledger_id,
            &ledger_transactions_metric_name(&ledger_suite_type)
        )
    );
    assert_eq!(
        NUM_BLOCKS_TO_ARCHIVE,
        parse_metric(
            &env,
            ledger_id,
            &ledger_archived_transactions_metric_name(&ledger_suite_type)
        )
    );
}

pub fn assert_ledger_upgrade_instructions_consumed_metric_set<T, U>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    encode_upgrade_args: fn() -> U,
) where
    T: CandidType,
    U: CandidType,
{
    const PRE_UPGRADE_METRIC: &str = "ledger_pre_upgrade_instructions_consumed";
    const POST_UPGRADE_METRIC: &str = "ledger_post_upgrade_instructions_consumed";
    const TOTAL_UPGRADE_METRICS: &str = "ledger_total_upgrade_instructions_consumed";

    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);

    for metric in [
        PRE_UPGRADE_METRIC,
        POST_UPGRADE_METRIC,
        TOTAL_UPGRADE_METRICS,
    ]
    .iter()
    {
        assert_eq!(0, parse_metric(&env, canister_id, metric));
    }

    let args = encode_upgrade_args();
    let encoded_upgrade_args = Encode!(&args).unwrap();
    env.upgrade_canister(canister_id, ledger_wasm, encoded_upgrade_args)
        .expect("should successfully upgrade ledger canister");

    let pre_upgrade_instructions_consumed = parse_metric(&env, canister_id, PRE_UPGRADE_METRIC);
    let post_upgrade_instructions_consumed = parse_metric(&env, canister_id, POST_UPGRADE_METRIC);
    assert_ne!(0, pre_upgrade_instructions_consumed);
    assert_ne!(0, post_upgrade_instructions_consumed);
    assert_eq!(
        pre_upgrade_instructions_consumed + post_upgrade_instructions_consumed,
        parse_metric(&env, canister_id, TOTAL_UPGRADE_METRICS)
    );
}

pub fn should_compute_and_export_total_volume_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const TOTAL_VOLUME_METRIC: &str = "total_volume";
    let mut expected_total = 0f64;

    let initial_balances = vec![(
        PrincipalId::new_user_test_id(1).0.into(),
        u64::MAX - 10_000_000,
    )];
    let env = StateMachine::new();

    let transfer_fee = 10f64.powf(DECIMAL_PLACES as f64 - 1f64) as u64;
    println!("transfer_fee: {transfer_fee}");
    let args = InitArgs {
        transfer_fee: transfer_fee.into(),
        ..init_args(initial_balances)
    };
    let args = Encode!(&encode_init_args(args)).unwrap();
    let canister_id = env.install_canister(ledger_wasm, args, None).unwrap();

    let denominator = 10f64.powf(DECIMAL_PLACES as f64);

    let mut increase_expected_total_volume_and_assert = |amount: u64| {
        expected_total += amount as f64 / denominator;
        assert_eq!(
            format!("{expected_total:.0}"),
            format!(
                "{:.0}",
                parse_metric(&env, canister_id, TOTAL_VOLUME_METRIC)
            )
        );
    };

    // Verify the metric returns 0 when no transactions have occurred
    assert_eq!(0, parse_metric(&env, canister_id, TOTAL_VOLUME_METRIC));

    // Perform a bunch of small transfers to verify that the computation of decimals is correct,
    // and so that the total fee exceeds 1.0.
    let num_operations = denominator as u64 / transfer_fee;
    println!("performing {num_operations} transfers");
    for _ in 0..num_operations {
        transfer(
            &env,
            canister_id,
            PrincipalId::new_user_test_id(1).0,
            PrincipalId::new_user_test_id(2).0,
            transfer_fee,
        )
        .expect("transfer failed");
    }
    increase_expected_total_volume_and_assert(2 * num_operations * transfer_fee);

    // Verify total volume accounting handles minting correctly (no fee).
    for _ in 0..num_operations {
        transfer(
            &env,
            canister_id,
            MINTER,
            PrincipalId::new_user_test_id(1).0,
            transfer_fee,
        )
        .expect("mint failed");
    }
    increase_expected_total_volume_and_assert(num_operations * transfer_fee);

    // Verify total volume accounting handles burning correctly (no fee).
    for _ in 0..num_operations {
        transfer(
            &env,
            canister_id,
            PrincipalId::new_user_test_id(1).0,
            MINTER,
            transfer_fee,
        )
        .expect("burn failed");
    }
    increase_expected_total_volume_and_assert(num_operations * transfer_fee);

    // Verify total volume accounting handles approvals correctly (no amount).
    let approve_args = ApproveArgs {
        fee: Some(transfer_fee.into()),
        ..default_approve_args(PrincipalId::new_user_test_id(1).0, 1_000_000_000)
    };
    for _ in 0..num_operations {
        send_approval(
            &env,
            canister_id,
            PrincipalId::new_user_test_id(2).0,
            &approve_args,
        )
        .expect("approval failed");
    }
    increase_expected_total_volume_and_assert(num_operations * transfer_fee);

    // Perform some larger transfers to verify a total volume larger than u64::MAX is handled correctly.
    transfer(
        &env,
        canister_id,
        PrincipalId::new_user_test_id(1).0,
        PrincipalId::new_user_test_id(2).0,
        u64::MAX - 1_000_000_000,
    )
    .expect("transfer failed");
    increase_expected_total_volume_and_assert(u64::MAX - 1_000_000_000 + transfer_fee);

    transfer(
        &env,
        canister_id,
        PrincipalId::new_user_test_id(2).0,
        PrincipalId::new_user_test_id(1).0,
        u64::MAX - 10_000_000_000,
    )
    .expect("transfer failed");

    increase_expected_total_volume_and_assert(u64::MAX - 10_000_000_000 + transfer_fee);
}

fn assert_existence_of_metric(env: &StateMachine, canister_id: CanisterId, metric: &str) {
    let metrics = retrieve_metrics(env, canister_id);
    assert!(
        metrics.iter().any(|line| line.contains(metric)),
        "Expected metric not found: {metric} in:\n{metrics:?}"
    );
}
