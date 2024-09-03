use crate::{setup, transfer, InitArgs, ARCHIVE_TRIGGER_THRESHOLD, MINTER, NUM_BLOCKS_TO_ARCHIVE};
use candid::{CandidType, Decode, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;

pub enum LedgerSuiteType {
    ICP,
    ICRC,
}

pub fn assert_existence_of_index_total_memory_bytes_metric<T>(
    index_wasm: Vec<u8>,
    encode_init_args: fn(Principal) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "index_total_memory_bytes";

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

pub fn assert_existence_of_ledger_total_memory_bytes_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "ledger_total_memory_bytes";

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

    env.run_until_completion(/*max_ticks=*/ 10);

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
    ledger_wasm_nextmigrationversionmemorymanager: Option<Vec<u8>>,
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

    let test_upgrade = |ledger_wasm: Vec<u8>| {
        let args = encode_upgrade_args();
        let encoded_upgrade_args = Encode!(&args).unwrap();
        env.upgrade_canister(canister_id, ledger_wasm, encoded_upgrade_args)
            .expect("should successfully upgrade ledger canister");

        let pre_upgrade_instructions_consumed = parse_metric(&env, canister_id, PRE_UPGRADE_METRIC);
        let post_upgrade_instructions_consumed =
            parse_metric(&env, canister_id, POST_UPGRADE_METRIC);
        assert_ne!(0, pre_upgrade_instructions_consumed);
        assert_ne!(0, post_upgrade_instructions_consumed);
        assert_eq!(
            pre_upgrade_instructions_consumed + post_upgrade_instructions_consumed,
            parse_metric(&env, canister_id, TOTAL_UPGRADE_METRICS)
        );
    };

    test_upgrade(ledger_wasm.clone());
    if let Some(ledger_wasm_nextmigrationversionmemorymanager) =
        ledger_wasm_nextmigrationversionmemorymanager
    {
        test_upgrade(ledger_wasm_nextmigrationversionmemorymanager.clone());
        test_upgrade(ledger_wasm_nextmigrationversionmemorymanager);
    }
    test_upgrade(ledger_wasm);
}

fn assert_existence_of_metric(env: &StateMachine, canister_id: CanisterId, metric: &str) {
    let metrics = retrieve_metrics(env, canister_id);
    assert!(
        metrics.iter().any(|line| line.contains(metric)),
        "Expected metric not found: {} in:\n{:?}",
        metric,
        metrics
    );
}

pub(crate) fn parse_metric(env: &StateMachine, canister_id: CanisterId, metric: &str) -> u64 {
    let metrics = retrieve_metrics(env, canister_id);
    for line in &metrics {
        let tokens: Vec<&str> = line.split(' ').collect();
        let name = *tokens
            .first()
            .unwrap_or_else(|| panic!("metric line '{}' should have at least one token", line));
        if name != metric {
            continue;
        }
        let value_str = *tokens
            .get(1)
            .unwrap_or_else(|| panic!("metric line '{}' should have at least two tokens", line));
        return value_str
            .parse()
            .unwrap_or_else(|err| panic!("metric value is not an integer: {} ({})", line, err));
    }
    panic!("metric '{}' not found in metrics: {:?}", metric, metrics);
}

fn retrieve_metrics(env: &StateMachine, canister_id: CanisterId) -> Vec<String> {
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: Default::default(),
        body: Default::default(),
    };
    let result = env
        .query(
            canister_id,
            "http_request",
            Encode!(&request).expect("failed to encode HTTP request"),
        )
        .expect("should successfully query canister for metrics");
    let reply = match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("expected a successful reply, got a reject: {}", reject)
        }
    };
    let response = Decode!(&reply, HttpResponse).expect("should successfully decode HttpResponse");
    assert_eq!(response.status_code, 200_u16);
    String::from_utf8_lossy(response.body.as_slice())
        .trim()
        .split('\n')
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
}
