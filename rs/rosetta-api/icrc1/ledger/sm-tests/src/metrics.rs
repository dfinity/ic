use crate::{setup, InitArgs};
use candid::{CandidType, Decode, Encode, Principal};
use ic_base_types::CanisterId;
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;

pub fn assert_existence_of_ledger_total_memory_bytes_metric<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const METRIC: &str = "ledger_total_memory_bytes";

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    assert_existence_of_total_memory_bytes_metric(env, canister_id, METRIC);
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

    assert_existence_of_total_memory_bytes_metric(env, index_id, METRIC);
}

fn assert_existence_of_total_memory_bytes_metric(
    env: StateMachine,
    canister_id: CanisterId,
    metric: &str,
) {
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
    let metrics = String::from_utf8_lossy(response.body.as_slice())
        .trim()
        .split('\n')
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert!(
        metrics.iter().any(|line| line.contains(metric)),
        "Expected metric not found: {} in:\n{:?}",
        metric,
        metrics
    );
}
