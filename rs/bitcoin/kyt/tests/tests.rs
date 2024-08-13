use assert_matches::assert_matches;
use candid::{Decode, Encode, Principal};
use ic_state_machine_tests::{Cycles, IngressState, IngressStatus, StateMachine, WasmResult};
use ic_test_utilities_load_wasm::load_wasm;

const MAX_TICKS: usize = 10;

fn kyt_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "btc-kyt-canister",
        &[],
    )
}

#[test]
fn test_get_inputs() {
    let env = StateMachine::new();
    let p2 = Principal::anonymous();

    let kyt = env
        .install_canister_with_cycles(
            kyt_wasm(),
            vec![],
            None,
            Cycles::from(100_000_000_000_000u64),
        )
        .expect("failed to install the KYT canister");

    let call_id = env.send_ingress(
        p2.into(),
        kyt,
        "get_inputs",
        Encode!(&"bd02819e5f81e5f78e18a33ffdc5e9a7d4aa9f6c4cc519a768dc11e6771b33d3".to_string())
            .unwrap(),
    );

    assert_matches!(
        env.ingress_status(&call_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    );

    let result = env
        .await_ingress(call_id, /*max_ticks=*/ MAX_TICKS)
        .expect("the fetch request didn't finish");

    match &result {
        WasmResult::Reply(bytes) => {
            let response = Decode!(bytes, Vec<String>).unwrap();
            assert_eq!(
                response,
                vec![
                    "bc1qqkn6aspfk6mhlpmq7q90kwxffyfs9sd5098yyp".to_string(),
                    "bc1q4q0vnhysu8kcnj9qgt3x2kqwscyl6w4r0gz80g".to_string(),
                    "bc1qv9hw8l05fke6p587qd450ve2ms9hchl3c2p6ea".to_string(),
                    "bc1qud0mnk7ggc5uanhs8vdmkj9fsa758q725nsajt".to_string()
                ],
            );
        }
        WasmResult::Reject(msg) => panic!("unexpected reject: {}", msg),
    }
}
