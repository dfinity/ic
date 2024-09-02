use assert_matches::assert_matches;
use candid::{Decode, Encode, Principal};
use ic_ckbtc_kyt::{
    Alert, AlertLevel, DepositRequest, Error as KytError, ExposureType, FetchAlertsResponse,
    InitArg, KytMode, LifecycleArg, SetApiKeyArg,
};
use ic_state_machine_tests::{
    CanisterHttpRequestContext, CanisterHttpResponsePayload, Cycles, IngressState, IngressStatus,
    StateMachine, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;

const MAX_TICKS: usize = 10;

fn assert_has_header(req: &CanisterHttpRequestContext, name: &str, value: &str) {
    assert!(req
        .headers
        .iter()
        .any(|h| h.name == name && h.value == value));
}

fn tick_until_next_request(env: &StateMachine) {
    for _ in 0..MAX_TICKS {
        if !env.canister_http_request_contexts().is_empty() {
            break;
        }
        env.tick();
    }
    assert!(
        !env.canister_http_request_contexts().is_empty(),
        "The canister did not produce another request in {} ticks",
        MAX_TICKS
    );
}

fn kyt_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-ckbtc-kyt",
        &[],
    )
}

#[test]
fn test_key_recovery() {
    let env = StateMachine::new();
    let p1 = Principal::management_canister();
    let p2 = Principal::anonymous();
    let minter_id = Principal::anonymous();

    let kyt = env
        .install_canister_with_cycles(
            kyt_wasm(),
            Encode!(&LifecycleArg::InitArg(InitArg {
                minter_id,
                maintainers: vec![p1, p2],
                mode: KytMode::Normal,
            }))
            .unwrap(),
            None,
            Cycles::from(100_000_000_000_000u64),
        )
        .expect("failed to install the KYT canister");

    env.execute_ingress_as(
        p1.into(),
        kyt,
        "set_api_key",
        Encode!(&SetApiKeyArg {
            api_key: "Key1".to_string()
        })
        .unwrap(),
    )
    .unwrap();

    env.execute_ingress_as(
        p2.into(),
        kyt,
        "set_api_key",
        Encode!(&SetApiKeyArg {
            api_key: "Key2".to_string()
        })
        .unwrap(),
    )
    .unwrap();

    let call_id = env.send_ingress(
        minter_id.into(),
        kyt,
        "fetch_utxo_alerts",
        Encode!(&DepositRequest {
            caller: minter_id,
            txid: [0; 32],
            vout: 0
        })
        .unwrap(),
    );

    assert_matches!(
        env.ingress_status(&call_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    );

    env.tick();

    env.handle_http_call("transfer with expired key", |req| {
        assert_has_header(req, "Token", "Key1");
        assert!(
            req.url.ends_with("/transfers"),
            "expected a transfer registration, got: {:?}",
            req
        );
        CanisterHttpResponsePayload {
            status: 403,
            headers: vec![],
            body: br#"{"status": 403, "message": "Access Denied"}"#.to_vec(),
        }
    });

    tick_until_next_request(&env);

    assert_matches!(
        env.ingress_status(&call_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    );

    env.handle_http_call("retry transfer with another key", |req| {
        assert_has_header(req, "Token", "Key2");
        assert!(
            req.url.ends_with("/transfers"),
            "expected a transfer registration, got: {:?}",
            req
        );
        CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: br#"{"externalId": "12356-abcde", "updatedAt": "2023-03-02T15:23:27+00:00", "transferReference":"0000000000000000000000000000000000000000000000000000000000000000:0"}"#.to_vec(),
        }
    });

    tick_until_next_request(&env);

    env.handle_http_call("fetch alerts", |req| {
        assert_has_header(req, "Token", "Key2");
        assert!(
            req.url.ends_with("/v2/transfers/12356-abcde/alerts"),
            "expected a call to fetch alerts, got: {:?}",
            req
        );
        CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: br#"{"alerts": [{"alertLevel": "HIGH", "category": "C", "service": "S", "exposureType": "DIRECT"}]}"#.to_vec(),
        }
    });

    let result = env
        .await_ingress(call_id, /*max_ticks=*/ MAX_TICKS)
        .expect("the fetch request didn't finish");

    match &result {
        WasmResult::Reply(bytes) => {
            let response = Decode!(bytes, Result<FetchAlertsResponse, KytError>).unwrap();
            assert_eq!(
                response,
                Ok(FetchAlertsResponse {
                    external_id: "12356-abcde".to_string(),
                    provider: p2,
                    alerts: vec![Alert {
                        level: AlertLevel::High,
                        category: Some("C".to_string()),
                        service: Some("S".to_string()),
                        exposure_type: ExposureType::Direct,
                    }],
                })
            );
        }
        WasmResult::Reject(msg) => panic!("unexpected reject: {}", msg),
    }
}
