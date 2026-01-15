use candid::{Encode, Principal, decode_one};
use ic_base_types::PrincipalId;
use ic_btc_checker::{
    BtcNetwork, CHECK_TRANSACTION_CYCLES_REQUIRED, CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
    CheckAddressArgs, CheckAddressResponse, CheckArg, CheckMode, CheckTransactionArgs,
    CheckTransactionIrrecoverableError, CheckTransactionQueryArgs, CheckTransactionQueryResponse,
    CheckTransactionResponse, CheckTransactionRetriable, CheckTransactionStatus,
    CheckTransactionStrArgs, INITIAL_MAX_RESPONSE_BYTES, InitArg, UpgradeArg, blocklist,
    get_tx_cycle_cost,
};
use ic_btc_interface::Txid;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_management_canister_types::CanisterId;
use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
use ic_test_utilities_load_wasm::load_wasm;
use ic_types::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use pocket_ic::{
    PocketIc, PocketIcBuilder, RejectCode, RejectResponse,
    common::rest::{
        CanisterHttpHeader, CanisterHttpReject, CanisterHttpReply, CanisterHttpRequest,
        CanisterHttpResponse, IcpConfig, IcpConfigFlag, MockCanisterHttpResponse, RawMessageId,
    },
    query_candid,
};
use std::str::FromStr;

const MAX_TICKS: usize = 10;

const TEST_SUBNET_NODES: u16 = 34;

// Because we use universal_canister to make calls with attached cycles to
// `check_transaction`, the actual_cost would be greater than expected_cost
// by a small margin. Namely, the universal_canister itself would consume
// some cycle for decoding args and sending the call.
//
// The number 43_000_000 is obtained empirically by running tests with pocket-ic
// and checking the actual consumptions. It is both big enough to allow tests to
// succeed, and small enough not to interfere with the expected cycle cost we
// are testing for.
const UNIVERSAL_CANISTER_CYCLE_MARGIN: u128 = 43_000_000;

struct Setup {
    // Owner of canisters created for the setup.
    controller: Principal,
    // The `caller` canister helps to proxy update calls with cycle payment.
    caller: Principal,
    btc_checker_canister: Principal,
    env: PocketIc,
}

fn btc_checker_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-btc-checker-canister",
        &[],
    )
}

impl Setup {
    fn new(btc_network: BtcNetwork) -> Setup {
        let controller = PrincipalId::new_user_test_id(1).0;
        // Disable rate-limiting to avoid CanisterInstallCodeRateLimited error
        // for canister upgrades
        let icp_config = IcpConfig {
            canister_execution_rate_limiting: Some(IcpConfigFlag::Disabled),
            ..Default::default()
        };
        let env = PocketIcBuilder::new()
            .with_application_subnet()
            .with_icp_config(icp_config)
            .build();

        let init_arg = InitArg {
            btc_network,
            check_mode: CheckMode::Normal,
            num_subnet_nodes: TEST_SUBNET_NODES,
        };
        let caller = env.create_canister_with_settings(Some(controller), None);
        env.add_cycles(caller, 100_000_000_000_000);
        env.install_canister(
            caller,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(controller),
        );

        let btc_checker_canister = env.create_canister_with_settings(Some(controller), None);
        env.add_cycles(btc_checker_canister, 100_000_000_000_000);
        env.install_canister(
            btc_checker_canister,
            btc_checker_wasm(),
            Encode!(&CheckArg::InitArg(init_arg)).unwrap(),
            Some(controller),
        );

        Setup {
            controller,
            caller,
            btc_checker_canister,
            env,
        }
    }

    fn submit_btc_checker_call(
        &self,
        method: &str,
        args: Vec<u8>,
        cycles: u128,
    ) -> Result<RawMessageId, RejectResponse> {
        let payload = wasm()
            .call_with_cycles(
                PrincipalId(self.btc_checker_canister),
                method,
                call_args()
                    .other_side(args)
                    .on_reject(wasm().reject_message().reject()),
                Cycles::new(cycles),
            )
            .build();
        self.env
            .submit_call(self.caller, self.controller, "update", payload)
    }

    fn query_btc_checker<I, O>(&self, method: &str, args: I) -> Result<O, RejectResponse>
    where
        I: candid::CandidType,
        O: for<'a> candid::utils::ArgumentDecoder<'a>,
    {
        query_candid(&self.env, self.btc_checker_canister, method, (args,))
    }
}

#[test]
fn test_get_tx_cycle_cost() {
    assert_eq!(
        get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, 13),
        97_063_200
    );
    assert_eq!(
        get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, 34),
        296_697_600
    );
}

#[test]
fn test_check_address() {
    let blocklist_len = blocklist::BTC_ADDRESS_BLOCKLIST.len();
    let blocked_address = blocklist::BTC_ADDRESS_BLOCKLIST[blocklist_len / 2].to_string();

    let Setup {
        btc_checker_canister,
        env,
        controller,
        ..
    } = Setup::new(BtcNetwork::Mainnet);

    // Choose an address from the blocklist
    let result = query_candid(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: blocked_address.clone(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Failed,))),
        "result = {result:?}"
    );

    // Satoshi's address hopefully is not in the blocklist
    let result = query_candid(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S".to_string(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Passed,))),
        "result = {result:?}"
    );

    // Test with a malformed address
    let result = query_candid::<_, (CheckAddressResponse,)>(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: "not an address".to_string(),
        },),
    );

    assert!(result.is_err_and(|err| format!("{err:?}").contains("Invalid Bitcoin address")));

    // Test with a testnet address
    let result = query_candid::<_, (CheckAddressResponse,)>(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: "n47QBape2PcisN2mkHR2YnhqoBr56iPhJh".to_string(),
        },),
    );
    assert!(result.is_err_and(|err| format!("{err:?}").contains("Not a Bitcoin mainnet address")));

    // Test CheckMode::AcceptAll
    env.upgrade_canister(
        btc_checker_canister,
        btc_checker_wasm(),
        Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
            check_mode: Some(CheckMode::AcceptAll),
            ..UpgradeArg::default()
        })))
        .unwrap(),
        Some(controller),
    )
    .unwrap();

    let result = query_candid(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: blocked_address.clone(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Passed,))),
        "result = {result:?}"
    );

    // Test a mainnet address against testnet setup
    let Setup {
        btc_checker_canister,
        env,
        ..
    } = Setup::new(BtcNetwork::Testnet);

    let result = query_candid::<_, (CheckAddressResponse,)>(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: blocked_address,
        },),
    );
    assert!(result.is_err_and(|err| format!("{err:?}").contains("Not a Bitcoin testnet address")));

    // Test CheckMode::RejectAll
    env.upgrade_canister(
        btc_checker_canister,
        btc_checker_wasm(),
        Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
            check_mode: Some(CheckMode::RejectAll),
            ..UpgradeArg::default()
        })))
        .unwrap(),
        Some(controller),
    )
    .unwrap();

    let result = query_candid(
        &env,
        btc_checker_canister,
        "check_address",
        (CheckAddressArgs {
            address: "n47QBape2PcisN2mkHR2YnhqoBr56iPhJh".to_string(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Failed,))),
        "result = {result:?}"
    );
}

#[test]
fn test_check_transaction_passed() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    let txid =
        Txid::from_str("c80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed").unwrap();
    let env = &setup.env;
    let check_transaction_args = Encode!(&CheckTransactionArgs {
        txid: txid.as_ref().to_vec()
    })
    .unwrap();
    let check_transaction_str_args = Encode!(&CheckTransactionStrArgs {
        txid: txid.to_string()
    })
    .unwrap();

    // Normal operation requires making http outcalls.
    // We'll run this again after testing other CheckMode.
    let test_normal_operation = |method, arg| {
        let cycles_before = setup.env.cycle_balance(setup.caller);
        let call_id = setup
            .submit_btc_checker_call(method, arg, CHECK_TRANSACTION_CYCLES_REQUIRED)
            .expect("submit_call failed to return call id");

        mock_fetch_txids_responses(env);

        let result = env
            .await_call(call_id)
            .expect("the fetch request didn't finish");

        assert!(matches!(
            decode_one(&result).unwrap(),
            CheckTransactionResponse::Passed
        ));

        let cycles_after = env.cycle_balance(setup.caller);
        let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE
            + 2 * get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES);
        let actual_cost = cycles_before - cycles_after;
        assert!(actual_cost > expected_cost);
        assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);
        MetricsAssert::from_http_query(&setup).assert_contains_metric_matching(
            r#"btc_check_requests_total\{type=\"check_transaction\"\} 1 \d+"#,
        );
    };

    // With default installation
    test_normal_operation("check_transaction", check_transaction_args);

    // Test CheckMode::RejectAll
    env.tick();
    env.upgrade_canister(
        setup.btc_checker_canister,
        btc_checker_wasm(),
        Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
            check_mode: Some(CheckMode::RejectAll),
            ..UpgradeArg::default()
        })))
        .unwrap(),
        Some(setup.controller),
    )
    .unwrap();
    let cycles_before = env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs {
                txid: txid.as_ref().to_vec()
            })
            .unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let result = env
        .await_call(call_id)
        .expect("the fetch request didn't finish");

    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Failed(addresses) if addresses.is_empty()
    ),);
    let cycles_after = env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);
    MetricsAssert::from_http_query(&setup).assert_contains_metric_matching(
        r#"btc_check_requests_total\{type=\"check_transaction\"\} 1 \d+"#,
    );

    // Test CheckMode::AcceptAll
    env.tick();
    env.upgrade_canister(
        setup.btc_checker_canister,
        btc_checker_wasm(),
        Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
            check_mode: Some(CheckMode::AcceptAll),
            ..UpgradeArg::default()
        })))
        .unwrap(),
        Some(setup.controller),
    )
    .unwrap();
    let cycles_before = env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs {
                txid: txid.as_ref().to_vec()
            })
            .unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let result = env
        .await_call(call_id)
        .expect("the fetch request didn't finish");

    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Passed
    ),);
    let cycles_after = env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(
        actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN,
        "actual_cost: {actual_cost}, expected_cost: {expected_cost}"
    );
    MetricsAssert::from_http_query(&setup).assert_contains_metric_matching(
        r#"btc_check_requests_total\{type=\"check_transaction\"\} 1 \d+"#,
    );

    // Test CheckMode::Normal
    env.tick();
    env.upgrade_canister(
        setup.btc_checker_canister,
        btc_checker_wasm(),
        Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
            check_mode: Some(CheckMode::Normal),
            ..UpgradeArg::default()
        })))
        .unwrap(),
        Some(setup.controller),
    )
    .unwrap();

    test_normal_operation("check_transaction_str", check_transaction_str_args.clone());

    // Test empty argument upgrade
    env.tick();
    env.upgrade_canister(
        setup.btc_checker_canister,
        btc_checker_wasm(),
        Encode!().unwrap(),
        Some(setup.controller),
    )
    .unwrap();

    test_normal_operation("check_transaction_str", check_transaction_str_args);
}

/// Mock the response for the HTTP outcalls fetching the transaction inputs for txid
/// `c80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed`. There will be
/// two outcalls because the canister will first fetch the input txid, and then fetch
/// the `vout[0]` from the returned transaction body. The response bodies are generated
/// from the output of:
/// ```shell
/// curl -H 'User-Agent: bitcoin-value-collector' https://btcscan.org/api/tx/{txid}/raw
/// ```
fn mock_fetch_txids_responses(env: &PocketIc) {
    let canister_http_requests = tick_until_next_request(env);
    let body = b"\
\x02\x00\x00\x00\x01\x17\x34\x3a\xab\xa9\x67\x67\x2f\x17\xef\x0a\xbf\x4b\xb1\x14\xad\x19\x63\xe0\
\x7d\xd2\xf2\x05\xaa\x25\xa4\xda\x50\x3e\xdb\x01\xab\x01\x00\x00\x00\x6a\x47\x30\x44\x02\x20\x21\
\x81\xb5\x9c\xa7\xed\x7e\x2c\x8e\x06\x96\x52\xb0\x7e\xd2\x10\x24\x9e\x83\x37\xec\xc5\x35\xca\x6b\
\x75\x3c\x02\x44\x89\xe4\x5d\x02\x20\x2a\xc7\x55\xcb\x55\x97\xf1\xcc\x2c\xad\x32\xb8\xa4\x33\xf1\
\x79\x6b\x5f\x51\x76\x71\x6d\xa9\x22\x2c\x65\xf9\x44\xaf\xd1\x3d\xa8\x01\x21\x02\xc4\xc6\x9e\x4d\
\x36\x4b\x3e\xdf\x84\xb5\x20\xa0\x18\xd5\x7e\x71\xfa\xce\x19\x7e\xc8\xf9\x46\x43\x60\x7e\x4a\xca\
\x70\xdc\x82\xc1\xfd\xff\xff\xff\x02\x10\x27\x00\x00\x00\x00\x00\x00\x19\x76\xa9\x14\x11\xb3\x66\
\xed\xfc\x0a\x8b\x66\xfe\xeb\xae\x5c\x2e\x25\xa7\xb6\xa5\xd1\xcf\x31\x88\xac\x7c\x2e\x00\x00\x00\
\x00\x00\x00\x19\x76\xa9\x14\xb9\x73\x68\xd8\xbf\x0a\x37\x69\x00\x85\x16\x57\xf3\x7f\xbe\x73\xa6\
\x56\x61\x33\x88\xac\x14\xa4\x0c\x00"
        .to_vec();
    env.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: canister_http_requests[0].subnet_id,
        request_id: canister_http_requests[0].request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body,
        }),
        additional_responses: vec![],
    });

    let canister_http_requests = tick_until_next_request(env);
    let body = b"\
\x02\x00\x00\x00\x01\x82\xc8\x5d\xe7\x4d\x19\xbb\x36\x16\x2f\xca\xef\xc7\xe7\x70\x15\x65\xb0\x2d\
\xf6\x06\x0f\x8e\xcf\x49\x64\x63\x37\xfc\xe8\x59\x37\x07\x00\x00\x00\x6a\x47\x30\x44\x02\x20\x15\
\xf2\xc7\x7a\x3b\x95\x13\x73\x7a\xa2\x86\xb3\xe6\x06\xf9\xb6\x82\x1c\x6d\x5d\x35\xe5\xa9\x58\xe0\
\x1f\x65\x76\xec\xdf\xac\x76\x02\x20\x4e\xad\x06\x1d\xe8\x3c\x5b\x07\x25\x8e\xfd\x2f\x44\x3d\xeb\
\xc8\x47\x25\x2b\xfc\xf4\x24\xb3\x75\x8f\xd1\x57\x92\xef\xf4\xa4\xaa\x01\x21\x02\xc4\xc6\x9e\x4d\
\x36\x4b\x3e\xdf\x84\xb5\x20\xa0\x18\xd5\x7e\x71\xfa\xce\x19\x7e\xc8\xf9\x46\x43\x60\x7e\x4a\xca\
\x70\xdc\x82\xc1\xfd\xff\xff\xff\x02\x10\x27\x00\x00\x00\x00\x00\x00\x19\x76\xa9\x14\x62\xe9\x07\
\xb1\x5c\xbf\x27\xd5\x42\x53\x99\xeb\xf6\xf0\xfb\x50\xeb\xb8\x8f\x18\x88\xac\x00\x96\x00\x00\x00\
\x00\x00\x00\x19\x76\xa9\x14\xb9\x73\x68\xd8\xbf\x0a\x37\x69\x00\x85\x16\x57\xf3\x7f\xbe\x73\xa6\
\x56\x61\x33\x88\xac\xb3\xa3\x0c\x00"
        .to_vec();
    env.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: canister_http_requests[0].subnet_id,
        request_id: canister_http_requests[0].request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        }),
        // Fill additional responses with different headers to test if the transform
        // function does its job by clearing the headers.
        additional_responses: (1..13)
            .map(|i| {
                CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                    status: 200,
                    headers: vec![CanisterHttpHeader {
                        name: format!("name-{i}"),
                        value: format!("{i}"),
                    }],
                    body: body.clone(),
                })
            })
            .collect(),
    });
}

#[test]
fn test_check_transaction_error() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    let mut txid =
        Txid::from_str("a80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed")
            .unwrap()
            .as_ref()
            .to_vec();

    // Test should return NotEnoughCycles error, not InvalidTransactionId
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: vec![0; 31] }).unwrap(),
            CHECK_TRANSACTION_CYCLES_SERVICE_FEE - 1,
        )
        .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles),
    ));

    // Test for cycles not enough
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED - 1,
        )
        .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles),
    ));

    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for 500 error
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let canister_http_requests = tick_until_next_request(&setup.env);
    setup
        .env
        .mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 500,
                headers: vec![],
                body: vec![],
            }),
            additional_responses: vec![],
        });
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    // 500 error is retriable
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::TransientInternalError(msg)
        )) if msg.contains("received code 500")
    ));
    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE
        + get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES);
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for 404 error
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let canister_http_requests = tick_until_next_request(&setup.env);
    setup
        .env
        .mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 404,
                headers: vec![],
                body: vec![],
            }),
            additional_responses: vec![],
        });
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    // 404 error is retriable too
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::TransientInternalError(msg)
        )) if msg.contains("received code 404")
    ));
    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE
        + get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES);
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for CanisterHttpReject error
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let canister_http_requests = tick_until_next_request(&setup.env);
    setup
        .env
        .mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
                reject_code: 2, //SYS_TRANSIENT
                message: "Failed to directly connect".to_string(),
            }),
            additional_responses: vec![],
        });
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    // Reject error is retriable too
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::TransientInternalError(msg)
        )) if msg.contains("Failed to directly connect")
    ));
    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE
        + get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES);
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for malformatted transaction data
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let canister_http_requests = tick_until_next_request(&setup.env);
    setup
        .env
        .mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: vec![2, 0, 0, 0],
            }),
            additional_responses: vec![],
        });
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    // malformated tx error is retriable
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(
            CheckTransactionRetriable::TransientInternalError(msg)
        )) if msg.contains("TxEncoding")
    ));
    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE
        + get_tx_cycle_cost(INITIAL_MAX_RESPONSE_BYTES, TEST_SUBNET_NODES);
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for malformatted txid
    let cycles_before = setup.env.cycle_balance(setup.caller);
    txid.pop();
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&CheckTransactionArgs { txid }).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(
            CheckTransactionIrrecoverableError::InvalidTransactionId(_)
        ))
    ));

    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    // Test for malformatted txid in string form
    let cycles_before = setup.env.cycle_balance(setup.caller);
    let too_short_txid =
        "a80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475".to_string();
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction_str",
            Encode!(&CheckTransactionStrArgs {
                txid: too_short_txid
            })
            .unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(
            CheckTransactionIrrecoverableError::InvalidTransactionId(_)
        ))
    ));

    let cycles_after = setup.env.cycle_balance(setup.caller);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < UNIVERSAL_CANISTER_CYCLE_MARGIN);

    MetricsAssert::from_http_query(&setup)
        .assert_contains_metric_matching(
            r#"btc_check_requests_total\{type=\"check_transaction\"\} 5 \d+"#,
        )
        .assert_contains_metric_matching(
            r#"btc_checker_http_calls_total\{provider=\"[a-z.]*\",status=\"HttpStatusCode\(500\)\"\} 1 \d+"#,
        )
        .assert_contains_metric_matching(
            r#"btc_checker_http_calls_total\{provider=\"[a-z.]*\",status=\"HttpStatusCode\(200\)\"\} 1 \d+"#,
        )
        .assert_contains_metric_matching(
            r#"btc_checker_http_calls_total\{provider=\"[a-z.]*\",status=\"HttpStatusCode\(404\)\"\} 1 \d+"#,
        )
        .assert_contains_metric_matching(
            r#"btc_checker_http_calls_total\{provider=\"[a-z.]*\",status=\"IcErrorCallRejected\(2\)\"\} 1 \d+"#,
        );
}
#[test]
fn test_check_transaction_query_unknown() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    let txid =
        Txid::from_str("c80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed").unwrap();

    let (result,): (CheckTransactionQueryResponse,) = setup
        .query_btc_checker(
            "check_transaction_query",
            CheckTransactionQueryArgs::TxIdBin(txid.as_ref().to_vec()),
        )
        .expect("the fetch request didn't finish");
    assert!(matches!(result, CheckTransactionQueryResponse::Unknown));
}

#[test]
fn test_check_transaction_query_error() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    let txid =
        Txid::from_str("a80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed").unwrap();

    // Tests for malformed txids
    let too_short_txid_str = "a80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993".to_string();
    let too_short_txid_bin = txid.as_ref()[..=28].to_vec();
    for arg in &[
        CheckTransactionQueryArgs::TxIdBin(too_short_txid_bin),
        CheckTransactionQueryArgs::TxIdStr(too_short_txid_str),
    ] {
        let result: Result<(CheckTransactionQueryResponse,), RejectResponse> =
            setup.query_btc_checker("check_transaction_query", arg);
        assert!(matches!(
            result,
            Err(RejectResponse {
                reject_code: RejectCode::CanisterError,
                ..
            })
        ));
    }
}

#[test]
fn test_check_transaction_query_already_fetched() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    let txid =
        Txid::from_str("c80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed").unwrap();

    // Pre-fetch the txid inputs and outputs with the update method
    let check_transaction_args = CheckTransactionArgs {
        txid: txid.as_ref().to_vec(),
    };
    let call_id = setup
        .submit_btc_checker_call(
            "check_transaction",
            Encode!(&check_transaction_args).unwrap(),
            CHECK_TRANSACTION_CYCLES_REQUIRED,
        )
        .expect("submit_call failed to return call id");
    mock_fetch_txids_responses(&setup.env);
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    assert!(matches!(
        decode_one(&result).unwrap(),
        CheckTransactionResponse::Passed
    ));

    for arg in &[
        CheckTransactionQueryArgs::TxIdBin(txid.as_ref().to_vec()),
        CheckTransactionQueryArgs::TxIdStr(txid.to_string()),
    ] {
        let (result,): (CheckTransactionQueryResponse,) = setup
            .query_btc_checker("check_transaction_query", arg)
            .expect("the fetch request didn't finish");
        assert!(matches!(result, CheckTransactionQueryResponse::Passed));
    }

    // Test for blocked addresses
    setup.env.tick();
    setup
        .env
        .upgrade_canister(
            setup.btc_checker_canister,
            btc_checker_wasm(),
            Encode!(&CheckArg::UpgradeArg(Some(UpgradeArg {
                check_mode: Some(CheckMode::RejectAll),
                ..UpgradeArg::default()
            })))
            .unwrap(),
            Some(setup.controller),
        )
        .unwrap();

    for arg in &[
        CheckTransactionQueryArgs::TxIdBin(txid.as_ref().to_vec()),
        CheckTransactionQueryArgs::TxIdStr(txid.to_string()),
    ] {
        let (result,): (CheckTransactionQueryResponse,) = setup
            .query_btc_checker("check_transaction_query", arg)
            .expect("the fetch request didn't finish");
        assert!(matches!(result, CheckTransactionQueryResponse::Failed(_)));
    }
}

fn tick_until_next_request(env: &PocketIc) -> Vec<CanisterHttpRequest> {
    for _ in 0..MAX_TICKS {
        if !env.get_canister_http().is_empty() {
            break;
        }
        env.tick();
    }
    let canister_http_requests = env.get_canister_http();
    assert!(
        !canister_http_requests.is_empty(),
        "The canister did not produce another request in {MAX_TICKS} ticks {canister_http_requests:?}"
    );
    canister_http_requests
}

#[test]
fn should_query_logs_and_metrics() {
    let setup = Setup::new(BtcNetwork::Mainnet);
    make_http_query(&setup, "/metrics");
    make_http_query(&setup, "/logs");
}

fn make_http_query<U: Into<String>>(setup: &Setup, url: U) -> Vec<u8> {
    use candid::Decode;
    let request = HttpRequest {
        method: "GET".to_string(),
        url: url.into(),
        headers: Default::default(),
        body: Default::default(),
    };

    let response = Decode!(
        &setup
            .env
            .query_call(
                setup.btc_checker_canister,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).expect("failed to encode HTTP request"),
            )
            .expect("failed to query get_transactions on the ledger"),
        HttpResponse
    )
    .unwrap();

    assert_eq!(response.status_code, 200_u16);
    response.body.into_vec()
}

impl PocketIcHttpQuery for &Setup {
    fn get_pocket_ic(&self) -> &PocketIc {
        &self.env
    }

    fn get_canister_id(&self) -> CanisterId {
        self.btc_checker_canister
    }
}
