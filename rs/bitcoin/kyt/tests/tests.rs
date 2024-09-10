use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_btc_interface::Txid;
use ic_btc_kyt::{
    blocklist, get_tx_cycle_cost, CheckAddressArgs, CheckAddressResponse, CheckTransactionArgs,
    CheckTransactionResponse, CHECK_TRANSACTION_CYCLES_REQUIRED,
    CHECK_TRANSACTION_CYCLES_SERVICE_FEE, INITIAL_BUFFER_SIZE,
};
use ic_test_utilities_load_wasm::load_wasm;
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use pocket_ic::{
    common::rest::{
        CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse, MockCanisterHttpResponse,
        RawMessageId,
    },
    query_candid, PocketIc, UserError, WasmResult,
};
use std::str::FromStr;

const MAX_TICKS: usize = 10;

struct Setup {
    controller: Principal,
    universal_canister: Principal,
    kyt_canister: Principal,
    env: PocketIc,
}

fn kyt_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-btc-kyt-canister",
        &[],
    )
}

fn setup_env() -> Setup {
    let controller = PrincipalId::new_user_test_id(1).0;
    let env = PocketIc::new();

    let universal_canister = env.create_canister_with_settings(Some(controller), None);
    env.add_cycles(universal_canister, 100_000_000_000_000);
    env.install_canister(
        universal_canister,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        Some(controller),
    );

    let kyt_canister = env.create_canister();
    env.add_cycles(kyt_canister, 100_000_000_000_000);
    env.install_canister(kyt_canister, kyt_wasm(), vec![], None);

    Setup {
        controller,
        universal_canister,
        kyt_canister,
        env,
    }
}

#[test]
fn test_check_address() {
    let Setup {
        kyt_canister, env, ..
    } = setup_env();

    // Choose an address from the blocklist
    let blocklist_len = blocklist::BTC_ADDRESS_BLOCKLIST.len();
    let result = query_candid(
        &env,
        kyt_canister,
        "check_address",
        (CheckAddressArgs {
            address: blocklist::BTC_ADDRESS_BLOCKLIST[blocklist_len / 2].to_string(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Failed,))),
        "result = {:?}",
        result
    );

    // Satoshi's address hopefully is not in the blocklist
    let result = query_candid(
        &env,
        kyt_canister,
        "check_address",
        (CheckAddressArgs {
            address: "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S".to_string(),
        },),
    );
    assert!(
        matches!(result, Ok((CheckAddressResponse::Passed,))),
        "result = {:?}",
        result
    );

    // Test with an malformed address
    let result = query_candid::<_, (CheckAddressResponse,)>(
        &env,
        kyt_canister,
        "check_address",
        (CheckAddressArgs {
            address: "not an address".to_string(),
        },),
    );
    assert!(result.is_err_and(|err| format!("{:?}", err).contains("Invalid bitcoin address")));

    // Test with an testnet address
    let result = query_candid::<_, (CheckAddressResponse,)>(
        &env,
        kyt_canister,
        "check_address",
        (CheckAddressArgs {
            address: "n47QBape2PcisN2mkHR2YnhqoBr56iPhJh".to_string(),
        },),
    );
    assert!(result.is_err_and(|err| format!("{:?}", err).contains("Not a bitcoin mainnet address")));
}

fn universal_canister_payload(
    receiver: &PrincipalId,
    method: &str,
    payload: Vec<u8>,
    cycles: Cycles,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles,
        )
        .build()
}

fn submit_universal_call(
    setup: &Setup,
    receiver: Principal,
    method: &str,
    args: Vec<u8>,
    cycles: u128,
) -> Result<RawMessageId, UserError> {
    let payload =
        universal_canister_payload(&PrincipalId(receiver), method, args, Cycles::new(cycles));
    setup.env.submit_call(
        setup.universal_canister,
        setup.controller,
        "update",
        payload,
    )
}

#[test]
fn test_check_transaction_passed() {
    let setup = setup_env();
    let cycles_before = setup.env.cycle_balance(setup.universal_canister);

    let txid =
        Txid::from_str("c80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed").unwrap();
    let call_id = submit_universal_call(
        &setup,
        setup.kyt_canister,
        "check_transaction",
        Encode!(&CheckTransactionArgs {
            txid: txid.as_ref().to_vec()
        })
        .unwrap(),
        CHECK_TRANSACTION_CYCLES_REQUIRED,
    )
    .expect("submit_call failed to return call id");
    let env = &setup.env;

    // The response body used for testing below is generated from the output of
    //
    //   curl -H 'User-Agent: bitcoin-value-collector' https://btcscan.org/api/tx/{txid}/raw
    //
    // There wll be two outcalls because the canister will first fetch the above
    // given txid, and then fetch the vout[0] from the returned transaction body.

    let canister_http_requests = tick_until_next_request(&env);
    env.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: b"\
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
                    .to_vec(),
            }),
        });

    let canister_http_requests = tick_until_next_request(&env);
    env.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: canister_http_requests[0].subnet_id,
            request_id: canister_http_requests[0].request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: b"\
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
                    .to_vec(),
            }),
        });

    let result = env
        .await_call(call_id)
        .expect("the fetch request didn't finish");

    match &result {
        WasmResult::Reply(bytes) => {
            let response = Decode!(bytes, CheckTransactionResponse).unwrap();
            assert!(matches!(response, CheckTransactionResponse::Passed));
        }
        WasmResult::Reject(msg) => panic!("unexpected reject: {}", msg),
    }

    let cycles_after = env.cycle_balance(setup.universal_canister);
    let expected_cost =
        CHECK_TRANSACTION_CYCLES_SERVICE_FEE + 2 * get_tx_cycle_cost(INITIAL_BUFFER_SIZE);
    let actual_cost = cycles_before - cycles_after;
    // Since we use universal_canister, actual_cost is greater than expected_cost
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < 7_000_000);
}

#[test]
fn test_check_transaction_error() {
    let setup = setup_env();
    let cycles_before = setup.env.cycle_balance(setup.universal_canister);
    let mut txid =
        Txid::from_str("a80763842edc9a697a2114517cf0c138c5403a761ef63cfad1fa6993fa3475ed")
            .unwrap()
            .as_ref()
            .to_vec();

    // Test for cycles not enough
    let call_id = submit_universal_call(
        &setup,
        setup.kyt_canister,
        "check_transaction",
        Encode!(&CheckTransactionArgs { txid: txid.clone() }).unwrap(),
        CHECK_TRANSACTION_CYCLES_REQUIRED - 1,
    )
    .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    match &result {
        WasmResult::Reply(bytes) => {
            let response = Decode!(bytes, CheckTransactionResponse).unwrap();
            assert!(matches!(
                response,
                CheckTransactionResponse::NotEnoughCycles
            ));
        }
        WasmResult::Reject(msg) => panic!("unexpected reject: {}", msg),
    };
    let cycles_after = setup.env.cycle_balance(setup.universal_canister);
    let expected_cost = CHECK_TRANSACTION_CYCLES_SERVICE_FEE;
    let actual_cost = cycles_before - cycles_after;
    // Since we use universal_canister, actual_cost is greater than expected_cost
    assert!(actual_cost > expected_cost);
    assert!(actual_cost - expected_cost < 7_000_000);

    // Test for malformatted txid
    txid.pop();
    let call_id = submit_universal_call(
        &setup,
        setup.kyt_canister,
        "check_transaction",
        Encode!(&CheckTransactionArgs { txid }).unwrap(),
        CHECK_TRANSACTION_CYCLES_REQUIRED,
    )
    .expect("submit_call failed to return call id");
    let result = setup
        .env
        .await_call(call_id)
        .expect("the fetch request didn't finish");
    match &result {
        WasmResult::Reply(bytes) => {
            let response = Decode!(bytes, CheckTransactionResponse).unwrap();
            assert!(matches!(
                response,
                CheckTransactionResponse::Error(msg) if msg.contains("Invalid txid"),
            ));
        }
        WasmResult::Reject(msg) => panic!("unexpected reject: {}", msg),
    };
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
        "The canister did not produce another request in {} ticks {:?}",
        MAX_TICKS,
        canister_http_requests
    );
    canister_http_requests
}
