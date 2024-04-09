use candid::{decode_one, encode_one, Principal};
use ic_base_types::PrincipalId;
use ic_cdk::api::management_canister::provisional::CanisterId;
use ic_universal_canister::{wasm, CallArgs, UNIVERSAL_CANISTER_WASM};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, BlockIndex, LedgerCanisterInitPayload, Memo, Name,
    Symbol, Tokens, TransferArgs, TransferError,
};
use pocket_ic::{
    common::rest::{BlobCompression, DtsFlag, SubnetConfigSet, SubnetKind},
    PocketIc, PocketIcBuilder, UserError, WasmResult,
};
use std::{
    collections::HashMap,
    io::Read,
    thread,
    time::{Duration, SystemTime},
};

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

#[test]
fn test_counter_canister() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the counter canister wasm file on the canister.
    let counter_wasm = counter_wasm();
    pic.install_canister(can_id, counter_wasm, vec![], None);

    // Make some calls to the canister.
    let reply = call_counter_can(&pic, can_id, "read");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![1, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "write");
    assert_eq!(reply, WasmResult::Reply(vec![2, 0, 0, 0]));
    let reply = call_counter_can(&pic, can_id, "read");
    assert_eq!(reply, WasmResult::Reply(vec![2, 0, 0, 0]));
}

fn counter_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("COUNTER_WASM").expect("Missing counter wasm file");
    std::fs::read(wasm_path).unwrap()
}

fn call_counter_can(ic: &PocketIc, can_id: CanisterId, method: &str) -> WasmResult {
    ic.update_call(
        can_id,
        Principal::anonymous(),
        method,
        encode_one(()).unwrap(),
    )
    .expect("Failed to call counter canister")
}

#[test]
fn test_xnet_ledger_canister() {
    // Set up PocketIC with two subnets: the NNS and an application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let nns_subnet = pic.topology().get_nns().unwrap();
    let app_subnet = pic.topology().get_app_subnets()[0];

    // Install a proxy canister on the application subnet.
    let proxy_canister = pic.create_canister_on_subnet(None, None, app_subnet);
    pic.add_cycles(proxy_canister, INIT_CYCLES);

    pic.install_canister(
        proxy_canister,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
    );

    // Create a ledger canister on the NNS subnet.
    let wasm_path = std::env::var_os("LEDGER_WASM").expect("Missing wasm file");
    let ledger_wasm = std::fs::read(wasm_path).unwrap();
    let ledger_canister = pic.create_canister_on_subnet(None, None, nns_subnet);

    // Give the proxy canister some tokens to pay the beneficiary.
    let beneficiary = AccountIdentifier::new(PrincipalId::new_user_test_id(1), None);
    let mut initial_balances = HashMap::new();
    initial_balances.insert(beneficiary, Tokens::from_e8s(0));
    initial_balances.insert(
        AccountIdentifier::new(proxy_canister.into(), None),
        Tokens::from_e8s(10_000_000),
    );

    // Specify token details.
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(Principal::anonymous().into(), None))
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("MYTOKEN", "My Token")
        .build()
        .unwrap();

    // Install ledger canister.
    pic.install_canister(
        ledger_canister,
        ledger_wasm,
        encode_one(payload).unwrap(),
        None,
    );

    // Check name and symbol.
    let resp: Name = cross_canister_call(&pic, proxy_canister, ledger_canister, "name", ());
    assert_eq!(resp.name, "My Token");
    let resp: Symbol = cross_canister_call(&pic, proxy_canister, ledger_canister, "symbol", ());
    assert_eq!(resp.symbol, "MYTOKEN");

    // Check initial balance of the beneficiary.
    let balance = balance_of(&pic, proxy_canister, ledger_canister, beneficiary);
    assert_eq!(balance, Tokens::from_e8s(0));

    // Transfer 420 tokens to the beneficiary from the proxy canister.
    let resp = transfer(
        &pic,
        proxy_canister,
        ledger_canister,
        beneficiary,
        420,
        10_000,
    );
    assert!(resp.is_ok());

    // Try to transfer tokens again, but with an insufficent fee.
    let resp = transfer(&pic, proxy_canister, ledger_canister, beneficiary, 420, 1);
    assert_eq!(
        resp,
        Err(TransferError::BadFee {
            expected_fee: Tokens::from_e8s(10_000)
        })
    );

    // Check new balance of the beneficiary.
    let balance = balance_of(&pic, proxy_canister, ledger_canister, beneficiary);
    assert_eq!(balance, Tokens::from_e8s(420));
}

fn balance_of(
    pic: &PocketIc,
    caller: Principal,
    callee: Principal,
    account: AccountIdentifier,
) -> Tokens {
    let payload = BinaryAccountBalanceArgs {
        account: account.to_address(),
    };
    cross_canister_call(pic, caller, callee, "account_balance", payload)
}

fn transfer(
    pic: &PocketIc,
    from: Principal,
    ledger_canister: Principal,
    to: AccountIdentifier,
    amount: u64,
    fee: u64,
) -> Result<BlockIndex, TransferError> {
    let payload = TransferArgs {
        memo: Memo(0),
        amount: Tokens::from_e8s(amount),
        fee: Tokens::from_e8s(fee),
        from_subaccount: None,
        to: to.to_address(),
        created_at_time: None,
    };
    cross_canister_call(pic, from, ledger_canister, "transfer", payload)
}

fn cross_canister_call<T>(
    pic: &PocketIc,
    caller: Principal,
    callee: Principal,
    method: &str,
    payload: impl candid::CandidType,
) -> T
where
    T: for<'a> serde::de::Deserialize<'a> + candid::CandidType,
{
    let xnet_result = pic.update_call(
        caller,
        Principal::anonymous(),
        "update",
        wasm()
            .call_simple(
                callee,
                method,
                CallArgs::default().other_side(encode_one(payload).unwrap()),
            )
            .build(),
    );
    let WasmResult::Reply(reply) = xnet_result.unwrap() else {
        unreachable!()
    };
    decode_one(&reply).unwrap()
}

// Canister code incrementing a counter in every heartbeat
// and exporting a query method to read the counter.
const AUTO_PROGRESS_WAT: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $read
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_query read" (func $read))
        (export "canister_heartbeat" (func $inc))
    )
"#;

#[test]
fn test_auto_progress() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the auto progress canister wasm file on the canister.
    let auto_progress_wasm = wat::parse_str(AUTO_PROGRESS_WAT).unwrap();
    pic.install_canister(can_id, auto_progress_wasm, vec![], None);

    // Capture the original value of the counter.
    let old_counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
        Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
        _ => panic!("could not read counter"),
    };

    // Starting auto progress on the IC.
    // Consequently, heartbeats should be executed on the auto progress canister automatically
    // and its counter should increase.
    pic.auto_progress();

    let mut ok = false;
    for _ in 0..100 {
        let counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
            Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
            _ => panic!("could not read counter"),
        };
        if counter > old_counter {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ok {
        panic!("did not observe a counter increase")
    }

    // Stopping auto progress on the IC.
    // The counter should not increase anymore.
    pic.stop_progress();

    // Capture the current value of the counter.
    let cur_counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
        Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
        _ => panic!("could not read counter"),
    };

    for _ in 0..100 {
        let counter = match pic.query_call(can_id, Principal::anonymous(), "read", vec![]) {
            Ok(WasmResult::Reply(data)) => u32::from_le_bytes(data.try_into().unwrap()),
            _ => panic!("could not read counter"),
        };
        assert_eq!(counter, cur_counter);
        thread::sleep(Duration::from_millis(100));
    }
}

// Canister code with a very slow method.
fn very_slow_wasm(n: u64) -> Vec<u8> {
    let wat = format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $run
            ;; create a local variable and initialize it to 0
            (local $i i32)
            (local $j i32)
            (loop $my_loop
                i32.const 0
                local.set $j
                (loop $my_inner_loop
                    ;; add one to $j
                    local.get $j
                    i32.const 1
                    i32.add
                    local.set $j
                    ;; if $j is less than 200000 branch to loop
                    local.get $j
                    i32.const {}
                    i32.lt_s
                    br_if $my_inner_loop
                )
                ;; add one to $i
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                ;; if $i is less than 200000 branch to loop
                local.get $i
                i32.const {}
                i32.lt_s
                br_if $my_loop
            )
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_update run" (func $run))
        (export "canister_heartbeat" (func $inc))
    )
"#,
        n, n
    );
    wat::parse_str(wat).unwrap()
}

fn run_very_slow_method(pic: &PocketIc, dts_flag: DtsFlag) -> Result<WasmResult, UserError> {
    // Create a canister.
    let t0 = pic.get_time();
    let can_id = pic.create_canister();
    let t1 = pic.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Charge the canister with 2T cycles.
    pic.add_cycles(can_id, 100 * INIT_CYCLES);

    // Install the very slow canister wasm file on the canister.
    pic.install_canister(can_id, very_slow_wasm(200_000), vec![], None);

    let t0 = pic.get_time();
    let res = pic.update_call(can_id, Principal::anonymous(), "run", vec![]);
    let t1 = pic.get_time();
    if let DtsFlag::Enabled = dts_flag {
        assert!(t1 >= t0 + Duration::from_nanos(10)); // DTS takes at least 10 rounds
    } else {
        assert_eq!(t1, t0 + Duration::from_nanos(1)); // update call should take one round, i.e., 1ns without DTS
    }

    res
}

#[test]
fn test_benchmarking_subnet() {
    let pic = PocketIcBuilder::new()
        .with_benchmarking_application_subnet()
        .build();
    run_very_slow_method(&pic, DtsFlag::Disabled).unwrap();
}

#[test]
fn very_slow_method_on_application_subnet() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();
    run_very_slow_method(&pic, DtsFlag::Enabled).unwrap_err();
}

fn test_dts(dts_flag: DtsFlag) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_dts_flag(dts_flag)
        .build();

    // Create a canister.
    let t0 = pic.get_time();
    let can_id = pic.create_canister();
    let t1 = pic.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Charge the canister with 2T cycles.
    pic.add_cycles(can_id, 100 * INIT_CYCLES);

    // Install the very slow canister wasm file on the canister.
    pic.install_canister(can_id, very_slow_wasm(60_000), vec![], None);

    let t0 = pic.get_time();
    pic.update_call(can_id, Principal::anonymous(), "run", vec![])
        .unwrap();
    let t1 = pic.get_time();
    if let DtsFlag::Enabled = dts_flag {
        assert!(t1 >= t0 + Duration::from_nanos(10)); // DTS takes at least 10 rounds
    } else {
        assert_eq!(t1, t0 + Duration::from_nanos(1)); // update call should take one round, i.e., 1ns without DTS
    }
}

#[test]
fn test_dts_enabled() {
    test_dts(DtsFlag::Enabled);
}

#[test]
fn test_dts_disabled() {
    test_dts(DtsFlag::Disabled);
}

#[test]
fn test_create_canister_with_id() {
    let config = SubnetConfigSet {
        nns: true,
        ii: true,
        ..Default::default()
    };
    let pic = PocketIc::from_config(config);
    // goes on NNS
    let canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);
    assert_eq!(
        pic.get_subnet(canister_id).unwrap(),
        pic.topology().get_nns().unwrap()
    );
    // goes on II
    let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);
    assert_eq!(
        pic.get_subnet(canister_id).unwrap(),
        pic.topology().get_ii().unwrap()
    );
}

#[test]
#[should_panic(expected = "is out of cycles")]
fn test_install_canister_with_no_cycles() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let wasm = b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec();
    pic.install_canister(canister_id, wasm.clone(), vec![], None);
}

#[test]
#[should_panic(expected = "not found")]
fn test_canister_routing_not_found() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.stop_canister(canister_id, None).unwrap();
    pic.delete_canister(canister_id, None).unwrap();

    let wasm = b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec();
    pic.install_canister(canister_id, wasm, vec![], None);
}

#[test]
fn test_create_canister_after_create_canister_with_id() {
    let pic = PocketIcBuilder::new().with_nns_subnet().build();

    let canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);
    let other_canister_id = pic.create_canister();
    assert_ne!(other_canister_id, canister_id);
}

#[test]
fn test_create_canister_with_used_id_fails() {
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    let canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let res = pic.create_canister_with_id(None, None, canister_id);
    assert!(res.is_ok());
    let res = pic.create_canister_with_id(None, None, canister_id);
    assert!(res.is_err());
}

#[test]
#[should_panic(expected = "not contained on any subnet")]
fn test_create_canister_with_not_contained_id_panics() {
    let pic = PocketIc::new();
    let _ = pic.create_canister_with_id(None, None, Principal::anonymous());
}

#[test]
fn test_cycle_scaling() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_fiduciary_subnet()
        .build();
    let app_canister_id =
        pic.create_canister_on_subnet(None, None, pic.topology().get_app_subnets()[0]);
    pic.add_cycles(app_canister_id, 100_000_000_000_000);
    let fidu_canister_id =
        pic.create_canister_on_subnet(None, None, pic.topology().get_fiduciary().unwrap());
    pic.add_cycles(fidu_canister_id, 100_000_000_000_000);

    let old_app_cycles = pic.cycle_balance(app_canister_id);
    pic.install_canister(
        app_canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
    );
    let new_app_cycles = pic.cycle_balance(app_canister_id);
    let app_cycles_delta = old_app_cycles - new_app_cycles;

    let old_fidu_cycles = pic.cycle_balance(fidu_canister_id);
    pic.install_canister(
        fidu_canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
    );
    let new_fidu_cycles = pic.cycle_balance(fidu_canister_id);
    let fidu_cycles_delta = old_fidu_cycles - new_fidu_cycles;

    // the fiduciary subnet has 28 nodes which is more than twice
    // the number of nodes on an application subnet (13)
    assert!(fidu_cycles_delta > 2 * app_cycles_delta);
}

#[test]
fn test_random_subnet_selection() {
    // Application subnet has highest priority
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .with_bitcoin_subnet()
        .with_system_subnet()
        .with_application_subnet()
        .build();

    let canister_id = pic.create_canister();
    let subnet_id = pic.get_subnet(canister_id).unwrap();
    let subnet_kind = pic.topology().0.get(&subnet_id).unwrap().subnet_kind;
    assert_eq!(subnet_kind, SubnetKind::Application);

    // System subnet has highest priority
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .with_bitcoin_subnet()
        .with_system_subnet()
        .build();
    let canister_id = pic.create_canister();
    let subnet_id = pic.get_subnet(canister_id).unwrap();
    let subnet_kind = pic.topology().0.get(&subnet_id).unwrap().subnet_kind;
    assert_eq!(subnet_kind, SubnetKind::System);
}

#[test]
fn test_xnet_call() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    let subnet_id_1 = pic.topology().get_app_subnets()[0];
    let subnet_id_2 = pic.topology().get_app_subnets()[1];

    let canister_1 = pic.create_canister_on_subnet(None, None, subnet_id_1);
    let canister_2 = pic.create_canister_on_subnet(None, None, subnet_id_2);
    pic.add_cycles(canister_1, INIT_CYCLES);
    pic.add_cycles(canister_2, INIT_CYCLES);

    pic.install_canister(canister_1, UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None);
    pic.install_canister(canister_2, UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None);

    let result = pic.update_call(
        canister_1,
        Principal::anonymous(),
        "update",
        wasm()
            .set_global_data(b"I'm canister 1 on subnet 1")
            .get_global_data()
            .append_and_reply()
            .build(),
    );
    assert_eq!(
        result,
        Ok(WasmResult::Reply(b"I'm canister 1 on subnet 1".to_vec()))
    );

    let result = pic.update_call(
        canister_2,
        Principal::anonymous(),
        "update",
        wasm()
            .set_global_data(b"I'm canister 2 on subnet 2")
            .get_global_data()
            .append_and_reply()
            .build(),
    );
    assert_eq!(
        result,
        Ok(WasmResult::Reply(b"I'm canister 2 on subnet 2".to_vec()))
    );

    let xnet_result = pic.update_call(
        canister_1,
        Principal::anonymous(),
        "update",
        wasm()
            .inter_update(
                canister_2,
                CallArgs::default().other_side(wasm().get_global_data().append_and_reply()),
            )
            .build(),
    );
    assert_eq!(
        xnet_result,
        Ok(WasmResult::Reply(b"I'm canister 2 on subnet 2".to_vec()))
    );

    let xnet_result = pic.update_call(
        canister_2,
        Principal::anonymous(),
        "update",
        wasm()
            .inter_update(
                canister_1,
                CallArgs::default().other_side(wasm().get_global_data().append_and_reply()),
            )
            .build(),
    );
    assert_eq!(
        xnet_result,
        Ok(WasmResult::Reply(b"I'm canister 1 on subnet 1".to_vec()))
    );
}

#[test]
fn test_routing_with_multiple_subnets() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let subnet_id_1 = pic.topology().get_nns().unwrap();
    let canister_id_1 = pic.create_canister_on_subnet(None, None, subnet_id_1);
    let subnet_id_2 = pic.topology().get_app_subnets()[0];
    let canister_id_2 = pic.create_canister_on_subnet(None, None, subnet_id_2);
    pic.add_cycles(canister_id_1, INIT_CYCLES);
    pic.add_cycles(canister_id_2, INIT_CYCLES);

    let counter_wasm = counter_wasm();
    pic.install_canister(canister_id_1, counter_wasm.clone(), vec![], None);
    pic.install_canister(canister_id_2, counter_wasm.clone(), vec![], None);

    // Call canister 1 on subnet 1.
    let reply = call_counter_can(&pic, canister_id_1, "read");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 0]));
    let reply = call_counter_can(&pic, canister_id_1, "write");
    assert_eq!(reply, WasmResult::Reply(vec![1, 0, 0, 0]));

    // Call canister 2 on subnet 2.
    let reply = call_counter_can(&pic, canister_id_2, "read");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 0]));
    let reply = call_counter_can(&pic, canister_id_2, "write");
    assert_eq!(reply, WasmResult::Reply(vec![1, 0, 0, 0]));

    // Creating a canister without specifying a subnet should still work.
    let _canister_id = pic.create_canister();
}

#[test]
fn test_multiple_large_xnet_payloads() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let nns_subnet = pic.topology().get_nns().unwrap();
    let app_subnet = pic.topology().get_app_subnets()[0];
    let canister_1 = pic.create_canister_on_subnet(None, None, nns_subnet);
    let canister_2 = pic.create_canister_on_subnet(None, None, app_subnet);
    pic.add_cycles(canister_1, INIT_CYCLES);
    pic.add_cycles(canister_2, INIT_CYCLES);

    pic.install_canister(canister_1, UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None);
    pic.install_canister(canister_2, UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None);

    for canister_a in [canister_1, canister_2] {
        for canister_b in [canister_1, canister_2] {
            for size in [2_000_000, 10_000_000] {
                let xnet_result = pic.update_call(
                    canister_a,
                    Principal::anonymous(),
                    "update",
                    wasm()
                        .inter_update(
                            canister_b,
                            CallArgs::default()
                                .eval_other_side(wasm().push_bytes_wasm_push_bytes_and_reply(size))
                                .on_reply(wasm().build())
                                .on_reject(wasm().build()),
                        )
                        .inter_update(
                            canister_b,
                            CallArgs::default()
                                .eval_other_side(wasm().push_bytes_wasm_push_bytes_and_reply(size))
                                .on_reply(wasm().build())
                                .on_reject(wasm().build()),
                        )
                        .inter_update(
                            canister_b,
                            CallArgs::default()
                                .eval_other_side(wasm().push_bytes_wasm_push_bytes_and_reply(size)),
                        )
                        .build(),
                );
                if canister_a == canister_b || size <= 2_000_000 {
                    // Self-calls with 10M and xnet-calls with up to 2M arguments work just fine.
                    let WasmResult::Reply(reply) = xnet_result.unwrap() else {
                        unreachable!()
                    };
                    // `push_bytes_wasm_push_bytes_and_reply` returns the length of the blob
                    // since the reply must be always at most 2M
                    assert_eq!(reply, size.to_le_bytes());
                } else {
                    let WasmResult::Reject(reject) = xnet_result.unwrap() else {
                        unreachable!()
                    };
                    // A xnet-call with 10M argument fails with CANISTER_ERROR reject code (5)
                    // proxied through the universal canister.
                    assert_eq!(reject.as_bytes(), 5_u32.to_le_bytes());
                }
            }
        }
    }
}

#[test]
fn test_get_and_set_and_advance_time() {
    let pic = PocketIc::new();
    pic.set_time(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890)
    );
    pic.advance_time(std::time::Duration::from_secs(420));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890 + 420)
    );
}

#[test]
fn test_get_set_cycle_balance() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let initial_balance = pic.cycle_balance(canister_id);
    let new_balance = pic.add_cycles(canister_id, 420);
    assert_eq!(new_balance, initial_balance + 420);
    let balance = pic.cycle_balance(canister_id);
    assert_eq!(balance, initial_balance + 420);
}

#[test]
fn test_create_and_drop_instances() {
    let pic = PocketIc::new();
    let id = pic.instance_id;
    assert_eq!(PocketIc::list_instances()[id], "Available".to_string());
    drop(pic);
    assert_eq!(PocketIc::list_instances()[id], "Deleted".to_string());
}

#[test]
fn test_tick() {
    let pic = PocketIc::new();
    pic.tick();
}

#[test]
fn test_root_key() {
    let pic = PocketIc::new();
    assert!(pic.root_key().is_none());

    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    assert!(pic.root_key().is_some());
}

#[test]
#[should_panic(expected = "SubnetConfigSet must contain at least one subnet")]
fn test_new_pocket_ic_without_subnets_panics() {
    let _pic: PocketIc = PocketIc::from_config(SubnetConfigSet::default());
}

#[test]
fn test_canister_exists() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    assert!(pic.canister_exists(canister_id));
    pic.stop_canister(canister_id, None).unwrap();
    pic.delete_canister(canister_id, None).unwrap();
    assert!(!pic.canister_exists(canister_id));

    let pic = PocketIc::new();
    assert!(!pic.canister_exists(canister_id));
}

#[test]
fn test_get_subnet_of_canister() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let nns_subnet = pic.topology().get_nns().unwrap();
    let app_subnet = pic.topology().get_app_subnets()[0];

    let canister_id = pic.create_canister_on_subnet(None, None, nns_subnet);
    let subnet_id = pic.get_subnet(canister_id);
    assert_eq!(subnet_id.unwrap(), nns_subnet);

    let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
    let subnet_id = pic.get_subnet(canister_id);
    assert_eq!(subnet_id.unwrap(), app_subnet);

    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let app_subnet = pic.topology().get_app_subnets()[0];
    let subnet_id = pic.get_subnet(canister_id).unwrap();
    assert_eq!(subnet_id, app_subnet);

    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.stop_canister(canister_id, None).unwrap();
    pic.delete_canister(canister_id, None).unwrap();
    let subnet_id = pic.get_subnet(canister_id);
    assert!(subnet_id.is_none());
}

#[test]
fn test_set_and_get_stable_memory_not_compressed() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    let counter_wasm = counter_wasm();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    let data = "deadbeef".as_bytes().to_vec();
    pic.set_stable_memory(canister_id, data.clone(), BlobCompression::NoCompression);

    let read_data = pic.get_stable_memory(canister_id);
    assert_eq!(data, read_data[..8]);
}

#[test]
fn test_set_and_get_stable_memory_compressed() {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = counter_wasm();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    let data = "decafbad".as_bytes().to_vec();
    let mut compressed_data = Vec::new();
    let mut gz = flate2::read::GzEncoder::new(&data[..], flate2::Compression::default());
    gz.read_to_end(&mut compressed_data).unwrap();

    pic.set_stable_memory(canister_id, compressed_data.clone(), BlobCompression::Gzip);

    let read_data = pic.get_stable_memory(canister_id);
    assert_eq!(data, read_data[..8]);
}
