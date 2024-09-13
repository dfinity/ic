use candid::{decode_one, encode_one, CandidType, Principal};
use ic_base_types::PrincipalId;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_cdk::api::management_canister::http_request::HttpResponse;
use ic_cdk::api::management_canister::main::{CanisterId, CanisterSettings};
use ic_universal_canister::{wasm, CallArgs, UNIVERSAL_CANISTER_WASM};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, BlockIndex, LedgerCanisterInitPayload, Memo, Name,
    Symbol, Tokens, TransferArgs, TransferError,
};
use pocket_ic::{
    common::rest::{
        BlobCompression, CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse,
        SubnetConfigSet, SubnetKind,
    },
    update_candid, PocketIc, PocketIcBuilder, WasmResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Read, time::SystemTime};

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
#[should_panic(
    expected = "The binary representation 04 of effective canister ID 2vxsx-fae should consist of 10 bytes."
)]
fn test_create_canister_with_not_contained_id_panics() {
    let pic = PocketIc::new();
    let _ = pic.create_canister_with_id(None, None, Principal::anonymous());
}

#[test]
#[should_panic(
    expected = "The effective canister ID rwlgt-iiaaa-aaaaa-aaaaa-cai belongs to the NNS or II subnet on the IC mainnet for which PocketIC provides a `SubnetKind`: please set up your PocketIC instance with a subnet of that `SubnetKind`."
)]
fn test_create_canister_with_special_mainnet_id_panics() {
    let pic = PocketIc::new();
    let _ = pic.create_canister_with_id(
        None,
        None,
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]),
    );
}

#[test]
#[should_panic(
    expected = "The effective canister ID nti35-np7aa-aaaaa-aaaaa-cai does not belong to an existing subnet and it is not a mainnet canister ID."
)]
fn test_create_canister_with_not_mainnet_id_panics() {
    let pic = PocketIc::new();
    let _ = pic.create_canister_with_id(
        None,
        None,
        Principal::from_slice(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]),
    );
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

fn xnet_calls(pic: &PocketIc, canister_1: Principal, canister_2: Principal) {
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
    let unix_time_secs = 1630328630;
    pic.set_time(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_time_secs));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_time_secs)
    );
    pic.advance_time(std::time::Duration::from_secs(420));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_time_secs + 420)
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
    let id = pic.instance_id();
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

#[test]
fn test_parallel_calls() {
    let wat = r#"
    (module
        (import "ic0" "time" (func $ic0_time (result i64)))
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $time
            (i64.store (i32.const 0) (call $ic0_time))
            (call $msg_reply_data_append (i32.const 0) (i32.const 8))
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_update time" (func $time))
    )
"#;

    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let time_wasm = wat::parse_str(wat).unwrap();
    pic.install_canister(canister_id, time_wasm, vec![], None);

    let msg_id1 = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "time",
            encode_one(()).unwrap(),
        )
        .unwrap();
    let msg_id2 = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "time",
            encode_one(()).unwrap(),
        )
        .unwrap();

    let time1 = pic.await_call(msg_id1).unwrap();
    let time2 = pic.await_call(msg_id2).unwrap();

    // times should be equal since the update calls are parallel
    // and should be executed in the same round
    assert_eq!(time1, time2);

    let time3 = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "time",
            encode_one(()).unwrap(),
        )
        .unwrap();

    // now times should not be equal since the last update call
    // was executed in a separate round and round times are strictly
    // monotone
    assert!(time1 != time3);
}

#[test]
fn test_inspect_message() {
    let wat = r#"
    (module
        (import "ic0" "accept_message" (func $accept_message))
        (import "ic0" "msg_reply" (func $msg_reply))
        (func $inspect
            (i32.load (i32.const 0))
            (if
              (then)
              (else
                (call $accept_message)
              )
            )
        )
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1)))
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_inspect_message" (func $inspect))
        (export "canister_update inc" (func $inc))
    )
"#;

    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let inspect_wasm = wat::parse_str(wat).unwrap();
    pic.install_canister(canister_id, inspect_wasm, vec![], None);

    // the first call succeeds because the inspect_message accepts for counter = 0
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "inc",
        encode_one(()).unwrap(),
    )
    .unwrap();

    // the second call fails because the first (successful) call incremented the counter
    // and the inspect_message does not accept for counter > 0
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "inc",
        encode_one(()).unwrap(),
    )
    .unwrap_err();
}

#[should_panic]
#[test]
fn test_too_large_call() {
    let pic = PocketIc::new();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = counter_wasm();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "inc",
        vec![42; 16_000_000],
    )
    .unwrap_err();
}

#[tokio::test]
async fn test_create_and_drop_instances_async() {
    let pic = pocket_ic::nonblocking::PocketIc::new().await;
    let id = pic.instance_id;
    assert_eq!(
        pocket_ic::nonblocking::PocketIc::list_instances().await[id],
        "Available".to_string()
    );
    pic.drop().await;
    assert_eq!(
        pocket_ic::nonblocking::PocketIc::list_instances().await[id],
        "Deleted".to_string()
    );
}

#[tokio::test]
async fn test_counter_canister_async() {
    let pic = pocket_ic::nonblocking::PocketIc::new().await;

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister().await;
    pic.add_cycles(can_id, INIT_CYCLES).await;

    // Install the counter canister wasm file on the canister.
    let counter_wasm = counter_wasm();
    pic.install_canister(can_id, counter_wasm, vec![], None)
        .await;

    // Make some calls to the canister.
    let reply = pic
        .update_call(
            can_id,
            Principal::anonymous(),
            "read",
            encode_one(()).unwrap(),
        )
        .await
        .expect("Failed to call counter canister");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 0]));

    // Drop the PocketIc instance.
    pic.drop().await;
}

// Canister code with a very large WASM.
fn very_large_wasm(n: usize) -> Vec<u8> {
    const WASM_PAGE_SIZE: usize = 1 << 16;
    let wat = format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $read
            (call $msg_reply_data_append (i32.const 0) (i32.const 4))
            (call $msg_reply))
        (memory $memory {})
        (export "canister_update read" (func $read))
        (data (i32.const 0) "{}")
    )
"#,
        n / WASM_PAGE_SIZE + 42,
        String::from_utf8(vec![b'X'; n]).unwrap()
    );
    wat::parse_str(wat).unwrap()
}

#[test]
fn install_very_large_wasm() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // Create a canister.
    let can_id = pic.create_canister();

    // Charge the canister with 2T cycles.
    pic.add_cycles(can_id, 100 * INIT_CYCLES);

    // Install the very large canister wasm on the canister.
    let wasm_module = very_large_wasm(5_000_000);
    assert!(wasm_module.len() >= 5_000_000);
    pic.install_canister(can_id, wasm_module, vec![], None);

    // Update call on the newly installed canister should succeed
    // and return 4 bytes of the large data section.
    let res = pic
        .update_call(can_id, Principal::anonymous(), "read", vec![])
        .unwrap();
    match res {
        WasmResult::Reply(data) => assert_eq!(data, vec![b'X'; 4]),
        _ => panic!("Unexpected update call response: {:?}", res),
    };
}

#[test]
fn test_uninstall_canister() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the counter canister wasm file on the canister.
    let counter_wasm = counter_wasm();
    pic.install_canister(can_id, counter_wasm, vec![], None);

    // The module hash should be set after the canister is installed.
    let status = pic.canister_status(can_id, None).unwrap();
    assert!(status.module_hash.is_some());

    // Uninstall the canister.
    pic.uninstall_canister(can_id, None).unwrap();

    // The module hash should be unset after the canister is uninstalled.
    let status = pic.canister_status(can_id, None).unwrap();
    assert!(status.module_hash.is_none());
}

#[test]
fn test_update_canister_settings() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 200T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, 100 * INIT_CYCLES);

    // The compute allocation of the canister should be zero.
    let status = pic.canister_status(can_id, None).unwrap();
    let zero: candid::Nat = 0_u64.into();
    assert_eq!(status.settings.compute_allocation, zero);

    // Set the compute allocation to 1.
    let new_compute_allocation: candid::Nat = 1_u64.into();
    let settings = CanisterSettings {
        compute_allocation: Some(new_compute_allocation.clone()),
        ..Default::default()
    };
    pic.update_canister_settings(can_id, None, settings)
        .unwrap();

    // Check that the compute allocation has been set.
    let status = pic.canister_status(can_id, None).unwrap();
    assert_eq!(status.settings.compute_allocation, new_compute_allocation);
}

#[test]
fn test_xnet_call_and_create_canister_with_specified_id() {
    // We start with a PocketIC instance consisting of two application subnets.
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    // We retrieve these two (distinct) subnet IDs from the topology.
    let subnet_id_1 = pic.topology().get_app_subnets()[0];
    let subnet_id_2 = pic.topology().get_app_subnets()[1];
    assert_ne!(subnet_id_1, subnet_id_2);

    // We create canisters on those two subnets.
    let canister_1 = pic.create_canister_on_subnet(None, None, subnet_id_1);
    assert_eq!(pic.get_subnet(canister_1), Some(subnet_id_1));
    let canister_2 = pic.create_canister_on_subnet(None, None, subnet_id_2);
    assert_eq!(pic.get_subnet(canister_2), Some(subnet_id_2));

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(specified_id).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_3 = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_3, specified_id);
    let subnet_id_3 = pic.get_subnet(specified_id).unwrap();
    assert_ne!(subnet_id_1, subnet_id_3);
    assert_ne!(subnet_id_2, subnet_id_3);

    // We also define a "specified" canister ID that corresponds to the Bitcoin mainnet canister,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let bitcoin_canister_id = Principal::from_text("ghsi2-tqaaa-aaaan-aaaca-cai").unwrap();
    assert!(pic.get_subnet(bitcoin_canister_id).is_none());
    assert!(pic.topology().get_bitcoin().is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_4 = pic
        .create_canister_with_id(None, None, bitcoin_canister_id)
        .unwrap();
    assert_eq!(canister_4, bitcoin_canister_id);
    let subnet_id_4 = pic.get_subnet(bitcoin_canister_id).unwrap();
    assert_eq!(pic.topology().get_bitcoin().unwrap(), subnet_id_4);
    assert_ne!(subnet_id_1, subnet_id_4);
    assert_ne!(subnet_id_2, subnet_id_4);
    assert_ne!(subnet_id_3, subnet_id_4);

    // We top up the canisters with cycles and install the universal canister WASM to them.
    for canister in [canister_1, canister_2, canister_3, canister_4] {
        pic.add_cycles(canister, INIT_CYCLES);
        pic.install_canister(canister, UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None);
    }

    // We test if xnet calls work between all pairs of canisters
    // (in particular, including the canisters on the new subnets).
    for canister_a in [canister_1, canister_2, canister_3, canister_4] {
        for canister_b in [canister_1, canister_2, canister_3, canister_4] {
            if canister_a != canister_b {
                xnet_calls(&pic, canister_a, canister_b);
            }
        }
    }
}

#[test]
fn test_query_call_on_new_pocket_ic() {
    let pic = PocketIc::new();

    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];
    let canister_id = Principal::from_slice(
        &topology.0.get(&app_subnet).unwrap().canister_ranges[0]
            .start
            .canister_id,
    );

    pic.query_call(canister_id, Principal::anonymous(), "foo", vec![])
        .unwrap_err();
}

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

#[derive(CandidType, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Deserialize, Debug)]
struct SchnorrPublicKeyResponse {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[test]
fn test_schnorr() {
    // We create a PocketIC instance consisting of the NNS, II, and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // this subnet has ECDSA keys
        .with_application_subnet()
        .build();

    // We retrieve the app subnet ID from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    let canister = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister), Some(app_subnet));

    // We top up the canister with cycles and install the test canister WASM to them.
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    // We define the message, derivation path, and ECDSA key ID to use in this test.
    let message = b"Hello, world!==================="; // must be of length 32 bytes for BIP340
    let derivation_path = vec!["my message".as_bytes().to_vec()];
    for algorithm in [SchnorrAlgorithm::Bip340Secp256k1, SchnorrAlgorithm::Ed25519] {
        for name in ["key_1", "test_key_1", "dfx_test_key1"] {
            let key_id = SchnorrKeyId {
                algorithm,
                name: name.to_string(),
            };

            // We get the Schnorr public key and signature via update calls to the test canister.
            let schnorr_public_key = update_candid::<
                (Option<Principal>, _, _),
                (Result<SchnorrPublicKeyResponse, String>,),
            >(
                &pic,
                canister,
                "schnorr_public_key",
                (None, derivation_path.clone(), key_id.clone()),
            )
            .unwrap()
            .0
            .unwrap();
            let schnorr_signature = update_candid::<_, (Result<Vec<u8>, String>,)>(
                &pic,
                canister,
                "sign_with_schnorr",
                (message, derivation_path.clone(), key_id.clone()),
            )
            .unwrap()
            .0
            .unwrap();

            // We verify the Schnorr signature.
            match key_id.algorithm {
                SchnorrAlgorithm::Bip340Secp256k1 => {
                    use k256::ecdsa::signature::hazmat::PrehashVerifier;
                    use k256::schnorr::{Signature, VerifyingKey};
                    let vk = VerifyingKey::from_bytes(&schnorr_public_key.public_key[1..]).unwrap();
                    let sig = Signature::try_from(schnorr_signature.as_slice()).unwrap();
                    vk.verify_prehash(message, &sig).unwrap();
                }
                SchnorrAlgorithm::Ed25519 => {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    let pk: [u8; 32] = schnorr_public_key.public_key.try_into().unwrap();
                    let vk = VerifyingKey::from_bytes(&pk).unwrap();
                    let signature = Signature::from_slice(&schnorr_signature).unwrap();
                    vk.verify(message, &signature).unwrap();
                }
            };
        }
    }
}

#[test]
fn test_ecdsa() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    // We create a PocketIC instance consisting of the NNS, II, and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // this subnet has ECDSA keys
        .with_application_subnet()
        .build();

    // We retrieve the app subnet ID from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    let canister = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister), Some(app_subnet));

    // We top up the canister with cycles and install the test canister WASM to them.
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    // We define the message, derivation path, and ECDSA key ID to use in this test.
    let message = "Hello, world!".to_string();
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: Vec<u8> = hasher.finalize().to_vec();
    let derivation_path = vec!["my message".as_bytes().to_vec()];

    for key_id in ["key_1", "test_key_1", "dfx_test_key1"] {
        let key_id = key_id.to_string();

        // We get the ECDSA public key and signature via update calls to the test canister.
        let ecsda_public_key = update_candid::<
            (Option<Principal>, Vec<Vec<u8>>, String),
            (Result<EcdsaPublicKeyResponse, String>,),
        >(
            &pic,
            canister,
            "ecdsa_public_key",
            (None, derivation_path.clone(), key_id.clone()),
        )
        .unwrap()
        .0
        .unwrap();
        let ecdsa_signature =
            update_candid::<(Vec<u8>, Vec<Vec<u8>>, String), (Result<Vec<u8>, String>,)>(
                &pic,
                canister,
                "sign_with_ecdsa",
                (message_hash.clone(), derivation_path.clone(), key_id),
            )
            .unwrap()
            .0
            .unwrap();

        // We verify the ECDSA signature.
        let pk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&ecsda_public_key.public_key).unwrap();
        let sig = k256::ecdsa::Signature::try_from(ecdsa_signature.as_slice()).unwrap();
        pk.verify_prehash(&message_hash, &sig).unwrap();
    }
}

#[test]
fn test_ecdsa_disabled() {
    // We create a PocketIC instance consisting of the NNS and one application subnet.
    // With no II subnet, there's no subnet with ECDSA keys.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // We retrieve the app subnet ID from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    let canister = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister), Some(app_subnet));

    // We top up the canister with cycles and install the test canister WASM to them.
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    // We define the message, derivation path, and ECDSA key ID to use in this test.
    let message = "Hello, world!".to_string();
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: Vec<u8> = hasher.finalize().to_vec();
    let derivation_path = vec!["my message".as_bytes().to_vec()];
    let key_id = "dfx_test_key1".to_string();

    // We attempt to get the ECDSA public key and signature via update calls to the test canister.
    let ecsda_public_key_error = update_candid::<
        (Option<Principal>, Vec<Vec<u8>>, String),
        (Result<EcdsaPublicKeyResponse, String>,),
    >(
        &pic,
        canister,
        "ecdsa_public_key",
        (None, derivation_path.clone(), key_id.clone()),
    )
    .unwrap()
    .0
    .unwrap_err();
    assert!(ecsda_public_key_error.contains(
        "Requested unknown threshold key: ecdsa:Secp256k1:dfx_test_key1, existing keys: []"
    ));

    let ecdsa_signature_err =
        update_candid::<(Vec<u8>, Vec<Vec<u8>>, String), (Result<Vec<u8>, String>,)>(
            &pic,
            canister,
            "sign_with_ecdsa",
            (message_hash.clone(), derivation_path, key_id),
        )
        .unwrap()
        .0
        .unwrap_err();
    assert!(ecdsa_signature_err.contains("Requested unknown or signing disabled threshold key: ecdsa:Secp256k1:dfx_test_key1, existing keys with signing enabled: []"));
}

#[test]
fn test_canister_http() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(can_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            can_id,
            Principal::anonymous(),
            "canister_http",
            encode_one(()).unwrap(),
        )
        .unwrap();

    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 1);
    let canister_http_request = &canister_http_requests[0];

    let body = b"hello".to_vec();
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        }),
        additional_responses: vec![],
    };
    pic.mock_canister_http_response(mock_canister_http_response);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    match reply {
        WasmResult::Reply(data) => {
            let http_response: Result<HttpResponse, (RejectionCode, String)> =
                decode_one(&data).unwrap();
            assert_eq!(http_response.unwrap().body, body);
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
    };

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);
}

#[test]
fn test_canister_http_with_transform() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(can_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // with a transform function (clearing http response headers and setting
    // the response body equal to the transform context fixed in the test canister)
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            can_id,
            Principal::anonymous(),
            "canister_http_with_transform",
            encode_one(()).unwrap(),
        )
        .unwrap();
    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 1);
    let canister_http_request = &canister_http_requests[0];

    let body = b"hello".to_vec();
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        }),
        additional_responses: vec![],
    };
    pic.mock_canister_http_response(mock_canister_http_response);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    match reply {
        WasmResult::Reply(data) => {
            let http_response: HttpResponse = decode_one(&data).unwrap();
            // http response headers are cleared by the transform function
            assert!(http_response.headers.is_empty());
            // mocked non-empty response body is transformed to the transform context
            // by the transform function
            assert_eq!(http_response.body, b"this is my transform context".to_vec());
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
    };

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);
}

#[test]
fn test_canister_http_with_diverging_responses() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(can_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock diverging canister http outcall responses.
    let call_id = pic
        .submit_call(
            can_id,
            Principal::anonymous(),
            "canister_http",
            encode_one(()).unwrap(),
        )
        .unwrap();

    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 1);
    let canister_http_request = &canister_http_requests[0];

    let response = |i: u64| {
        CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: format!("hello{}", i / 2).as_bytes().to_vec(),
        })
    };
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: response(0),
        additional_responses: (1..13).map(response).collect(),
    };
    pic.mock_canister_http_response(mock_canister_http_response);

    // Now the test canister will receive an error
    // and reply to the ingress message from the test driver
    // relaying the error.
    let reply = pic.await_call(call_id).unwrap();
    match reply {
        WasmResult::Reply(data) => {
            let http_response: Result<HttpResponse, (RejectionCode, String)> =
                decode_one(&data).unwrap();
            let (reject_code, err) = http_response.unwrap_err();
            assert_eq!(reject_code, RejectionCode::SysTransient);
            let expected = "No consensus could be reached. Replicas had different responses. Details: request_id: 0, timeout: 1620328930000000005, hashes: [98387cc077af9cff2ef439132854e91cb074035bb76e2afb266960d8e3beaf11: 2], [6a2fa8e54fb4bbe62cde29f7531223d9fcf52c21c03500c1060a5f893ed32d2e: 2], [3e9ec98abf56ef680bebb14309858ede38f6fde771cd4c04cda8f066dc2810db: 2], [2c14e77f18cd990676ae6ce0d7eb89c0af9e1a66e17294b5f0efa68422bba4cb: 2], [2843e4133f673571ff919808d3ca542cc54aaf288c702944e291f0e4fafffc69: 2], [1c4ad84926c36f1fbc634a0dc0535709706f7c48f0c6ebd814fe514022b90671: 2], [7bf80e2f02011ab0a7836b526546e75203b94e856d767c9df4cb0c19baf34059: 1]";
            assert_eq!(err, expected);
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
    };

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);
}

#[test]
#[should_panic(expected = "InvalidMockCanisterHttpResponses((2, 13))")]
fn test_canister_http_with_one_additional_response() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(can_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock diverging canister http outcall responses.
    pic.submit_call(
        can_id,
        Principal::anonymous(),
        "canister_http",
        encode_one(()).unwrap(),
    )
    .unwrap();

    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 1);
    let canister_http_request = &canister_http_requests[0];

    let body = b"hello".to_vec();
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        }),
        additional_responses: vec![CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        })],
    };
    pic.mock_canister_http_response(mock_canister_http_response);
}
