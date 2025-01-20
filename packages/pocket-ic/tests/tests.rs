use candid::{decode_one, encode_one, CandidType, Decode, Deserialize, Encode, Principal};
use ic_certification::Label;
use ic_transport_types::Envelope;
use ic_transport_types::EnvelopeContent::ReadState;
use pocket_ic::management_canister::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettings, EcdsaPublicKeyResult,
    HttpRequestResult, ProvisionalCreateCanisterWithCyclesArgs, SchnorrAlgorithm,
    SchnorrPublicKeyArgsKeyId, SchnorrPublicKeyResult, SignWithBip341Aux, SignWithSchnorrAux,
};
use pocket_ic::{
    common::rest::{
        BlobCompression, CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse,
        RawEffectivePrincipal, SubnetKind,
    },
    query_candid, update_candid, DefaultEffectiveCanisterIdError, ErrorCode, IngressStatusResult,
    PocketIc, PocketIcBuilder, RejectCode,
};
#[cfg(unix)]
use reqwest::blocking::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io::Read, time::SystemTime};

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

#[derive(CandidType, Deserialize, Debug)]
enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

// Create a counter canister and charge it with 2T cycles.
fn deploy_counter_canister(pic: &PocketIc) -> Principal {
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, counter_wasm(), vec![], None);
    canister_id
}

// Call a method on the counter canister as the anonymous principal.
fn call_counter_canister(pic: &PocketIc, canister_id: Principal, method: &str) -> Vec<u8> {
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        method,
        encode_one(()).unwrap(),
    )
    .expect("Failed to call counter canister")
}

#[test]
fn test_counter_canister() {
    let pic = PocketIc::new();
    let canister_id = deploy_counter_canister(&pic);

    // Make some calls to the counter canister.
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, vec![0, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, vec![1, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, vec![2, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, vec![2, 0, 0, 0]);
}

fn counter_wasm() -> Vec<u8> {
    const COUNTER_WAT: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
        (func $write
            (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
            (call $read))
        (func $read
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_query read" (func $read))
        (export "canister_update write" (func $write))
    )"#;
    wat::parse_str(COUNTER_WAT).unwrap()
}

#[test]
fn test_create_canister_with_id() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .build();
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
    pic.install_canister(app_canister_id, test_canister_wasm(), vec![], None);
    let new_app_cycles = pic.cycle_balance(app_canister_id);
    let app_cycles_delta = old_app_cycles - new_app_cycles;

    let old_fidu_cycles = pic.cycle_balance(fidu_canister_id);
    pic.install_canister(fidu_canister_id, test_canister_wasm(), vec![], None);
    let new_fidu_cycles = pic.cycle_balance(fidu_canister_id);
    let fidu_cycles_delta = old_fidu_cycles - new_fidu_cycles;

    // the fiduciary subnet has 28 nodes which is more than twice
    // the number of nodes on an application subnet (13)
    assert!(fidu_cycles_delta > 2 * app_cycles_delta);
}

#[test]
fn test_canister_creation_subnet_selection() {
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
    let subnet_kind = pic
        .topology()
        .subnet_configs
        .get(&subnet_id)
        .unwrap()
        .subnet_kind;
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
    let subnet_kind = pic
        .topology()
        .subnet_configs
        .get(&subnet_id)
        .unwrap()
        .subnet_kind;
    assert_eq!(subnet_kind, SubnetKind::System);
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
    pic.install_canister(canister_id_1, counter_wasm(), vec![], None);
    pic.install_canister(canister_id_2, counter_wasm(), vec![], None);

    // Call canister 1 on subnet 1.
    let reply = call_counter_canister(&pic, canister_id_1, "read");
    assert_eq!(reply, vec![0, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id_1, "write");
    assert_eq!(reply, vec![1, 0, 0, 0]);

    // Call canister 2 on subnet 2.
    let reply = call_counter_canister(&pic, canister_id_2, "read");
    assert_eq!(reply, vec![0, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id_2, "write");
    assert_eq!(reply, vec![1, 0, 0, 0]);

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

    pic.install_canister(canister_1, test_canister_wasm(), vec![], None);
    pic.install_canister(canister_2, test_canister_wasm(), vec![], None);

    for canister_a in [canister_1, canister_2] {
        for canister_b in [canister_1, canister_2] {
            for size in [2_000_000, 10_000_000] {
                let xnet_result = pic.update_call(
                    canister_a,
                    Principal::anonymous(),
                    "call_with_large_blob",
                    Encode!(&canister_b, &size).unwrap(),
                );
                if canister_a == canister_b || size <= 2_000_000 {
                    // Self-calls with 10M and xnet-calls with up to 2M arguments work just fine
                    // and return the length of the blob sent in the inter-canister call.
                    match xnet_result {
                        Ok(reply) => {
                            let blob_len = Decode!(&reply, usize).unwrap();
                            assert_eq!(blob_len, size);
                        }
                        _ => panic!("Unexpected update call result: {:?}", xnet_result),
                    };
                } else {
                    // An inter-canister call to a different subnet with 10M argument traps.
                    match xnet_result {
                        Err(reject_response) => {
                            assert_eq!(reject_response.error_code, ErrorCode::CanisterCalledTrap);
                        }
                        _ => panic!("Unexpected update call result: {:?}", xnet_result),
                    };
                }
            }
        }
    }
}

#[test]
fn test_get_and_set_and_advance_time() {
    let pic = PocketIc::new();

    let unix_time_secs = 1630328630;
    let set_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_time_secs);
    pic.set_time(set_time);
    assert_eq!(pic.get_time(), set_time);
    pic.tick();
    assert_eq!(pic.get_time(), set_time);

    pic.advance_time(std::time::Duration::from_secs(420));
    assert_eq!(
        pic.get_time(),
        set_time + std::time::Duration::from_secs(420)
    );
    pic.tick();
    assert_eq!(
        pic.get_time(),
        set_time + std::time::Duration::from_secs(420)
    );
}

#[test]
#[should_panic(expected = "SettingTimeIntoPast")]
fn set_time_into_past() {
    let pic = PocketIc::new();

    let now = SystemTime::now();
    pic.set_time(now + std::time::Duration::from_secs(1));

    pic.set_time(now);
}

fn query_and_check_time(pic: &PocketIc, test_canister: Principal) {
    let current_time = pic
        .get_time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let t: (u64,) = query_candid(pic, test_canister, "time", ((),)).unwrap();
    assert_eq!(
        pic.get_time()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        current_time
    );
    assert_eq!(current_time, t.0 as u128);
}

#[test]
fn query_call_after_advance_time() {
    let pic = PocketIc::new();

    // We create a test canister.
    let canister = pic.create_canister();
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    query_and_check_time(&pic, canister);

    pic.advance_time(std::time::Duration::from_secs(420));
    pic.tick();

    query_and_check_time(&pic, canister);

    pic.advance_time(std::time::Duration::from_secs(0));
    pic.tick();

    query_and_check_time(&pic, canister);
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
    let _pic: PocketIc = PocketIcBuilder::new().build();
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
    let canister_id = deploy_counter_canister(&pic);

    let data = "deadbeef".as_bytes().to_vec();
    pic.set_stable_memory(canister_id, data.clone(), BlobCompression::NoCompression);

    let read_data = pic.get_stable_memory(canister_id);
    assert_eq!(data, read_data[..8]);
}

#[test]
fn test_set_and_get_stable_memory_compressed() {
    let pic = PocketIc::new();
    let canister_id = deploy_counter_canister(&pic);

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
    let canister_id = deploy_counter_canister(&pic);

    const MAX_INGRESS_MESSAGE_ARG_SIZE: usize = 2097152;
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "inc",
        vec![42; MAX_INGRESS_MESSAGE_ARG_SIZE + 1],
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

    // Create a counter canister and charge it with 2T cycles.
    let canister_id = pic.create_canister().await;
    pic.add_cycles(canister_id, INIT_CYCLES).await;
    pic.install_canister(canister_id, counter_wasm(), vec![], None)
        .await;

    // Make some calls to the canister.
    let reply = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "read",
            encode_one(()).unwrap(),
        )
        .await
        .expect("Failed to call counter canister");
    assert_eq!(reply, vec![0, 0, 0, 0]);

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
    let canister_id = pic.create_canister();

    // Charge the canister with 2T cycles.
    pic.add_cycles(canister_id, 100 * INIT_CYCLES);

    // Install the very large canister wasm on the canister.
    let wasm_module = very_large_wasm(5_000_000);
    assert!(wasm_module.len() >= 5_000_000);
    pic.install_canister(canister_id, wasm_module, vec![], None);

    // Update call on the newly installed canister should succeed
    // and return 4 bytes of the large data section.
    let res = pic
        .update_call(canister_id, Principal::anonymous(), "read", vec![])
        .unwrap();
    assert_eq!(res, vec![b'X'; 4]);
}

#[test]
fn test_uninstall_canister() {
    let pic = PocketIc::new();
    let canister_id = deploy_counter_canister(&pic);

    // The module hash should be set after the canister is installed.
    let status = pic.canister_status(canister_id, None).unwrap();
    assert!(status.module_hash.is_some());

    // Uninstall the canister.
    pic.uninstall_canister(canister_id, None).unwrap();

    // The module hash should be unset after the canister is uninstalled.
    let status = pic.canister_status(canister_id, None).unwrap();
    assert!(status.module_hash.is_none());
}

#[test]
fn test_update_canister_settings() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 200T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * INIT_CYCLES);

    // The compute allocation of the canister should be zero.
    let status = pic.canister_status(canister_id, None).unwrap();
    let zero: candid::Nat = 0_u64.into();
    assert_eq!(status.settings.compute_allocation, zero);

    // Set the compute allocation to 1.
    let new_compute_allocation: candid::Nat = 1_u64.into();
    let settings = CanisterSettings {
        compute_allocation: Some(new_compute_allocation.clone()),
        ..Default::default()
    };
    pic.update_canister_settings(canister_id, None, settings)
        .unwrap();

    // Check that the compute allocation has been set.
    let status = pic.canister_status(canister_id, None).unwrap();
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

    // We top up the canisters with cycles and install the test canister WASM to them.
    for canister in [canister_1, canister_2, canister_3, canister_4] {
        pic.add_cycles(canister, INIT_CYCLES);
        pic.install_canister(canister, test_canister_wasm(), vec![], None);
    }

    // We test if xnet calls work between all pairs of canisters
    // (in particular, including the canisters on the new subnets).
    for canister_a in [canister_1, canister_2, canister_3, canister_4] {
        for canister_b in [canister_1, canister_2, canister_3, canister_4] {
            if canister_a != canister_b {
                let xnet_result = pic.update_call(
                    canister_a,
                    Principal::anonymous(),
                    "whois",
                    Encode!(&canister_b).unwrap(),
                );
                match xnet_result {
                    Ok(reply) => {
                        let identity = Decode!(&reply, String).unwrap();
                        assert_eq!(identity, canister_b.to_string());
                    }
                    _ => panic!("Unexpected update call result: {:?}", xnet_result),
                };
            }
        }
    }
}

#[test]
fn test_query_call_on_new_pocket_ic() {
    let pic = PocketIc::new();

    let topology = pic.topology();
    let canister_id: Principal = topology.default_effective_canister_id.into();

    pic.query_call(canister_id, Principal::anonymous(), "foo", vec![])
        .unwrap_err();
}

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
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
    let some_aux: Option<SignWithSchnorrAux> =
        Some(SignWithSchnorrAux::Bip341(SignWithBip341Aux {
            merkle_root_hash: b"Hello, aux!=====================".to_vec(),
        }));
    for algorithm in [SchnorrAlgorithm::Bip340Secp256K1, SchnorrAlgorithm::Ed25519] {
        for name in ["key_1", "test_key_1", "dfx_test_key"] {
            for aux in [None, some_aux.clone()] {
                let key_id = SchnorrPublicKeyArgsKeyId {
                    algorithm: algorithm.clone(),
                    name: name.to_string(),
                };

                // We get the Schnorr public key and signature via update calls to the test canister.
                let schnorr_public_key = update_candid::<
                    (Option<Principal>, _, _),
                    (Result<SchnorrPublicKeyResult, String>,),
                >(
                    &pic,
                    canister,
                    "schnorr_public_key",
                    (None, derivation_path.clone(), key_id.clone()),
                )
                .unwrap()
                .0
                .unwrap();
                let schnorr_signature_result = update_candid::<_, (Result<Vec<u8>, String>,)>(
                    &pic,
                    canister,
                    "sign_with_schnorr",
                    (
                        message,
                        derivation_path.clone(),
                        key_id.clone(),
                        aux.clone(),
                    ),
                )
                .unwrap()
                .0;

                // We verify the Schnorr signature.
                match key_id.algorithm {
                    SchnorrAlgorithm::Bip340Secp256K1 => {
                        use k256::ecdsa::signature::hazmat::PrehashVerifier;
                        use k256::schnorr::{Signature, VerifyingKey};
                        let bip340_public_key = schnorr_public_key.public_key[1..].to_vec();
                        let public_key = match aux {
                            None => bip340_public_key,
                            Some(SignWithSchnorrAux::Bip341(bip341_aux)) => {
                                use bitcoin::hashes::Hash;
                                use bitcoin::schnorr::TapTweak;
                                let xonly = bitcoin::util::key::XOnlyPublicKey::from_slice(
                                    bip340_public_key.as_slice(),
                                )
                                .unwrap();
                                let merkle_root =
                                    bitcoin::util::taproot::TapBranchHash::from_slice(
                                        &bip341_aux.merkle_root_hash,
                                    )
                                    .unwrap();
                                let secp256k1_engine = bitcoin::secp256k1::Secp256k1::new();
                                xonly
                                    .tap_tweak(&secp256k1_engine, Some(merkle_root))
                                    .0
                                    .to_inner()
                                    .serialize()
                                    .to_vec()
                            }
                        };
                        let vk = VerifyingKey::from_bytes(&public_key).unwrap();
                        let sig = Signature::try_from(schnorr_signature_result.unwrap().as_slice())
                            .unwrap();

                        vk.verify_prehash(message, &sig).unwrap();
                    }
                    SchnorrAlgorithm::Ed25519 => {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        let pk: [u8; 32] = schnorr_public_key.public_key.try_into().unwrap();
                        let vk = VerifyingKey::from_bytes(&pk).unwrap();
                        let verification_result = schnorr_signature_result.map(|signature| {
                            let s = Signature::from_slice(&signature).unwrap();
                            vk.verify(message, &s).unwrap();
                        });
                        assert!(
                            verification_result.is_ok() == aux.is_none(),
                            "{:?}",
                            verification_result
                        );
                    }
                };
            }
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

    for key_id in ["key_1", "test_key_1", "dfx_test_key"] {
        let key_id = key_id.to_string();

        // We get the ECDSA public key and signature via update calls to the test canister.
        let ecsda_public_key = update_candid::<
            (Option<Principal>, Vec<Vec<u8>>, String),
            (Result<EcdsaPublicKeyResult, String>,),
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
    let key_id = "dfx_test_key".to_string();

    // We attempt to get the ECDSA public key and signature via update calls to the test canister.
    let ecsda_public_key_error = update_candid::<
        (Option<Principal>, Vec<Vec<u8>>, String),
        (Result<EcdsaPublicKeyResult, String>,),
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
        "Requested unknown threshold key: ecdsa:Secp256k1:dfx_test_key, existing keys: []"
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
    assert!(ecdsa_signature_err.contains("Requested unknown or disabled threshold key: ecdsa:Secp256k1:dfx_test_key, existing enabled keys: []"));
}

#[test]
fn test_canister_http() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            canister_id,
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

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    assert_eq!(http_response.unwrap().body, body);
}

#[test]
fn test_canister_http_with_transform() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // with a transform function (clearing http response headers and setting
    // the response body equal to the transform context fixed in the test canister)
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            canister_id,
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

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: HttpRequestResult = decode_one(&reply).unwrap();
    // http response headers are cleared by the transform function
    assert!(http_response.headers.is_empty());
    // mocked non-empty response body is transformed to the transform context
    // by the transform function
    assert_eq!(http_response.body, b"this is my transform context".to_vec());
}

#[test]
fn test_canister_http_with_diverging_responses() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock diverging canister http outcall responses.
    let call_id = pic
        .submit_call(
            canister_id,
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

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);

    // Now the test canister will receive an error
    // and reply to the ingress message from the test driver
    // relaying the error.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    let (reject_code, err) = http_response.unwrap_err();
    assert!(matches!(reject_code, RejectionCode::SysTransient));
    let expected = "No consensus could be reached. Replicas had different responses. Details: request_id: 0, timeout: 1620328930000000005, hashes: [98387cc077af9cff2ef439132854e91cb074035bb76e2afb266960d8e3beaf11: 2], [6a2fa8e54fb4bbe62cde29f7531223d9fcf52c21c03500c1060a5f893ed32d2e: 2], [3e9ec98abf56ef680bebb14309858ede38f6fde771cd4c04cda8f066dc2810db: 2], [2c14e77f18cd990676ae6ce0d7eb89c0af9e1a66e17294b5f0efa68422bba4cb: 2], [2843e4133f673571ff919808d3ca542cc54aaf288c702944e291f0e4fafffc69: 2], [1c4ad84926c36f1fbc634a0dc0535709706f7c48f0c6ebd814fe514022b90671: 2], [7bf80e2f02011ab0a7836b526546e75203b94e856d767c9df4cb0c19baf34059: 1]";
    assert_eq!(err, expected);
}

#[test]
#[should_panic(expected = "InvalidMockCanisterHttpResponses((2, 13))")]
fn test_canister_http_with_one_additional_response() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock diverging canister http outcall responses.
    pic.submit_call(
        canister_id,
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

#[test]
fn test_canister_http_timeout() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            canister_id,
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

    // Advance time so that the canister http outcall times out.
    pic.advance_time(std::time::Duration::from_secs(180));
    pic.tick();

    // The canister http outcall should time out by now.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    let (reject_code, err) = http_response.unwrap_err();
    match reject_code {
        RejectionCode::SysTransient => (),
        _ => panic!("Unexpected reject code {:?}", reject_code),
    };
    assert_eq!(err, "Canister http request timed out");
}

#[test]
fn subnet_metrics() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    assert!(pic
        .get_subnet_metrics(Principal::management_canister())
        .is_none());

    deploy_counter_canister(&pic);

    let metrics = pic.get_subnet_metrics(app_subnet).unwrap();
    assert_eq!(metrics.num_canisters, 1);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));

    let canister_id = deploy_counter_canister(&pic);

    let metrics = pic.get_subnet_metrics(app_subnet).unwrap();
    assert_eq!(metrics.num_canisters, 2);
    assert!((1 << 17) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 18));

    pic.uninstall_canister(canister_id, None).unwrap();
    pic.stop_canister(canister_id, None).unwrap();

    let metrics = pic.get_subnet_metrics(app_subnet).unwrap();
    assert_eq!(metrics.num_canisters, 2);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));

    pic.delete_canister(canister_id, None).unwrap();

    let metrics = pic.get_subnet_metrics(app_subnet).unwrap();
    assert_eq!(metrics.num_canisters, 1);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));
}

#[cfg(unix)]
#[test]
fn test_raw_gateway() {
    // We create a PocketIC instance consisting of the NNS and one application subnet.
    let mut pic = PocketIcBuilder::new()
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

    // We start the HTTP gateway
    let endpoint = pic.make_live(None);

    // We make two requests: the non-raw request fails because the test canister does not certify its response,
    // the raw request succeeds.
    let client = Client::new();
    let gateway_host = endpoint.host().unwrap();
    for (host, expected) in [
        (
            format!("{}.{}", canister, gateway_host),
            "Response verification failed: Certification values not found",
        ),
        (
            format!("{}.raw.{}", canister, gateway_host),
            "My sample asset.",
        ),
    ] {
        let mut url = endpoint.clone();
        url.set_host(Some(&host)).unwrap();
        url.set_path("/asset.txt");
        let res = client.get(url).send().unwrap();
        let page = String::from_utf8(res.bytes().unwrap().to_vec()).unwrap();
        assert!(page.contains(expected));
    }
}

fn create_canister_with_effective_canister_id(
    pic: &PocketIc,
    effective_canister_id: Principal,
) -> Principal {
    let CanisterIdRecord { canister_id } = pocket_ic::call_candid_as(
        pic,
        Principal::management_canister(),
        RawEffectivePrincipal::CanisterId(effective_canister_id.as_slice().to_vec()),
        Principal::anonymous(),
        "provisional_create_canister_with_cycles",
        (ProvisionalCreateCanisterWithCyclesArgs {
            settings: None,
            specified_id: None,
            amount: None,
            sender_canister_version: None,
        },),
    )
    .map(|(x,)| x)
    .unwrap();
    canister_id
}

async fn create_canister_with_effective_canister_id_nonblocking(
    pic: &pocket_ic::nonblocking::PocketIc,
    effective_canister_id: Principal,
) -> Principal {
    let CanisterIdRecord { canister_id } = pocket_ic::nonblocking::call_candid_as(
        pic,
        Principal::management_canister(),
        RawEffectivePrincipal::CanisterId(effective_canister_id.as_slice().to_vec()),
        Principal::anonymous(),
        "provisional_create_canister_with_cycles",
        (ProvisionalCreateCanisterWithCyclesArgs {
            settings: None,
            specified_id: None,
            amount: None,
            sender_canister_version: None,
        },),
    )
    .await
    .map(|(x,)| x)
    .unwrap();
    canister_id
}

#[test]
fn test_get_default_effective_canister_id() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway_url = pic.make_live(None);

    let default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    let canister_id =
        create_canister_with_effective_canister_id(&pic, default_effective_canister_id);
    assert_eq!(canister_id, default_effective_canister_id);

    let subnet_id = pic.get_subnet(canister_id).unwrap();
    assert!(pic.topology().get_app_subnets().contains(&subnet_id));
}

#[tokio::test]
async fn test_get_default_effective_canister_id_nonblocking() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let gateway_url = pic.make_live(None).await;

    let default_effective_canister_id =
        pocket_ic::nonblocking::get_default_effective_canister_id(gateway_url.to_string())
            .await
            .unwrap();

    let canister_id =
        create_canister_with_effective_canister_id_nonblocking(&pic, default_effective_canister_id)
            .await;
    assert_eq!(canister_id, default_effective_canister_id);

    let subnet_id = pic.get_subnet(canister_id).await.unwrap();
    assert!(pic.topology().await.get_app_subnets().contains(&subnet_id));
}

#[test]
fn test_get_default_effective_canister_id_system_subnet() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_system_subnet()
        .build();
    let gateway_url = pic.make_live(None);

    let initial_default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    let canister_id =
        create_canister_with_effective_canister_id(&pic, initial_default_effective_canister_id);
    assert_eq!(canister_id, initial_default_effective_canister_id);

    let subnet_id = pic.get_subnet(canister_id).unwrap();
    assert!(pic.topology().get_system_subnets().contains(&subnet_id));

    assert_eq!(pic.topology().get_app_subnets().len(), 0);

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(specified_id).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_id, specified_id);

    assert_eq!(pic.topology().get_app_subnets().len(), 1);

    let default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    assert_eq!(
        default_effective_canister_id,
        initial_default_effective_canister_id
    );
}

#[test]
fn test_get_default_effective_canister_id_subnet_precedence() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_system_subnet()
        .build();
    let gateway_url = pic.make_live(None);

    let default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    let canister_id =
        create_canister_with_effective_canister_id(&pic, default_effective_canister_id);
    assert_eq!(canister_id, default_effective_canister_id);

    let subnet_id = pic.get_subnet(canister_id).unwrap();
    assert!(pic.topology().get_app_subnets().contains(&subnet_id));
}

#[test]
fn test_get_default_effective_canister_id_specified_id() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway_url = pic.make_live(None);

    let initial_default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    assert_eq!(pic.topology().get_app_subnets().len(), 1);

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(specified_id).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_id, specified_id);

    assert_eq!(pic.topology().get_app_subnets().len(), 2);

    let default_effective_canister_id =
        pocket_ic::get_default_effective_canister_id(gateway_url.to_string()).unwrap();

    assert_eq!(
        default_effective_canister_id,
        initial_default_effective_canister_id
    );
}

#[test]
fn test_get_default_effective_canister_id_invalid_url() {
    let _pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let test_driver_pid = std::process::id();
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", test_driver_pid));
    let port = std::fs::read_to_string(port_file_path).unwrap();

    let server_url = format!("http://localhost:{}", port);
    match pocket_ic::get_default_effective_canister_id(server_url).unwrap_err() {
        DefaultEffectiveCanisterIdError::ReqwestError(_) => (),
        err => panic!("Unexpected error: {}", err),
    };
}

#[test]
fn get_controllers() {
    let pic = PocketIc::new();

    let canister_id = pic.create_canister();

    let controllers = pic.get_controllers(canister_id);
    assert_eq!(controllers, vec![Principal::anonymous()]);

    let user_id = Principal::from_slice(&[u8::MAX; 29]);
    pic.set_controllers(canister_id, None, vec![Principal::anonymous(), user_id])
        .unwrap();

    let controllers = pic.get_controllers(canister_id);
    assert_eq!(controllers.len(), 2);
    assert!(controllers.contains(&Principal::anonymous()));
    assert!(controllers.contains(&user_id));
}

#[test]
#[should_panic(expected = "CanisterNotFound(CanisterId")]
fn get_controllers_of_nonexisting_canister() {
    let pic = PocketIc::new();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.stop_canister(canister_id, None).unwrap();
    pic.delete_canister(canister_id, None).unwrap();

    let _ = pic.get_controllers(canister_id);
}

#[test]
fn test_canister_snapshots() {
    let pic = PocketIc::new();
    let canister_id = deploy_counter_canister(&pic);

    // We bump the counter to make the counter different from its initial value.
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, 1_u32.to_le_bytes().to_vec());
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, 1_u32.to_le_bytes().to_vec());

    // We haven't taken any snapshot so far and thus listing snapshots yields an empty result.
    let snapshots = pic.list_canister_snapshots(canister_id, None).unwrap();
    assert!(snapshots.is_empty());

    // We take a snapshot (it is recommended to only take a snapshot of a stopped canister).
    pic.stop_canister(canister_id, None).unwrap();
    let first_snapshot = pic.take_canister_snapshot(canister_id, None, None).unwrap();
    pic.start_canister(canister_id, None).unwrap();

    // Listing the snapshots now should yield the snapshot we just took.
    let snapshots = pic.list_canister_snapshots(canister_id, None).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, first_snapshot.id);
    assert_eq!(snapshots[0].total_size, first_snapshot.total_size);
    assert_eq!(
        snapshots[0].taken_at_timestamp,
        first_snapshot.taken_at_timestamp
    );

    // We bump the counter once more to test loading snapshots in a subsequent step.
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, 2_u32.to_le_bytes().to_vec());
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, 2_u32.to_le_bytes().to_vec());

    // We load the snapshot (it is recommended to only load a snapshot on a stopped canister).
    pic.stop_canister(canister_id, None).unwrap();
    pic.load_canister_snapshot(canister_id, None, first_snapshot.id.clone())
        .unwrap();
    pic.start_canister(canister_id, None).unwrap();

    // We verify that the snapshot was successfully loaded.
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, 1_u32.to_le_bytes().to_vec());

    // We bump the counter again.
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, 2_u32.to_le_bytes().to_vec());
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, 2_u32.to_le_bytes().to_vec());

    // We take one more snapshot: since we already have an active snapshot,
    // taking another snapshot fails unless we specify the active snapshot to be replaced.
    pic.stop_canister(canister_id, None).unwrap();
    pic.take_canister_snapshot(canister_id, None, None)
        .unwrap_err();
    let second_snapshot = pic
        .take_canister_snapshot(canister_id, None, Some(first_snapshot.id))
        .unwrap();
    pic.start_canister(canister_id, None).unwrap();

    // Finally, we delete the current snapshot which allows us to take a snapshot without specifying any snapshot to be replaced.
    pic.delete_canister_snapshot(canister_id, None, second_snapshot.id)
        .unwrap();
    pic.take_canister_snapshot(canister_id, None, None).unwrap();
}

#[test]
fn test_wasm_chunk_store() {
    let pic = PocketIc::new();

    // We create an empty canister and top it up with cycles (WASM chunk store operations cost cycles).
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // There should be no chunks in the WASM chunk store yet.
    let stored_chunks = pic.stored_chunks(canister_id, None).unwrap();
    assert!(stored_chunks.is_empty());

    // Chunk the test canister into two chunks.
    let mut first_chunk = test_canister_wasm();
    let second_chunk = first_chunk.split_off(first_chunk.len() / 2);
    assert!(!first_chunk.is_empty());
    assert!(!second_chunk.is_empty());

    // We upload a bogus chunk to the WASM chunk store and confirm that the returned hash
    // matches the actual hash of the chunk.
    let first_chunk_hash = pic
        .upload_chunk(canister_id, None, first_chunk.clone())
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(first_chunk.clone());
    assert_eq!(first_chunk_hash, hasher.finalize().to_vec());

    // We upload the same chunk once more and get the same hash back.
    let same_chunk_hash = pic
        .upload_chunk(canister_id, None, first_chunk.clone())
        .unwrap();
    assert_eq!(first_chunk_hash, same_chunk_hash);

    // We upload a different chunk.
    let second_chunk_hash = pic.upload_chunk(canister_id, None, second_chunk).unwrap();

    // Now the two chunks should be stored in the WASM chunk store.
    let stored_chunks = pic.stored_chunks(canister_id, None).unwrap();
    assert_eq!(stored_chunks.len(), 2);
    assert!(stored_chunks.contains(&first_chunk_hash));
    assert!(stored_chunks.contains(&second_chunk_hash));

    // We create a new canister and install it from chunks.
    let test_canister = pic.create_canister();
    pic.add_cycles(test_canister, INIT_CYCLES);
    let mut hasher = Sha256::new();
    hasher.update(test_canister_wasm());
    let test_canister_wasm_hash = hasher.finalize().to_vec();
    pic.install_chunked_canister(
        test_canister,
        None,
        CanisterInstallMode::Install,
        canister_id,
        vec![first_chunk_hash, second_chunk_hash],
        test_canister_wasm_hash,
        Encode!(&()).unwrap(),
    )
    .unwrap();

    // We clear the WASM chunk store.
    pic.clear_chunk_store(canister_id, None).unwrap();

    // There should be no more chunks in the WASM chunk store.
    let stored_chunks = pic.stored_chunks(canister_id, None).unwrap();
    assert!(stored_chunks.is_empty());
}

#[test]
fn canister_logs() {
    let pic = PocketIc::new();

    // We deploy the test canister.
    let canister = pic.create_canister();
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    let logs = pic
        .fetch_canister_logs(canister, Principal::anonymous())
        .unwrap();
    assert!(logs.is_empty());

    let log_msg_works = "Logging works!";
    pic.update_call(
        canister,
        Principal::anonymous(),
        "canister_log",
        encode_one(log_msg_works).unwrap(),
    )
    .unwrap();
    let log_msg_multiple = "Multiple logs are stored!";
    pic.update_call(
        canister,
        Principal::anonymous(),
        "canister_log",
        encode_one(log_msg_multiple).unwrap(),
    )
    .unwrap();

    let logs = pic
        .fetch_canister_logs(canister, Principal::anonymous())
        .unwrap();
    assert_eq!(logs.len(), 2);
    assert_eq!(
        String::from_utf8(logs[0].content.clone()).unwrap(),
        log_msg_works
    );
    assert_eq!(
        String::from_utf8(logs[1].content.clone()).unwrap(),
        log_msg_multiple
    );
}

#[test]
fn get_subnet() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let topology = pic.topology();

    let default_subnet = topology
        .get_subnet(topology.default_effective_canister_id.clone().into())
        .unwrap();
    let default_subnet_config = topology.subnet_configs.get(&default_subnet).unwrap();
    assert_eq!(default_subnet_config.subnet_kind, SubnetKind::Application);

    let nns_subnet = topology
        .get_subnet(Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap())
        .unwrap();
    let nns_subnet_config = topology.subnet_configs.get(&nns_subnet).unwrap();
    assert_eq!(nns_subnet_config.subnet_kind, SubnetKind::NNS);
}

#[test]
fn make_live_twice() {
    // create PocketIC instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // create HTTP gateway
    let url = pic.make_live(None);

    let same_url = pic.make_live(None);
    assert_eq!(same_url, url);
}

#[test]
fn create_instance_from_existing() {
    let pic = PocketIc::new();
    let canister_id = deploy_counter_canister(&pic);

    // Bump and check the counter value;
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, vec![1, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, vec![1, 0, 0, 0]);

    // Create a new PocketIC handle to the existing PocketIC instance.
    let pic_handle =
        PocketIc::new_from_existing_instance(pic.get_server_url(), pic.instance_id(), None);

    // Bump and check the counter value;
    let reply = call_counter_canister(&pic_handle, canister_id, "write");
    assert_eq!(reply, vec![2, 0, 0, 0]);
    let reply = call_counter_canister(&pic_handle, canister_id, "read");
    assert_eq!(reply, vec![2, 0, 0, 0]);

    // Drop the newly created PocketIC handle.
    // This should not delete the existing PocketIC instance.
    drop(pic_handle);

    // Bump and check the counter value;
    let reply = call_counter_canister(&pic, canister_id, "write");
    assert_eq!(reply, vec![3, 0, 0, 0]);
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, vec![3, 0, 0, 0]);
}

#[test]
fn ingress_status() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    let caller = Principal::from_slice(&[0xFF; 29]);
    let msg_id = pic
        .submit_call(canister_id, caller, "whoami", encode_one(()).unwrap())
        .unwrap();

    assert!(pic.ingress_status(msg_id.clone()).is_none());

    // since the ingress status is not available, any caller can attempt to retrieve it
    match pic.ingress_status_as(msg_id.clone(), Principal::anonymous()) {
        IngressStatusResult::NotAvailable => (),
        status => panic!("Unexpected ingress status: {:?}", status),
    }

    pic.tick();

    let reply = pic.ingress_status(msg_id.clone()).unwrap().unwrap();
    let principal = Decode!(&reply, String).unwrap();
    assert_eq!(principal, canister_id.to_string());

    // now that the ingress status is available, the caller must match
    let expected_err = "The user tries to access Request ID not signed by the caller.";
    match pic.ingress_status_as(msg_id.clone(), Principal::anonymous()) {
        IngressStatusResult::Forbidden(msg) => assert_eq!(msg, expected_err,),
        status => panic!("Unexpected ingress status: {:?}", status),
    }

    // confirm the behavior of read state requests
    let resp = read_state_request_status(&pic, canister_id, msg_id.message_id.as_slice());
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap(),
        expected_err
    );
}

fn read_state_request_status(
    pic: &PocketIc,
    canister_id: Principal,
    msg_id: &[u8],
) -> reqwest::blocking::Response {
    let path = vec!["request_status".into(), Label::from_bytes(msg_id)];
    let paths = vec![path.clone()];
    let content = ReadState {
        ingress_expiry: pic
            .get_time()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            + 240_000_000_000,
        sender: Principal::anonymous(),
        paths,
    };
    let envelope = Envelope {
        content: std::borrow::Cow::Borrowed(&content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    let mut serialized_bytes = Vec::new();
    let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
    serializer.self_describe().unwrap();
    envelope.serialize(&mut serializer).unwrap();

    let endpoint = format!(
        "instances/{}/api/v2/canister/{}/read_state",
        pic.instance_id(),
        canister_id.to_text()
    );
    let client = reqwest::blocking::Client::new();
    client
        .post(pic.get_server_url().join(&endpoint).unwrap())
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(serialized_bytes)
        .send()
        .unwrap()
}

#[test]
fn await_call_no_ticks() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    pic.make_live(None);

    let msg_id = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "whoami",
            encode_one(()).unwrap(),
        )
        .unwrap();

    let result = pic.await_call_no_ticks(msg_id).unwrap();
    let principal = Decode!(&result, String).unwrap();
    assert_eq!(principal, canister_id.to_string());
}

#[test]
fn many_intersubnet_calls() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .build();
    let canister_1 = pic.create_canister_on_subnet(None, None, pic.topology().get_app_subnets()[0]);
    pic.add_cycles(canister_1, 100_000_000_000_000_000);
    pic.install_canister(canister_1, test_canister_wasm(), vec![], None);
    let canister_2 = pic.create_canister_on_subnet(None, None, pic.topology().get_app_subnets()[1]);
    pic.add_cycles(canister_2, 100_000_000_000_000_000);
    pic.install_canister(canister_2, test_canister_wasm(), vec![], None);

    let mut msg_ids = vec![];
    let num_msgs: usize = 500;
    let msg_size: usize = 10000;
    for _ in 0..num_msgs {
        let msg_id = pic
            .submit_call(
                canister_1,
                Principal::anonymous(),
                "call_with_large_blob",
                Encode!(&canister_2, &msg_size).unwrap(),
            )
            .unwrap();
        msg_ids.push(msg_id);
    }
    for msg_id in msg_ids {
        pic.await_call(msg_id).unwrap();
    }
}

#[test]
fn test_reject_response_type() {
    let pic = PocketIc::new();

    // We create a test canister.
    let canister = pic.create_canister();
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    for certified in [true, false] {
        for action in ["reject", "trap"] {
            for method in ["query", "update"] {
                // updates are always certified
                if !certified && method == "update" {
                    continue;
                }
                let method_name = format!("{}_{}", action, method);
                let (err, msg_id) = if certified {
                    let msg_id = pic
                        .submit_call(
                            canister,
                            Principal::anonymous(),
                            &method_name,
                            Encode!(&()).unwrap(),
                        )
                        .unwrap();
                    let err = pic.await_call(msg_id.clone()).unwrap_err();
                    (err, Some(msg_id))
                } else {
                    let err = pic
                        .query_call(
                            canister,
                            Principal::anonymous(),
                            &method_name,
                            Encode!(&()).unwrap(),
                        )
                        .unwrap_err();
                    (err, None)
                };
                if let Some(msg_id) = msg_id {
                    let ingress_status_err = pic.ingress_status(msg_id).unwrap().unwrap_err();
                    assert_eq!(ingress_status_err, err);
                }
                if action == "reject" {
                    assert_eq!(err.reject_code, RejectCode::CanisterReject);
                    assert_eq!(err.error_code, ErrorCode::CanisterRejectedMessage);
                } else {
                    assert_eq!(action, "trap");
                    assert_eq!(err.reject_code, RejectCode::CanisterError);
                    assert_eq!(err.error_code, ErrorCode::CanisterCalledTrap);
                }
                assert!(err
                    .reject_message
                    .contains(&format!("{} in {} method", action, method)));
                assert_eq!(err.certified, certified);
            }
        }
    }

    for action in [b"trap", b"skip"] {
        let err = pic
            .submit_call(
                canister,
                Principal::anonymous(),
                "trap_update",
                action.to_vec(),
            )
            .unwrap_err();
        if action == b"trap" {
            assert_eq!(err.reject_code, RejectCode::CanisterError);
            assert!(err.reject_message.contains("trap in inspect message"));
            assert_eq!(err.error_code, ErrorCode::CanisterCalledTrap);
        } else {
            assert_eq!(action, b"skip");
            assert_eq!(err.reject_code, RejectCode::CanisterReject);
            assert!(err.reject_message.contains("Canister rejected the message"));
            assert_eq!(err.error_code, ErrorCode::CanisterRejectedMessage);
        }
        // inspect message is always uncertified
        assert!(!err.certified);
    }
}
