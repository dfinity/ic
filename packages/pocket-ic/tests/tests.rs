use crate::common::frontend_canister;
use candid::{CandidType, Decode, Deserialize, Encode, Principal, decode_one, encode_one};
use ic_agent::Agent;
use ic_agent::agent::EffectiveId;
use ic_certification::Label;
use ic_management_canister_types::{
    Bip341, CanisterIdRecord, CanisterInstallMode, CanisterSettings, EcdsaPublicKeyResult,
    ProvisionalCreateCanisterWithCyclesArgs, SchnorrAlgorithm, SchnorrAux,
    SchnorrKeyId as SchnorrPublicKeyArgsKeyId, SchnorrPublicKeyResult,
};
use ic_management_canister_types_private::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterHttpResponsePayload,
    FlexibleCanisterHttpRequestArgs, FlexibleHttpGlobalError, FlexibleHttpRequestErr,
    FlexibleHttpRequestResult, HttpMethod, HttpRequestResourceReport,
    PRICING_VERSION_PAY_AS_YOU_GO, ReplicationCounts, TransformContext, TransformFunc,
};
use ic_transport_types::EnvelopeContent::{Call, ReadState};
use ic_transport_types::{CallResponse, Envelope};
use ic_utils::interfaces::ManagementCanister;
use pocket_ic::SubnetMetrics;
use pocket_ic::{
    CreateCanisterParams, CreateCanisterPlacement, DefaultEffectiveCanisterIdError, ErrorCode,
    IngressStatusResult, PocketIc, PocketIcBuilder, PocketIcState, RejectCode, StartServerParams,
    Time,
    common::rest::{
        AutoProgressConfig, BlobCompression, CanisterCyclesCostSchedule,
        CanisterHttpPricingVersion, CanisterHttpReject, CanisterHttpReplication, CanisterHttpReply,
        CanisterHttpRequest, CanisterHttpResponse, CanisterIdRange, CreateInstanceResponse,
        ExtendedSubnetConfigSet, HttpGatewayDetails, HttpsConfig, IcpConfig, IcpConfigFlag,
        IcpFeatures, IcpFeaturesConfig, InitialTime, InstanceConfig, InstanceHttpGatewayConfig,
        MockCanisterHttpResponse, MockFlexibleCanisterHttpResponse, RawEffectivePrincipal,
        RawMessageId, SubnetConfigSet, SubnetKind, SubnetSpec,
    },
    nonblocking::PocketIc as PocketIcAsync,
    query_candid, start_server, update_candid,
};
use reqwest::blocking::Response;
use reqwest::header::CONTENT_LENGTH;
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::OnceLock,
    time::{Duration, SystemTime},
};
use tempfile::{NamedTempFile, TempDir};

mod common;

// 3T cycles
const INIT_CYCLES: u128 = 3_000_000_000_000;

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

// Create a counter canister and charge it with initial cycles.
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
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
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
    // goes on II which is created dynamically with its ICP mainnet canister ranges
    let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);
    let topology = pic.topology();
    let ii_subnet_id = topology.get_ii().unwrap();
    assert_eq!(pic.get_subnet(canister_id).unwrap(), ii_subnet_id);
    // The II canister ID is a singleton range.
    let ii_canister_ranges = &topology
        .subnet_configs
        .get(&ii_subnet_id)
        .unwrap()
        .canister_ranges;
    let ii_canister_range = CanisterIdRange {
        start: canister_id.into(),
        end: canister_id.into(),
    };
    assert!(ii_canister_ranges.contains(&ii_canister_range));
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
    expected = "The effective canister ID 2vxsx-fae does not belong to an existing subnet and it is not a mainnet canister ID."
)]
fn test_create_canister_with_not_contained_id_panics() {
    let pic = PocketIc::new();
    let _ = pic.create_canister_with_id(None, None, Principal::anonymous());
}

#[test]
#[should_panic(
    expected = "The effective canister ID rwlgt-iiaaa-aaaaa-aaaaa-cai belongs to the NNS subnet on the IC mainnet for which PocketIC provides a `SubnetKind`: please set up your PocketIC instance with a subnet of that `SubnetKind`."
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
fn test_create_canister_with_params_default() {
    let pic = PocketIc::new();
    let canister_id = pic
        .create_canister_with_params(None, CreateCanisterParams::default())
        .unwrap();
    // Default cycles balance is 100T.
    assert_eq!(pic.cycle_balance(canister_id), 100_000_000_000_000);
}

#[test]
fn test_create_canister_with_params_cycles() {
    let pic = PocketIc::new();
    let cycles = 42_000_000_000_000_u128;
    let canister_id = pic
        .create_canister_with_params(
            None,
            CreateCanisterParams {
                cycles: Some(cycles),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(pic.cycle_balance(canister_id), cycles);
}

#[test]
fn test_create_canister_with_params_subnet() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_fiduciary_subnet()
        .build();
    let topology = pic.topology();
    let fidu_subnet_id = topology.get_fiduciary().unwrap();
    let canister_id = pic
        .create_canister_with_params(
            None,
            CreateCanisterParams {
                placement: Some(CreateCanisterPlacement::SubnetId(fidu_subnet_id)),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(pic.get_subnet(canister_id).unwrap(), fidu_subnet_id);
}

#[test]
fn test_create_canister_with_params_canister_id() {
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    let canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_params(
            None,
            CreateCanisterParams {
                placement: Some(CreateCanisterPlacement::CanisterId(canister_id)),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);
    assert_eq!(
        pic.get_subnet(canister_id).unwrap(),
        pic.topology().get_nns().unwrap()
    );
}

#[test]
fn test_create_canister_with_params_duplicate_id_fails() {
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    let canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    let res = pic.create_canister_with_params(
        None,
        CreateCanisterParams {
            placement: Some(CreateCanisterPlacement::CanisterId(canister_id)),
            ..Default::default()
        },
    );
    assert!(res.is_ok());
    let res = pic.create_canister_with_params(
        None,
        CreateCanisterParams {
            placement: Some(CreateCanisterPlacement::CanisterId(canister_id)),
            ..Default::default()
        },
    );
    assert!(res.is_err());
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
                        _ => panic!("Unexpected update call result: {xnet_result:?}"),
                    };
                } else {
                    // An inter-canister call to a different subnet with 10M argument traps.
                    match xnet_result {
                        Err(reject_response) => {
                            assert_eq!(reject_response.error_code, ErrorCode::CanisterCalledTrap);
                        }
                        _ => panic!("Unexpected update call result: {xnet_result:?}"),
                    };
                }
            }
        }
    }
}

#[test]
fn test_initial_timestamp() {
    let initial_timestamp = 1_620_328_630_000_000_000; // 06 May 2021 21:17:10 CEST
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_initial_time(Time::from_nanos_since_unix_epoch(initial_timestamp))
        .build();

    // Initial time is bumped by 1ns during instance creation to ensure strict monotonicity.
    assert_eq!(
        pic.get_time().as_nanos_since_unix_epoch(),
        initial_timestamp + 1
    );
}

#[test]
#[should_panic(
    expected = "The initial timestamp (unix timestamp in nanoseconds) must be no earlier than 1620328630000000000 (provided 0)."
)]
fn test_invalid_initial_timestamp() {
    let _pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_initial_time(Time::from_nanos_since_unix_epoch(0))
        .build();
}

#[test]
fn test_initial_timestamp_with_cycles_minting() {
    let initial_timestamp = 1_620_633_601_000_000_000; // 10 May 2021 10:00:01
    let icp_features = IcpFeatures {
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_icp_features(icp_features)
        .with_initial_time(Time::from_nanos_since_unix_epoch(initial_timestamp))
        .build();

    // Initial time is bumped during each subnet creation and when executing rounds to deploy the CMC.
    assert_eq!(
        pic.get_time().as_nanos_since_unix_epoch(),
        initial_timestamp + 7
    );
}

#[test]
#[should_panic(
    expected = "The initial timestamp (unix timestamp in nanoseconds) must be no earlier than 1620633601000000000 (provided 1620328630000000000)."
)]
fn test_invalid_initial_timestamp_with_cycles_minting() {
    let initial_timestamp = 1_620_328_630_000_000_000; // 06 May 2021 21:17:10 CEST
    let icp_features = IcpFeatures {
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_icp_features(icp_features)
        .with_initial_time(Time::from_nanos_since_unix_epoch(initial_timestamp))
        .build();
}

#[test]
fn test_auto_progress() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_auto_progress()
        .build();

    assert!(pic.auto_progress_enabled());
}

#[test]
fn test_auto_progress_updates_certified_time() {
    let pic = PocketIc::new();

    // We create a test canister.
    let canister = pic.create_canister();
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    let before = SystemTime::now();
    pic.auto_progress();

    // Enabling auto progress only returns after the certified time has been updated
    // for the first time and thus a query call (which reads the certified time)
    // must observe a time no earlier than the time before enabling auto progress.
    let t: (u64,) = query_candid(&pic, canister, "time", ((),)).unwrap();
    assert!(t.0 >= Time::from(before).as_nanos_since_unix_epoch());
}

fn query_and_check_time(pic: &PocketIc, test_canister: Principal) {
    let current_time = pic.get_time().as_nanos_since_unix_epoch();
    let t: (u64,) = query_candid(pic, test_canister, "time", ((),)).unwrap();
    assert_eq!(pic.get_time().as_nanos_since_unix_epoch(), current_time);
    assert_eq!(current_time, t.0);
}

#[test]
fn test_get_and_set_and_advance_time() {
    let pic = PocketIc::new();

    // We create a test canister.
    let canister = pic.create_canister();
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    let unix_time_nanos = 1650000000000000000;
    let time = Time::from_nanos_since_unix_epoch(unix_time_nanos);
    pic.set_time(time);
    // time is not certified so `query_and_check_time` would fail here
    assert_eq!(pic.get_time(), time);
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time);
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time + std::time::Duration::from_nanos(1));

    let unix_time_nanos = 1700000000000000000;
    let time = Time::from_nanos_since_unix_epoch(unix_time_nanos);
    pic.set_certified_time(time);
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time);
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time + std::time::Duration::from_nanos(1));
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time + std::time::Duration::from_nanos(2));

    let time = pic.get_time();
    pic.advance_time(std::time::Duration::from_secs(420));
    // time is not certified so `query_and_check_time` would fail here
    assert_eq!(pic.get_time(), time + std::time::Duration::from_secs(420));
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(pic.get_time(), time + std::time::Duration::from_secs(420));
    pic.tick();
    query_and_check_time(&pic, canister);
    assert_eq!(
        pic.get_time(),
        time + std::time::Duration::from_secs(420) + std::time::Duration::from_nanos(1)
    );
}

#[test]
#[should_panic(expected = "SettingTimeIntoPast")]
fn set_time_into_past() {
    let pic = PocketIc::new();

    let now = SystemTime::now();
    let future = now + std::time::Duration::from_secs(1);
    pic.set_time(future.into());

    pic.set_time(now.into());
}

#[test]
fn time_on_resumed_instance() {
    let state = PocketIcState::new();

    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(state)
        .build();

    let now = SystemTime::now();
    pic.set_certified_time(now.into());

    let time = pic.get_time();
    assert_eq!(time, now.into());
    let state = pic.drop_and_take_state().unwrap();

    let pic = PocketIcBuilder::new().with_state(state).build();

    // The time on the resumed instances increases by 2ns:
    // - 1ns due to executing a checkpointed round before dropping the original instance;
    // - 1ns due to bumping time when creating a new instance to ensure strict time monotonicity.
    let resumed_time = pic.get_time();
    assert_eq!(resumed_time, time + Duration::from_nanos(2));
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

    // Create a counter canister and charge it with initial cycles.
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

    // Charge the canister with cycles.
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
                    _ => panic!("Unexpected update call result: {xnet_result:?}"),
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
    // We create a PocketIC instance consisting of the NNS, II, test threshold keys, and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // this subnet has `key_1`
        .with_test_threshold_keys_subnet() // this subnet has `test_key_1` and `dfx_test_key`
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

    // We define the message, derivation path, and Merkle root hash.
    let message = b"Hello, world!==================="; // must be of length 32 bytes for BIP340
    let derivation_path = vec!["my message".as_bytes().to_vec()];
    let some_aux: Option<SchnorrAux> = Some(SchnorrAux::Bip341(Bip341 {
        merkle_root_hash: b"Hello, aux!=====================".to_vec(),
    }));
    for algorithm in [SchnorrAlgorithm::Bip340secp256k1, SchnorrAlgorithm::Ed25519] {
        for name in ["key_1", "test_key_1", "dfx_test_key"] {
            for aux in [None, some_aux.clone()] {
                let key_id = SchnorrPublicKeyArgsKeyId {
                    algorithm,
                    name: name.to_string(),
                };

                // We get the Schnorr public key and signature.
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
                    SchnorrAlgorithm::Bip340secp256k1 => {
                        use k256::ecdsa::signature::hazmat::PrehashVerifier;
                        use k256::schnorr::{Signature, VerifyingKey};
                        let bip340_public_key = schnorr_public_key.public_key[1..].to_vec();
                        let public_key = match aux {
                            None => bip340_public_key,
                            Some(SchnorrAux::Bip341(bip341_aux)) => {
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
                            "{verification_result:?}"
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

    // We create a PocketIC instance consisting of the NNS, II, test threshold keys, and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // this subnet has `key_1`
        .with_test_threshold_keys_subnet() // this subnet has `test_key_1` and `dfx_test_key`
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

    // We define the message and derivation path.
    let message = "Hello, world!".to_string();
    let derivation_path = vec!["my message".as_bytes().to_vec()];

    // We compute the hash of the message.
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: Vec<u8> = hasher.finalize().to_vec();

    for key_id in ["key_1", "test_key_1", "dfx_test_key"] {
        let key_id = key_id.to_string();

        // We get the ECDSA public key and signature.
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
    // With no II and fiduciary subnet, there's no subnet with ECDSA keys.
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

    // We define the message and derivation path.
    let message = "Hello, world!".to_string();
    let derivation_path = vec!["my message".as_bytes().to_vec()];

    // We compute the hash of the message.
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: Vec<u8> = hasher.finalize().to_vec();

    // We attempt to get the ECDSA public key and signature via update calls to the test canister.
    let key_id = "dfx_test_key".to_string();
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
fn test_vetkd() {
    use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};

    // We create a PocketIC instance consisting of the II, test threshold keys, and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_ii_subnet() // this subnet has `key_1`
        .with_test_threshold_keys_subnet() // this subnet has `test_key_1` and `dfx_test_key`
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

    // We define the context, input, and transport public key.
    let context = b"My context".to_vec();
    let input = b"My input".to_vec();
    let tsk = TransportSecretKey::from_seed([64; 32].to_vec()).unwrap();
    let transport_public_key = tsk.public_key();

    for key_id in ["key_1", "test_key_1", "dfx_test_key"] {
        let key_id = key_id.to_string();

        // We get the VetKd public key and encrypted key.
        let vetkd_public_key =
            update_candid::<(Option<Principal>, Vec<u8>, String), (Result<Vec<u8>, String>,)>(
                &pic,
                canister,
                "vetkd_public_key",
                (None, context.clone(), key_id.clone()),
            )
            .unwrap()
            .0
            .unwrap();

        let vetkd_encryped_key =
            update_candid::<(Vec<u8>, Vec<u8>, String, Vec<u8>), (Result<Vec<u8>, String>,)>(
                &pic,
                canister,
                "vetkd_derive_key",
                (
                    context.clone(),
                    input.clone(),
                    key_id.clone(),
                    transport_public_key.clone(),
                ),
            )
            .unwrap()
            .0
            .unwrap();

        // We verify the vetKd encrypted key.
        let ek = EncryptedVetKey::deserialize(&vetkd_encryped_key).unwrap();

        let dpk = DerivedPublicKey::deserialize(&vetkd_public_key).unwrap();

        ek.decrypt_and_verify(&tsk, &dpk, &input).unwrap();
    }
}

/// Makes an ordinary (fully replicated, legacy priced) outcall through
/// `canister_id`, mocks a reply for it and checks that the reply arrives.
fn test_canister_http(pic: &PocketIc, canister_id: Principal) {
    let outcall = Outcall::FullyReplicated {
        pay_as_you_go: false,
    };
    let (call_id, request) =
        submit_outcall(pic, canister_id, &outcall, None, OUTCALL_CYCLES, false);

    let body = b"hello".to_vec();
    mock_uniform(pic, &request, reply(&body));
    // There should be no more pending canister http outcalls.
    assert!(pic.get_canister_http().is_empty());

    let outcome = await_outcome(pic, call_id, &outcall);
    assert_eq!(outcome.bodies(&outcall.label()), vec![body]);
}

#[test]
fn test_canister_http_on_fresh_and_resumed_instance() {
    // create an empty PocketIC state to be used:
    // - initially by a fresh PocketIC instance;
    // - later by a PocketIC instance resumed from that state.
    let state = PocketIcState::new();

    // create a fresh PocketIC instance with two application subnets
    // so that the latest registry version is different
    // from the registry version at which one of the subnets was created
    // (this scenario led to a bug in PocketIC canister http outcalls)
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_application_subnet()
        .with_state(state)
        .build();

    // create a test canister on every subnet
    let topology = pic.topology();
    let mut canisters = vec![];
    for app_subnet in topology.get_app_subnets() {
        let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
        pic.add_cycles(canister_id, INIT_CYCLES);
        pic.install_canister(canister_id, test_canister_wasm(), vec![], None);
        canisters.push(canister_id);
    }
    // ensure that canister http outcalls work on every subnet
    for canister_id in &canisters {
        test_canister_http(&pic, *canister_id);
    }

    // drop the first PocketIC instance and serialize its state
    let state = pic.drop_and_take_state().unwrap();

    // create the second PocketIC instance resuming from the existing state
    let pic = PocketIcBuilder::new().with_state(state).build();
    // ensure that canister http outcalls still work on every subnet
    for canister_id in &canisters {
        test_canister_http(&pic, *canister_id);
    }
}

// ---------------------------------------------------------------------------
// Flexible canister HTTP outcalls and pay-as-you-go pricing
// ---------------------------------------------------------------------------

/// The cycles attached to the outcalls in these tests, comfortably above anything
/// an outcall can cost. Whatever the outcall does not spend is refunded when its
/// response is delivered.
const OUTCALL_CYCLES: u128 = 1_000_000_000_000;

/// The number of nodes of a PocketIC application subnet.
const SUBNET_NODES: u32 = 13;

/// Every outcall below has `url = "example.com"` and no headers, body or
/// transform, so the request size its fees are computed from is the URL's length.
const REQUEST_BYTES: u128 = 11;

/// The up-front base fee of a fully replicated outcall of `request_bytes` bytes,
/// mirroring `base_fee` in `rs/https_outcalls/pricing/src/fees.rs`. 38_424_750
/// cycles for these tests.
const fn fully_replicated_base_fee(request_bytes: u128) -> u128 {
    let n = SUBNET_NODES as u128;
    n * (1_000_000 + 50 * request_bytes + 140_000 * n + 800 * n * n)
}

/// The up-front base fee of a flexible or non-replicated outcall of
/// `request_bytes` bytes requiring `min_responses` responses (1 for a
/// non-replicated one), mirroring `base_fee` in
/// `rs/https_outcalls/pricing/src/fees.rs`.
const fn gossipping_base_fee(request_bytes: u128, min_responses: u128) -> u128 {
    let n = SUBNET_NODES as u128;
    n * (1_000_000
        + 50 * request_bytes
        + 90_000 * n
        + 2_000 * n * min_responses
        + 100_000 * min_responses)
}

/// What putting `response_bytes` bytes of response into a block costs, mirroring
/// `consensus_fee` in `rs/https_outcalls/pricing/src/fees.rs`. 9_490 cycles per
/// byte on a 13-node subnet.
const fn consensus_fee(response_bytes: u128) -> u128 {
    let n = SUBNET_NODES as u128;
    n * (10 * n + 600) * response_bytes
}

/// The per-response overhead the consensus fee of a flexible outcall is priced
/// with (`FLEXIBLE_RESPONSE_SIZE_OVERHEAD` in
/// `rs/https_outcalls/pricing/src/fees.rs`).
const FLEXIBLE_RESPONSE_OVERHEAD: u128 = 181;

/// A response is delivered Candid-encoded, which adds a body-independent header of
/// well under 64 bytes, so `body.len() <= content_size <= body.len() + CANDID_SLACK`.
const CANDID_SLACK: u128 = 64;

/// Everything a scenario costs besides the outcall itself: inducting the ingress
/// message, executing the two messages, transmitting request and response, and the
/// idle burn of a few rounds. About 20M cycles in practice.
const EXECUTION_SLACK: u128 = 100_000_000;

/// What a node is charged for downloading `response_bytes` bytes of a response
/// (`PER_DOWNLOADED_BYTE_FEE` in `rs/https_outcalls/pricing/src/fees.rs`).
const fn download_fee(response_bytes: u128) -> u128 {
    50 * response_bytes
}

/// What a node of an outcall whose nodes gossip their own responses instead of
/// agreeing on one — a non-replicated or flexible outcall — is charged for gossiping
/// a response of `response_bytes` bytes to its peers (`gossip_usage_fee` in
/// `rs/https_outcalls/pricing/src/fees.rs`).
const fn gossip_fee(response_bytes: u128) -> u128 {
    50 * response_bytes * SUBNET_NODES as u128
}

/// How the outcall under test is made.
#[derive(Clone, Debug, PartialEq)]
enum Outcall {
    /// `http_request`, performed by every node of the subnet.
    FullyReplicated { pay_as_you_go: bool },
    /// `http_request` with `is_replicated = false`, performed by a single node.
    NonReplicated { pay_as_you_go: bool },
    /// `flexible_http_request` with the given replication counts (`None` asks for
    /// the subnet's default). Always priced with the pay-as-you-go pricing model
    /// where that model is enabled.
    Flexible(Option<ReplicationCounts>),
}

impl Outcall {
    /// Names this outcall in assertion messages, so that a failing cell of a
    /// matrix test can be told apart from its siblings.
    fn label(&self) -> String {
        match self {
            Self::FullyReplicated { pay_as_you_go } => {
                format!("fully replicated, {}", pricing_label(*pay_as_you_go))
            }
            Self::NonReplicated { pay_as_you_go } => {
                format!("non-replicated, {}", pricing_label(*pay_as_you_go))
            }
            Self::Flexible(None) => "flexible (default replication)".to_string(),
            Self::Flexible(Some(counts)) => format!(
                "flexible ({}/{}/{})",
                counts.total_requests, counts.min_responses, counts.max_responses
            ),
        }
    }

    /// The replication `PocketIc::get_canister_http` must report for it.
    fn expected_replication(&self) -> CanisterHttpReplication {
        match self {
            Self::FullyReplicated { .. } => CanisterHttpReplication::FullyReplicated,
            Self::NonReplicated { .. } => CanisterHttpReplication::NonReplicated,
            // Without explicit counts every node performs the outcall and
            // `floor(2N/3) + 1` responses are required.
            Self::Flexible(None) => CanisterHttpReplication::Flexible {
                total_requests: SUBNET_NODES,
                min_responses: 2 * SUBNET_NODES / 3 + 1,
                max_responses: SUBNET_NODES,
            },
            Self::Flexible(Some(counts)) => CanisterHttpReplication::Flexible {
                total_requests: counts.total_requests,
                min_responses: counts.min_responses,
                max_responses: counts.max_responses,
            },
        }
    }

    /// The pricing model `PocketIc::get_canister_http` must report for it on a
    /// subnet where the pay-as-you-go pricing model is (or is not) enabled.
    fn expected_pricing(&self, pay_as_you_go_enabled: bool) -> CanisterHttpPricingVersion {
        let pay_as_you_go = match self {
            Self::FullyReplicated { pay_as_you_go } | Self::NonReplicated { pay_as_you_go } => {
                // An `http_request` asking for pay-as-you-go pricing where that
                // model is not enabled falls back to the legacy pricing model.
                *pay_as_you_go && pay_as_you_go_enabled
            }
            // A flexible outcall does not choose: it is priced with pay-as-you-go
            // pricing where that model is enabled, and falls back to the legacy
            // pricing model on the free subnets where it is offered without it.
            Self::Flexible(_) => pay_as_you_go_enabled,
        };
        if pay_as_you_go {
            CanisterHttpPricingVersion::PayAsYouGo
        } else {
            CanisterHttpPricingVersion::Legacy
        }
    }

    /// The number of nodes that perform the outcall, i.e. the number of responses
    /// `PocketIc::mock_flexible_canister_http_response` accepts.
    fn committee_size(&self) -> u32 {
        match self.expected_replication() {
            CanisterHttpReplication::FullyReplicated => SUBNET_NODES,
            CanisterHttpReplication::NonReplicated => 1,
            CanisterHttpReplication::Flexible { total_requests, .. } => total_requests,
        }
    }

    /// The base fee this outcall is charged up front under the pay-as-you-go
    /// pricing model.
    fn base_fee(&self) -> u128 {
        match self.expected_replication() {
            CanisterHttpReplication::FullyReplicated => fully_replicated_base_fee(REQUEST_BYTES),
            CanisterHttpReplication::NonReplicated => gossipping_base_fee(REQUEST_BYTES, 1),
            CanisterHttpReplication::Flexible { min_responses, .. } => {
                gossipping_base_fee(REQUEST_BYTES, min_responses as u128)
            }
        }
    }

    /// Whether the nodes of this outcall gossip their own responses to their peers
    /// rather than agreeing on a single one, which is what they are charged a
    /// gossip fee on top of their download fee for.
    fn gossips(&self) -> bool {
        !matches!(
            self.expected_replication(),
            CanisterHttpReplication::FullyReplicated
        )
    }

    /// The management canister endpoint that makes this outcall, and its
    /// Candid-encoded arguments.
    fn call(&self, transform: Option<&TransformContext>) -> (&'static str, Vec<u8>) {
        match self {
            Self::FullyReplicated { pay_as_you_go } | Self::NonReplicated { pay_as_you_go } => {
                let args = CanisterHttpRequestArgs {
                    url: OUTCALL_URL.to_string(),
                    max_response_bytes: None,
                    headers: BoundedHttpHeaders::new(vec![]),
                    body: None,
                    method: HttpMethod::GET,
                    transform: transform.cloned(),
                    is_replicated: matches!(self, Self::NonReplicated { .. }).then_some(false),
                    pricing_version: pay_as_you_go.then_some(PRICING_VERSION_PAY_AS_YOU_GO),
                };
                ("http_request", Encode!(&args).unwrap())
            }
            Self::Flexible(replication) => {
                let args = FlexibleCanisterHttpRequestArgs {
                    url: OUTCALL_URL.to_string(),
                    max_response_bytes: None,
                    headers: BoundedHttpHeaders::new(vec![]),
                    body: None,
                    method: HttpMethod::GET,
                    transform: transform.cloned(),
                    replication: replication.clone(),
                };
                ("flexible_http_request", Encode!(&args).unwrap())
            }
        }
    }

    /// Whether the calling canister receives a `flexible_http_request_result`
    /// rather than an `http_request_result`.
    fn is_flexible(&self) -> bool {
        matches!(self, Self::Flexible(_))
    }
}

fn pricing_label(pay_as_you_go: bool) -> &'static str {
    if pay_as_you_go {
        "pay-as-you-go"
    } else {
        "legacy"
    }
}

/// The URL every outcall in these tests is made to. It is never dialed: PocketIC
/// answers the outcall from the mocked response.
const OUTCALL_URL: &str = "example.com";

/// A PocketIC instance with a single application subnet on which flexible HTTP
/// outcalls and the pay-as-you-go pricing model are enabled.
fn flexible_outcalls_pic() -> PocketIc {
    PocketIcBuilder::new()
        .with_application_subnet()
        .with_icp_config(IcpConfig {
            beta_features: Some(IcpConfigFlag::Enabled),
            ..Default::default()
        })
        .build()
}

fn deploy_test_canister(pic: &PocketIc) -> Principal {
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);
    canister_id
}

/// The argument of the test canister's `proxy_call` endpoint: the callee, the
/// method, the Candid-encoded arguments to pass on, and the cycles to attach.
fn proxy_call_arg(method: &str, args: Vec<u8>, cycles: u128) -> Vec<u8> {
    Encode!(
        &Principal::management_canister(),
        &method.to_string(),
        &ByteBuf::from(args),
        &cycles
    )
    .unwrap()
}

/// Submits `outcall` through the test canister and returns the message ID of the
/// pending update call together with the pending outcall, having checked that
/// PocketIC reports the outcall's replication and pricing model as expected.
///
/// This is the one place that knows how an outcall is submitted, for all three
/// ways of making one.
fn submit_outcall(
    pic: &PocketIc,
    canister_id: Principal,
    outcall: &Outcall,
    transform: Option<&TransformContext>,
    cycles: u128,
    pay_as_you_go_enabled: bool,
) -> (RawMessageId, CanisterHttpRequest) {
    let (method, args) = outcall.call(transform);
    let call_id = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "proxy_call",
            proxy_call_arg(method, args, cycles),
        )
        .unwrap();

    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let mut canister_http_requests = pic.get_canister_http();
    assert_eq!(
        canister_http_requests.len(),
        1,
        "{}: expected exactly one pending outcall",
        outcall.label()
    );
    let request = canister_http_requests.pop().unwrap();
    assert_eq!(
        request.replication,
        outcall.expected_replication(),
        "{}: unexpected replication",
        outcall.label()
    );
    assert_eq!(
        request.pricing_version,
        outcall.expected_pricing(pay_as_you_go_enabled),
        "{}: unexpected pricing version",
        outcall.label()
    );
    (call_id, request)
}

/// Submits `outcall` on an instance where the pay-as-you-go pricing model is
/// enabled, attaching [`OUTCALL_CYCLES`] and using no transform.
fn submit(
    pic: &PocketIc,
    canister_id: Principal,
    outcall: &Outcall,
) -> (RawMessageId, CanisterHttpRequest) {
    submit_outcall(pic, canister_id, outcall, None, OUTCALL_CYCLES, true)
}

fn reply(body: &[u8]) -> CanisterHttpResponse {
    CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
        status: 200,
        headers: vec![],
        body: body.to_vec(),
    })
}

fn reject(message: &str) -> CanisterHttpResponse {
    CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
        // `SysTransient`, i.e. what a connection failure produces.
        reject_code: 2,
        message: message.to_string(),
    })
}

/// Mocks the same response for every node of the subnet, which is what an outcall
/// made through `http_request` needs.
fn mock_uniform(pic: &PocketIc, request: &CanisterHttpRequest, response: CanisterHttpResponse) {
    pic.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response,
        additional_responses: vec![],
    });
}

/// Mocks one response per node of the subnet, which is how the nodes of an outcall
/// made through `http_request` are made to disagree.
fn mock_per_node(
    pic: &PocketIc,
    request: &CanisterHttpRequest,
    responses: Vec<CanisterHttpResponse>,
) {
    let (response, additional_responses) = responses.split_first().unwrap();
    pic.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response: response.clone(),
        additional_responses: additional_responses.to_vec(),
    });
}

/// Mocks one response per committee node of a flexible outcall.
fn mock_committee(
    pic: &PocketIc,
    request: &CanisterHttpRequest,
    responses: Vec<CanisterHttpResponse>,
) {
    pic.mock_flexible_canister_http_response(MockFlexibleCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        responses,
    });
}

/// What the calling canister observed, whichever endpoint it called.
enum Outcome {
    Http(Result<CanisterHttpResponsePayload, (RejectionCode, String)>),
    Flexible(FlexibleHttpRequestResult),
}

impl Outcome {
    /// The response payloads delivered to the calling canister: one for an
    /// `http_request`, between `min_responses` and `max_responses` for a flexible
    /// outcall.
    fn payloads(&self, label: &str) -> Vec<CanisterHttpResponsePayload> {
        match self {
            Self::Http(Ok(payload)) => vec![payload.clone()],
            Self::Http(Err((code, message))) => {
                panic!("{label}: expected a response, got a {code:?} rejection: {message}")
            }
            Self::Flexible(FlexibleHttpRequestResult::Ok(payloads)) => payloads.clone(),
            Self::Flexible(FlexibleHttpRequestResult::Err(err)) => {
                panic!("{label}: expected a response, got {:?}", err.global_error)
            }
        }
    }

    /// The bodies delivered to the calling canister, in the order they were
    /// delivered in.
    fn bodies(&self, label: &str) -> Vec<Vec<u8>> {
        self.payloads(label)
            .into_iter()
            .map(|payload| payload.body)
            .collect()
    }
}

/// Awaits the calling canister's update call and decodes what it observed.
fn await_outcome(pic: &PocketIc, call_id: RawMessageId, outcall: &Outcall) -> Outcome {
    let reply = pic.await_call(call_id).unwrap();
    let result: Result<ByteBuf, (RejectionCode, String)> = decode_one(&reply).unwrap();
    if outcall.is_flexible() {
        let bytes = result.expect("the flexible outcall was rejected synchronously");
        Outcome::Flexible(Decode!(&bytes, FlexibleHttpRequestResult).unwrap())
    } else {
        Outcome::Http(result.map(|bytes| Decode!(&bytes, CanisterHttpResponsePayload).unwrap()))
    }
}

/// The `flexible_http_request_result` error the calling canister observed, having
/// checked what every flexible error carries whatever its outcome.
fn expect_flexible_error(outcome: Outcome, label: &str) -> FlexibleHttpRequestErr {
    let err = match outcome {
        Outcome::Flexible(FlexibleHttpRequestResult::Err(err)) => err,
        Outcome::Flexible(FlexibleHttpRequestResult::Ok(payloads)) => {
            panic!(
                "{label}: expected an error, got {} payloads",
                payloads.len()
            )
        }
        Outcome::Http(_) => panic!("{label}: not a flexible outcall"),
    };

    assert!(
        !err.message.is_empty(),
        "{label}: a flexible error carries a human readable message"
    );
    // Each detail is a different node of the outcall's committee.
    let mut node_ids: Vec<_> = err
        .node_details
        .iter()
        .map(|detail| detail.node_id)
        .collect();
    let reported = node_ids.len();
    node_ids.sort();
    node_ids.dedup();
    assert_eq!(
        node_ids.len(),
        reported,
        "{label}: node_details names the same node twice"
    );
    for detail in &err.node_details {
        assert_ne!(
            detail.node_id,
            Principal::anonymous(),
            "{label}: a node detail has no node ID"
        );
        // Consensus does not populate the per-node resource report yet: every
        // outcome fills in `HttpRequestResourceReport::default()`, so no resource is
        // ever reported as used or as having exceeded its budget. Pinned here so
        // that a test notices when the report starts carrying something.
        assert_eq!(
            detail.report,
            HttpRequestResourceReport::default(),
            "{label}: the per-node resource report is populated now"
        );
    }
    err
}

/// The rejection the calling canister observed for a non-flexible outcall.
fn expect_http_rejection(outcome: Outcome, label: &str) -> (RejectionCode, String) {
    match outcome {
        Outcome::Http(Err(rejection)) => rejection,
        Outcome::Http(Ok(payload)) => panic!(
            "{label}: expected a rejection, got a {} response",
            payload.status
        ),
        Outcome::Flexible(_) => panic!("{label}: not an `http_request` outcall"),
    }
}

/// Decodes the synchronous rejection of the test canister's `proxy_call`.
fn decode_sync_rejection(reply: &[u8]) -> (RejectionCode, String) {
    let result: Result<ByteBuf, (RejectionCode, String)> = decode_one(reply).unwrap();
    result.expect_err("the outcall was not rejected synchronously")
}

/// The cell set of a scenario that both pricing models can reach: each way of
/// making an outcall, in each pricing model where that is a choice, with the
/// flexible cell shaped as the scenario needs it.
///
/// Every such scenario should use this, so that the sets do not drift apart. A
/// scenario that can only be reached under one pricing model spells its cells out
/// instead, and says why.
fn outcalls_with(flexible: ReplicationCounts) -> Vec<Outcall> {
    vec![
        Outcall::FullyReplicated {
            pay_as_you_go: false,
        },
        Outcall::FullyReplicated {
            pay_as_you_go: true,
        },
        Outcall::NonReplicated {
            pay_as_you_go: false,
        },
        Outcall::NonReplicated {
            pay_as_you_go: true,
        },
        Outcall::Flexible(Some(flexible)),
    ]
}

/// Every way of making an outcall, with flexible cells covering the three orderings
/// the replication counts can have: `max < total`, `min < max == total` at subnet
/// scale, and `min == max == total`.
fn all_outcalls() -> Vec<Outcall> {
    let mut outcalls = outcalls_with(ReplicationCounts {
        // `max_responses` caps the delivery below what the committee reported.
        total_requests: 4,
        min_responses: 1,
        max_responses: 2,
    });
    outcalls.push(Outcall::Flexible(None));
    // Every node must answer, and every answer is delivered.
    outcalls.push(Outcall::Flexible(Some(ReplicationCounts {
        total_requests: 3,
        min_responses: 3,
        max_responses: 3,
    })));
    outcalls
}

/// Every way of making an outcall delivers the mocked response, whichever pricing
/// model it is priced with, and a flexible one delivers between `min_responses`
/// and `max_responses` of them.
#[test]
fn test_canister_http_reply() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let body = b"hello".to_vec();

    for outcall in all_outcalls() {
        let label = outcall.label();
        // Keep every cell's starting balance comparable.
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit(&pic, canister_id, &outcall);

        let committee_size = outcall.committee_size();
        if outcall.is_flexible() {
            mock_committee(&pic, &request, vec![reply(&body); committee_size as usize]);
        } else {
            mock_uniform(&pic, &request, reply(&body));
        }
        // Once any response to an outcall has been mocked it is no longer pending.
        assert!(pic.get_canister_http().is_empty(), "{label}");

        let outcome = await_outcome(&pic, call_id, &outcall);
        let payloads = outcome.payloads(&label);
        let delivered = match outcall.expected_replication() {
            CanisterHttpReplication::Flexible {
                min_responses,
                max_responses,
                ..
            } => min_responses..=max_responses,
            // An `http_request` delivers exactly one response.
            _ => 1..=1,
        };
        assert!(
            delivered.contains(&(payloads.len() as u32)),
            "{label}: {} payloads delivered, expected {delivered:?}",
            payloads.len()
        );
        for payload in &payloads {
            assert_eq!(payload.status, 200, "{label}");
            assert_eq!(payload.body, body, "{label}");
        }
    }
}

/// What differing responses mean depends on how the outcall is replicated: a fully
/// replicated outcall fails because its nodes cannot reach consensus, a
/// non-replicated one delivers the designated node's response and ignores the rest,
/// and a flexible one delivers several of them, smallest first.
#[test]
fn test_canister_http_differing_responses() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    // Distinct sizes, so that the order a flexible outcall delivers them in is
    // determined.
    let bodies = [
        b"a".to_vec(),
        b"bb".to_vec(),
        b"ccc".to_vec(),
        b"dddd".to_vec(),
    ];

    for outcall in outcalls_with(ReplicationCounts {
        total_requests: 4,
        min_responses: 4,
        max_responses: 4,
    }) {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit(&pic, canister_id, &outcall);

        if outcall.is_flexible() {
            mock_committee(
                &pic,
                &request,
                bodies.iter().map(|body| reply(body)).collect(),
            );
        } else {
            // One response per subnet node, cycling through the four bodies, so
            // that at most four nodes agree — short of the `n - f` a fully
            // replicated outcall needs.
            mock_per_node(
                &pic,
                &request,
                (0..SUBNET_NODES)
                    .map(|i| reply(&bodies[i as usize % bodies.len()]))
                    .collect(),
            );
        }

        let outcome = await_outcome(&pic, call_id, &outcall);
        match outcall {
            Outcall::FullyReplicated { .. } => {
                let (reject_code, message) = expect_http_rejection(outcome, &label);
                assert!(
                    matches!(reject_code, RejectionCode::SysTransient),
                    "{label}: unexpected reject code {reject_code:?} ({message})"
                );
                assert!(
                    message.starts_with(
                        "No consensus could be reached. Replicas had different responses."
                    ),
                    "{label}: unexpected rejection message {message:?}"
                );
                // The message reports how many nodes reported each response: the
                // 13 nodes cycle through the four bodies, so one group of four
                // and three of three.
                assert_eq!(message.matches(": 4]").count(), 1, "{label}: {message}");
                assert_eq!(message.matches(": 3]").count(), 3, "{label}: {message}");
            }
            Outcall::NonReplicated { .. } => {
                // Which node was delegated the outcall is not exposed, so only the
                // fact that one of the mocked responses was delivered is determined.
                let delivered = outcome.bodies(&label);
                assert_eq!(delivered.len(), 1, "{label}");
                assert!(bodies.contains(&delivered[0]), "{label}: {delivered:?}");
            }
            Outcall::Flexible(_) => {
                // All four are delivered, smallest first.
                assert_eq!(outcome.bodies(&label), bodies.to_vec(), "{label}");
            }
        }
    }
}

/// An outcall whose nodes do not respond stays pending until it times out,
/// whichever way it was made and whichever pricing model it is priced with.
#[test]
fn test_canister_http_timeout() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);

    for outcall in outcalls_with(ReplicationCounts {
        total_requests: 4,
        min_responses: 3,
        max_responses: 4,
    }) {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit(&pic, canister_id, &outcall);

        // Leave the outcall undecided. A flexible outcall can be answered by only
        // some of its committee — fewer than the `min_responses` it needs — while
        // an `http_request` outcall is answered for every node of the subnet or not
        // at all, so it is simply left unanswered.
        if outcall.is_flexible() {
            mock_committee(&pic, &request, vec![reply(b"hello")]);
        }
        pic.tick();

        // Advance the time past the outcall's 60 second timeout.
        pic.advance_time(std::time::Duration::from_secs(180));
        pic.tick();

        // A timed out outcall is no longer pending, so it can neither be answered
        // nor time out a second time.
        assert!(
            pic.get_canister_http().is_empty(),
            "{label}: the timed out outcall is still pending"
        );

        let outcome = await_outcome(&pic, call_id, &outcall);
        if outcall.is_flexible() {
            let err = expect_flexible_error(outcome, &label);
            assert_eq!(
                err.global_error,
                Some(FlexibleHttpGlobalError::Timeout(candid::Reserved)),
                "{label}"
            );
            assert_eq!(err.message, "Flexible HTTP request timed out", "{label}");
            // A timed out outcall saw no response, so there is no node to detail.
            assert!(err.node_details.is_empty(), "{label}");
        } else {
            let (reject_code, message) = expect_http_rejection(outcome, &label);
            assert!(
                matches!(reject_code, RejectionCode::SysTransient),
                "{label}: unexpected reject code {reject_code:?} ({message})"
            );
            assert_eq!(message, "Canister http request timed out", "{label}");
        }
    }
}

/// A mocked reject is delivered to the calling canister for an `http_request`;
/// for a flexible outcall, more rejects than the slack between `total_requests`
/// and `min_responses` allows deliver a `too_many_rejects` error naming the
/// rejecting nodes.
#[test]
fn test_canister_http_reject() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    const MESSAGE: &str = "Connection refused";

    for outcall in outcalls_with(ReplicationCounts {
        total_requests: 4,
        min_responses: 3,
        max_responses: 4,
    }) {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit(&pic, canister_id, &outcall);

        if outcall.is_flexible() {
            // The slack is `4 - 3 = 1`, so two rejects are one too many.
            mock_committee(
                &pic,
                &request,
                vec![
                    reject(MESSAGE),
                    reject(MESSAGE),
                    reply(b"hello"),
                    reply(b"hello"),
                ],
            );
        } else {
            mock_uniform(&pic, &request, reject(MESSAGE));
        }

        let outcome = await_outcome(&pic, call_id, &outcall);
        if outcall.is_flexible() {
            let err = expect_flexible_error(outcome, &label);
            assert_eq!(
                err.global_error,
                Some(FlexibleHttpGlobalError::TooManyRejects(candid::Reserved)),
                "{label}"
            );
            assert_eq!(
                err.message, "Too many rejects: 2 responses are rejects",
                "{label}"
            );
            assert_eq!(err.node_details.len(), 2, "{label}");
            for detail in &err.node_details {
                let node_error = detail.error.as_ref().expect("expected a per-node error");
                assert_eq!(node_error.code, "SysTransient", "{label}");
                assert_eq!(node_error.message, MESSAGE, "{label}");
            }
        } else {
            let (reject_code, message) = expect_http_rejection(outcome, &label);
            assert!(
                matches!(reject_code, RejectionCode::SysTransient),
                "{label}: unexpected reject code {reject_code:?} ({message})"
            );
            assert_eq!(message, MESSAGE, "{label}");
        }
    }
}

/// The calling canister's transform function is applied to every mocked response,
/// however the outcall was made.
#[test]
fn test_canister_http_transform() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let context = b"this is my transform context".to_vec();
    let transform = TransformContext {
        function: TransformFunc(candid::Func {
            method: "transform".to_string(),
            principal: canister_id,
        }),
        context: context.clone(),
    };

    for outcall in outcalls_with(ReplicationCounts {
        total_requests: 2,
        min_responses: 2,
        max_responses: 2,
    }) {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit_outcall(
            &pic,
            canister_id,
            &outcall,
            Some(&transform),
            OUTCALL_CYCLES,
            true,
        );

        if outcall.is_flexible() {
            mock_committee(
                &pic,
                &request,
                vec![reply(b"hello"); outcall.committee_size() as usize],
            );
        } else {
            mock_uniform(&pic, &request, reply(b"hello"));
        }

        let outcome = await_outcome(&pic, call_id, &outcall);
        for payload in outcome.payloads(&label) {
            // The transform function clears the response headers and replaces the
            // body with its transform context.
            assert!(payload.headers.is_empty(), "{label}");
            assert_eq!(payload.body, context, "{label}");
        }
    }
}

/// Under the pay-as-you-go pricing model an outcall is charged its base fee plus
/// what the responding nodes report having spent plus the cost of putting the
/// response into a block — and nothing else: the per-replica cycles allowances it
/// withheld are refunded.
///
/// A mocked outcall is charged no response time, so what its nodes spend follows
/// from the size of the mocked response and the charge is determined up to the
/// Candid encoding of that response.
#[test]
fn test_canister_http_pay_as_you_go_cycles() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let body = vec![b'x'; 1_000];

    // Pay-as-you-go cells only: the formula asserted below is the pay-as-you-go
    // one, and the legacy pricing model charges its whole fee up front instead.
    for outcall in [
        Outcall::FullyReplicated {
            pay_as_you_go: true,
        },
        // The only cell whose committee is smaller than the subnet, and so the only
        // one that tells charging the one designated node's reported spend apart
        // from charging all of the subnet's.
        Outcall::NonReplicated {
            pay_as_you_go: true,
        },
        Outcall::Flexible(Some(ReplicationCounts {
            total_requests: 4,
            min_responses: 4,
            max_responses: 4,
        })),
    ] {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let balance_before = pic.cycle_balance(canister_id);
        let (call_id, request) = submit(&pic, canister_id, &outcall);

        // The whole attached payment leaves the canister while the outcall is in
        // flight (along with what the call itself reserves for transmitting and
        // executing the response); the unspent part comes back with the response.
        let balance_in_flight = pic.cycle_balance(canister_id);
        assert!(
            balance_before - balance_in_flight >= OUTCALL_CYCLES,
            "{label}: {} withheld, expected at least {OUTCALL_CYCLES}",
            balance_before - balance_in_flight
        );

        let committee_size = outcall.committee_size() as u128;
        let response = reply(&body);
        if outcall.is_flexible() {
            mock_committee(&pic, &request, vec![response; committee_size as usize]);
        } else {
            mock_uniform(&pic, &request, response);
        }
        let outcome = await_outcome(&pic, call_id, &outcall);
        assert_eq!(outcome.bodies(&label)[0], body, "{label}");

        // What the outcall is charged: the base fee, the spend every responding
        // node reported, and the consensus cost of the delivered response(s). A
        // flexible outcall delivers up to `max_responses` of them and prices each
        // with a per-response overhead.
        let response_bytes = body.len() as u128;
        let per_response = if outcall.is_flexible() {
            FLEXIBLE_RESPONSE_OVERHEAD + response_bytes
        } else {
            response_bytes
        };
        // The consensus fee is charged over the responses actually delivered, a
        // count that walks down from `max_responses` towards `min_responses`
        // depending on what the committee's unspent allowances cover and what fits
        // the block (`select_flexible_responses` in
        // `rs/https_outcalls/consensus/src/payload_builder/utils.rs`). Pinning it
        // with `min_responses == max_responses` is also what zeroes the
        // `flexible_extra_response_fee(delivered - min_responses)` term that the
        // formula below leaves out.
        let responses = match outcall.expected_replication() {
            CanisterHttpReplication::Flexible {
                min_responses,
                max_responses,
                ..
            } => {
                assert_eq!(
                    min_responses, max_responses,
                    "{label}: the formula below holds only for a pinned delivered response count"
                );
                max_responses as u128
            }
            _ => 1,
        };
        // Charged no response time, a node spends what it paid to download the
        // response, plus what it paid to gossip it if its outcall's nodes gossip.
        let spend_per_node = |bytes: u128| {
            download_fee(bytes)
                + if outcall.gossips() {
                    gossip_fee(bytes)
                } else {
                    0
                }
        };
        // The two bounds are the same formula, priced with the Candid header of every
        // response first left out, then counted in.
        let floor = outcall.base_fee()
            + committee_size * spend_per_node(response_bytes)
            + consensus_fee(responses * per_response);
        let ceiling = outcall.base_fee()
            + committee_size * spend_per_node(response_bytes + CANDID_SLACK)
            + consensus_fee(responses * (per_response + CANDID_SLACK))
            + EXECUTION_SLACK;

        let charged = balance_before - pic.cycle_balance(canister_id);
        assert!(
            charged >= floor,
            "{label}: charged {charged}, expected at least {floor}"
        );
        // Had the per-replica allowances not been refunded, `charged` would be tens
        // of billions of cycles rather than tens of millions.
        assert!(
            charged < ceiling,
            "{label}: charged {charged}, expected less than {ceiling}"
        );
    }
}

/// A mocked reject costs exactly the base fee plus the consensus cost of putting
/// the reject into a block: a rejecting node downloads nothing, and a fully
/// replicated outcall does not gossip its responses either, so it reports a zero
/// spend.
#[test]
fn test_canister_http_pay_as_you_go_reject_cycles() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    const MESSAGE: &str = "Connection refused";

    let outcall = Outcall::FullyReplicated {
        pay_as_you_go: true,
    };
    let label = outcall.label();
    let balance_before = pic.cycle_balance(canister_id);
    let (call_id, request) = submit(&pic, canister_id, &outcall);
    mock_uniform(&pic, &request, reject(MESSAGE));

    let outcome = await_outcome(&pic, call_id, &outcall);
    let (_, message) = expect_http_rejection(outcome, &label);
    assert_eq!(message, MESSAGE);

    // A reject's size is its reject code plus its message.
    let http_cost =
        fully_replicated_base_fee(REQUEST_BYTES) + consensus_fee(1 + MESSAGE.len() as u128);
    let charged = balance_before - pic.cycle_balance(canister_id);
    assert!(
        charged >= http_cost,
        "charged {charged}, expected at least {http_cost}"
    );
    assert!(
        charged < http_cost + EXECUTION_SLACK,
        "charged {charged}, expected less than {}",
        http_cost + EXECUTION_SLACK
    );
}

/// Pay-as-you-go pricing charges for the response actually received, so a small
/// response costs materially less than under the legacy pricing model, which
/// charges for the largest response the outcall could have received.
#[test]
fn test_canister_http_pay_as_you_go_is_cheaper_for_a_small_response() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let body = b"hello".to_vec();

    let mut charged = BTreeMap::new();
    for pay_as_you_go in [false, true] {
        let outcall = Outcall::FullyReplicated { pay_as_you_go };
        pic.add_cycles(canister_id, INIT_CYCLES);
        let balance_before = pic.cycle_balance(canister_id);
        let (call_id, request) = submit(&pic, canister_id, &outcall);
        mock_uniform(&pic, &request, reply(&body));
        let outcome = await_outcome(&pic, call_id, &outcall);
        assert_eq!(outcome.bodies(&outcall.label())[0], body);
        charged.insert(
            pay_as_you_go,
            balance_before - pic.cycle_balance(canister_id),
        );
    }

    assert!(
        charged[&true] < charged[&false],
        "pay-as-you-go charged {}, legacy charged {}",
        charged[&true],
        charged[&false]
    );
}

/// A "fire and forget" flexible outcall — `min_responses = max_responses = 0`, which
/// the replication counts allow — is answered as soon as any one of its committee
/// has responded, and delivers no payloads at all.
///
/// It cannot fail with `too_many_rejects` either: needing zero replies never becomes
/// impossible, however many nodes reject.
#[test]
fn test_flexible_canister_http_fire_and_forget() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);

    let outcall = Outcall::Flexible(Some(ReplicationCounts {
        total_requests: 4,
        min_responses: 0,
        max_responses: 0,
    }));
    let label = outcall.label();

    for response in [reply(b"hello"), reject("Connection refused")] {
        pic.add_cycles(canister_id, INIT_CYCLES);
        let (call_id, request) = submit(&pic, canister_id, &outcall);
        // One response from one of the four committee nodes is enough to decide it.
        mock_committee(&pic, &request, vec![response]);

        let outcome = await_outcome(&pic, call_id, &outcall);
        let payloads = outcome.payloads(&label);
        assert!(
            payloads.is_empty(),
            "{label}: expected no payloads, got {}",
            payloads.len()
        );
    }
}

/// Once the responses that would have to be delivered no longer fit into a block,
/// a flexible outcall fails with `ResponsesTooLarge`.
#[test]
fn test_flexible_canister_http_responses_too_large() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);

    let outcall = Outcall::Flexible(Some(ReplicationCounts {
        total_requests: 2,
        min_responses: 2,
        max_responses: 2,
    }));
    let (call_id, request) = submit(&pic, canister_id, &outcall);

    // Both responses are well below the 2 MB cap on a single response
    // (`MAX_CANISTER_HTTP_RESPONSE_BYTES`), but the two of them together exceed the
    // 2 MiB a block has for HTTP outcall responses
    // (`MAX_CANISTER_HTTP_PAYLOAD_SIZE`), and both of them have to be delivered
    // (`min_responses == 2`).
    let body = vec![b'x'; 1_100_000];
    mock_committee(&pic, &request, vec![reply(&body); 2]);

    let err = expect_flexible_error(await_outcome(&pic, call_id, &outcall), &outcall.label());
    assert_eq!(
        err.global_error,
        Some(FlexibleHttpGlobalError::ResponsesTooLarge(candid::Reserved))
    );
    // The message accounts for the responses it could not fit, and the per-node
    // details report the size of every response the committee was seen to produce.
    assert!(
        err.message.starts_with(
            "Responses too large: need at least 2 OK responses to fit within 2097152 bytes"
        ),
        "unexpected message {:?}",
        err.message
    );
    assert_eq!(err.node_details.len(), 2);
    for detail in &err.node_details {
        let node_error = detail.error.as_ref().expect("expected a per-node error");
        assert_eq!(node_error.code, "ok");
        assert!(
            node_error.message.ends_with(" bytes"),
            "unexpected node message {:?}",
            node_error.message
        );
    }
}

/// An outcall fails with out-of-cycles once what its nodes leave unspent of their
/// per-replica cycles allowances no longer covers putting a response into a block.
#[test]
fn test_canister_http_out_of_cycles() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let body = vec![b'x'; 100_000];
    let response_bytes = body.len() as u128;

    // Pay-as-you-go cells only: out-of-cycles is a pay-as-you-go outcome, since the
    // legacy pricing model does not hold the delivery against what the nodes spent.
    for outcall in [
        Outcall::FullyReplicated {
            pay_as_you_go: true,
        },
        Outcall::Flexible(Some(ReplicationCounts {
            total_requests: 4,
            min_responses: 4,
            max_responses: 4,
        })),
    ] {
        let label = outcall.label();
        pic.add_cycles(canister_id, INIT_CYCLES);
        let committee_size = outcall.committee_size() as u128;

        // What each node spends on the response: a mocked outcall is charged no
        // response time, so only what it paid to download the response and — if its
        // nodes gossip their own responses — to gossip it.
        let spend_per_node = download_fee(response_bytes)
            + if outcall.gossips() {
                gossip_fee(response_bytes)
            } else {
                0
            };
        // Attaching twice that per node makes the per-replica allowance twice what a
        // node spends: the payment, not the worst-case usage fee, is what bounds it
        // (see `try_add_http_context_to_replicated_state`). So every node can afford
        // its response and still leaves exactly what it spent — two orders of
        // magnitude short of the 9_490 cycles per byte that delivering the response
        // costs, whatever its size.
        let cycles = outcall.base_fee() + committee_size * 2 * spend_per_node;
        let response = reply(&body);

        let (call_id, request) = submit_outcall(&pic, canister_id, &outcall, None, cycles, true);
        if outcall.is_flexible() {
            mock_committee(&pic, &request, vec![response; committee_size as usize]);
        } else {
            mock_uniform(&pic, &request, response);
        }

        let outcome = await_outcome(&pic, call_id, &outcall);
        if outcall.is_flexible() {
            let err = expect_flexible_error(outcome, &label);
            assert_eq!(
                err.global_error,
                Some(FlexibleHttpGlobalError::OutOfCycles(candid::Reserved)),
                "{label}"
            );
            // The message accounts for what the committee spent against what
            // delivering a response would have cost, and every committee node is
            // detailed with its own spend.
            assert!(
                err.message.starts_with(&format!(
                    "Out of cycles: {committee_size} of the assigned replicas reported a \
                     collective spend of "
                )),
                "{label}: unexpected message {:?}",
                err.message
            );
            assert_eq!(err.node_details.len(), committee_size as usize, "{label}");
            for detail in &err.node_details {
                let node_error = detail.error.as_ref().expect("expected a per-node error");
                assert_eq!(node_error.code, "ok", "{label}");
                assert!(
                    node_error.message.ends_with(" cycles spent"),
                    "{label}: unexpected node message {:?}",
                    node_error.message
                );
            }
        } else {
            let (reject_code, message) = expect_http_rejection(outcome, &label);
            assert!(
                matches!(reject_code, RejectionCode::CanisterReject),
                "{label}: unexpected reject code {reject_code:?} ({message})"
            );
            assert!(
                message.contains("Out of cycles:"),
                "{label}: unexpected rejection message {message:?}"
            );
        }
    }
}

/// A committee that has run out of cycles reports `out_of_cycles` even when enough
/// of its nodes rejected to make the outcall fail with `too_many_rejects`: what the
/// nodes left unspent is checked after the rejects have been found undeliverable.
#[test]
fn test_canister_http_out_of_cycles_preempts_too_many_rejects() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    /// A reject message just under the 1 KiB a node truncates them to, so that
    /// delivering the two rejects costs far more than the committee has left.
    const MESSAGE_BYTES: usize = 1_000;
    /// Per-replica allowance: enough for every node to gossip its own response many
    /// times over, but so little that the whole committee's leftovers do not cover
    /// putting two 1 KiB rejects into a block (about 22 M cycles).
    const ALLOWANCE_PER_NODE: u128 = 3_000_000;

    // The slack is `4 - 3 = 1`, so the two rejects below are one too many and would
    // deliver `too_many_rejects` if the committee could pay for it.
    let outcall = Outcall::Flexible(Some(ReplicationCounts {
        total_requests: 4,
        min_responses: 3,
        max_responses: 4,
    }));
    let label = outcall.label();
    let cycles = outcall.base_fee() + outcall.committee_size() as u128 * ALLOWANCE_PER_NODE;
    let (call_id, request) = submit_outcall(&pic, canister_id, &outcall, None, cycles, true);

    // What the committee leaves unspent no longer covers delivering either the
    // rejects or the replies.
    let message = "x".repeat(MESSAGE_BYTES);
    mock_committee(
        &pic,
        &request,
        vec![
            reject(&message),
            reject(&message),
            reply(b"hello"),
            reply(b"hello"),
        ],
    );

    let err = expect_flexible_error(await_outcome(&pic, call_id, &outcall), &label);
    assert_eq!(
        err.global_error,
        Some(FlexibleHttpGlobalError::OutOfCycles(candid::Reserved)),
        "{label}"
    );
    // The out-of-cycles message accounts for the whole committee, not just for the
    // rejects that would otherwise have decided the outcome, and every node is
    // detailed with the kind of response it produced.
    assert!(
        err.message.starts_with(
            "Out of cycles: 4 of the assigned replicas reported a collective spend of "
        ),
        "{label}: unexpected message {:?}",
        err.message
    );
    let mut codes: Vec<_> = err
        .node_details
        .iter()
        .map(|detail| {
            detail
                .error
                .as_ref()
                .expect("a per-node error")
                .code
                .clone()
        })
        .collect();
    codes.sort();
    assert_eq!(codes, ["ok", "ok", "reject", "reject"], "{label}");
}

/// What the nodes spend is what the pay-as-you-go pricing model charges for, and
/// what the legacy pricing model ignores: a larger response costs the calling
/// canister more under the former, and nothing extra under the latter, which
/// charges for the largest response the outcall could have received either way.
///
/// Delivering a larger response to the calling canister costs more as a message
/// under either pricing model, so this differences the two response sizes *and* the
/// two pricing models. What is left is what the outcall itself was charged for the
/// response, with the base fee, the message and every execution cost cancelled out.
#[test]
fn test_canister_http_derived_spend_is_only_charged_under_pay_as_you_go() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    /// Large enough that downloading and delivering it costs far more than the
    /// execution of a couple of messages, and small enough to stay well within the
    /// per-replica allowance `OUTCALL_CYCLES` buys.
    const LARGE_BODY_BYTES: u128 = 200_000;

    // No flexible cell: a flexible outcall is always priced pay-as-you-go, so there
    // is no legacy counterpart to difference it against.
    for gossips in [false, true] {
        let mut committee_size = 0;
        let mut extra = BTreeMap::new();
        for pay_as_you_go in [false, true] {
            let outcall = if gossips {
                Outcall::NonReplicated { pay_as_you_go }
            } else {
                Outcall::FullyReplicated { pay_as_you_go }
            };
            let label = outcall.label();
            committee_size = outcall.committee_size() as u128;

            let mut charged = vec![];
            for body_bytes in [0, LARGE_BODY_BYTES] {
                let body = vec![b'x'; body_bytes as usize];
                pic.add_cycles(canister_id, INIT_CYCLES);
                let balance_before = pic.cycle_balance(canister_id);
                let (call_id, request) = submit(&pic, canister_id, &outcall);
                mock_uniform(&pic, &request, reply(&body));
                let outcome = await_outcome(&pic, call_id, &outcall);
                assert_eq!(outcome.bodies(&label)[0], body, "{label}");
                charged.push(balance_before - pic.cycle_balance(canister_id));
            }
            let [with_empty_body, with_large_body] = charged[..] else {
                unreachable!()
            };
            extra.insert(pay_as_you_go, with_large_body - with_empty_body);
        }

        // Every node of the committee paid to download the larger response — and to
        // gossip it, if its outcall's nodes gossip their own responses — and putting
        // it into a block cost more too. The legacy pricing model charges for none of
        // that: it charged its whole fee up front, before any response existed.
        let spend_per_node = download_fee(LARGE_BODY_BYTES)
            + if gossips {
                gossip_fee(LARGE_BODY_BYTES)
            } else {
                0
            };
        // Priced one Candid header short of the body, to absorb both the difference
        // between the two responses' Candid encodings and a per-node receipt that
        // lands a round after the charge was measured.
        let floor =
            committee_size * spend_per_node + consensus_fee(LARGE_BODY_BYTES - CANDID_SLACK);
        let charged_for_the_response = extra[&true] - extra[&false];
        assert!(
            charged_for_the_response >= floor,
            "gossips={gossips}: pay-as-you-go was charged only {charged_for_the_response} \
             more than legacy for the larger response, expected at least {floor}"
        );
    }
}

/// Which outcalls are available, and which pricing model they end up with, on the
/// three kinds of instance a test can build: one with beta features, a plain one,
/// and one whose subnet does not charge for HTTP outcalls.
///
/// The pay-as-you-go pricing model is enabled on every subnet, so all three offer
/// flexible outcalls and price them the same way; what differs between them is
/// only whether anything is actually charged.
#[test]
fn test_canister_http_availability_and_pricing() {
    let beta = flexible_outcalls_pic();
    let beta_canister = deploy_test_canister(&beta);
    let default = PocketIc::new();
    let default_canister = deploy_test_canister(&default);
    let system = PocketIcBuilder::new().with_system_subnet().build();
    let system_subnet = system.topology().get_system_subnets()[0];
    let system_canister = system.create_canister_on_subnet(None, None, system_subnet);
    system.add_cycles(system_canister, INIT_CYCLES);
    system.install_canister(system_canister, test_canister_wasm(), vec![], None);

    for (env, pic, canister_id) in [
        ("beta features", &beta, beta_canister),
        ("default instance", &default, default_canister),
        ("system subnet", &system, system_canister),
    ] {
        for outcall in [
            Outcall::FullyReplicated {
                pay_as_you_go: true,
            },
            Outcall::NonReplicated {
                pay_as_you_go: true,
            },
            // A flexible outcall does not fit the subnet's default replication on
            // a 1-node system subnet, so ask for a single node explicitly.
            Outcall::Flexible(Some(ReplicationCounts {
                total_requests: 1,
                min_responses: 1,
                max_responses: 1,
            })),
        ] {
            let label = format!("{env}, {}", outcall.label());
            // `submit_outcall` asserts the reported replication and pricing model.
            let (call_id, request) =
                submit_outcall(pic, canister_id, &outcall, None, OUTCALL_CYCLES, true);
            let body = b"hello".to_vec();
            if outcall.is_flexible() {
                mock_committee(
                    pic,
                    &request,
                    vec![reply(&body); outcall.committee_size() as usize],
                );
            } else {
                mock_uniform(pic, &request, reply(&body));
            }
            let outcome = await_outcome(pic, call_id, &outcall);
            for delivered in outcome.bodies(&label) {
                assert_eq!(delivered, body, "{label}");
            }
        }
    }
}

/// Invalid replication counts are rejected synchronously, so the outcall never
/// becomes a pending one. (Which counts are invalid, and the exact messages, are
/// covered by the unit tests of `CanisterHttpRequestContext` in `ic-types`.)
#[test]
fn test_flexible_canister_http_invalid_replication_counts() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);

    let outcall = Outcall::Flexible(Some(ReplicationCounts {
        total_requests: 4,
        min_responses: 3,
        max_responses: 2,
    }));
    let (method, args) = outcall.call(None);
    let reply = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "proxy_call",
            proxy_call_arg(method, args, OUTCALL_CYCLES),
        )
        .unwrap();
    let (reject_code, message) = decode_sync_rejection(&reply);
    assert!(
        matches!(reject_code, RejectionCode::CanisterReject),
        "unexpected reject code {reject_code:?} (message: {message})"
    );
    assert!(
        message.contains("min_responses (3) must not exceed max_responses (2)"),
        "unexpected rejection message {message:?}"
    );
    assert!(pic.get_canister_http().is_empty());
}

/// Submits an outcall and mocks a response for it that no node of its subnet could
/// have produced. Panics with the error PocketIC reports.
fn mock_invalid_response(outcall: Outcall, invalid: InvalidMock) {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let (_call_id, request) = submit(&pic, canister_id, &outcall);
    let committee_size = outcall.committee_size() as usize;

    match invalid {
        InvalidMock::RejectMessageTooLong => {
            let response = reject(&"x".repeat(1025));
            if outcall.is_flexible() {
                mock_committee(&pic, &request, vec![response]);
            } else {
                mock_uniform(&pic, &request, response);
            }
        }
        InvalidMock::TooManyResponses => {
            mock_committee(&pic, &request, vec![reply(b"hello"); committee_size + 1]);
        }
        InvalidMock::WrongNumberOfResponses => {
            mock_per_node(&pic, &request, vec![reply(b"hello"); 2]);
        }
        InvalidMock::FlexibleMockOfNonFlexibleOutcall => {
            mock_committee(&pic, &request, vec![reply(b"hello")]);
        }
        InvalidMock::InvalidRejectCode => {
            // `RejectCode` only goes up to `SysUnknown == 6`, so there is no reject
            // a node could have reported with code 0.
            let response = CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
                reject_code: 0,
                message: "Connection refused".to_string(),
            });
            if outcall.is_flexible() {
                mock_committee(&pic, &request, vec![response]);
            } else {
                mock_uniform(&pic, &request, response);
            }
        }
        InvalidMock::UnknownRequestId => {
            // The outcall submitted above is the only pending one, so no context
            // can be found for any other request id.
            let request_id = request.request_id + 1;
            if outcall.is_flexible() {
                pic.mock_flexible_canister_http_response(MockFlexibleCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id,
                    responses: vec![reply(b"hello")],
                });
            } else {
                pic.mock_canister_http_response(MockCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id,
                    response: reply(b"hello"),
                    additional_responses: vec![],
                });
            }
        }
    }
}

enum InvalidMock {
    RejectMessageTooLong,
    TooManyResponses,
    WrongNumberOfResponses,
    FlexibleMockOfNonFlexibleOutcall,
    InvalidRejectCode,
    UnknownRequestId,
}

const FLEXIBLE_2_1_2: Outcall = Outcall::Flexible(Some(ReplicationCounts {
    total_requests: 2,
    min_responses: 1,
    max_responses: 2,
}));
const FULLY_REPLICATED: Outcall = Outcall::FullyReplicated {
    pay_as_you_go: true,
};

/// A reject message longer than the 1 KiB a node truncates its reject messages to
/// is not one any node could have reported, so mocking it is an error — through
/// either mock endpoint.
#[test]
#[should_panic(expected = "CanisterHttpRejectMessageTooLong((1025, 1024))")]
fn test_canister_http_reject_message_too_long() {
    mock_invalid_response(FULLY_REPLICATED, InvalidMock::RejectMessageTooLong);
}

#[test]
#[should_panic(expected = "CanisterHttpRejectMessageTooLong((1025, 1024))")]
fn test_flexible_canister_http_reject_message_too_long() {
    mock_invalid_response(FLEXIBLE_2_1_2, InvalidMock::RejectMessageTooLong);
}

/// The flexible mock takes at most one response per committee node.
#[test]
#[should_panic(expected = "TooManyMockCanisterHttpResponses((3, 2))")]
fn test_flexible_canister_http_too_many_responses() {
    mock_invalid_response(FLEXIBLE_2_1_2, InvalidMock::TooManyResponses);
}

/// The non-flexible mock takes either one response or exactly one per subnet node.
#[test]
#[should_panic(expected = "InvalidMockCanisterHttpResponses((2, 13))")]
fn test_canister_http_wrong_number_of_responses() {
    mock_invalid_response(FULLY_REPLICATED, InvalidMock::WrongNumberOfResponses);
}

/// A flexible outcall, on the other hand, *can* be mocked through the non-flexible
/// endpoint: that endpoint answers every node of the subnet, and the shares of the
/// nodes outside the outcall's committee are simply ignored rather than rejected.
/// This is the inverse of the two tests below, and pins the deliberate non-failure
/// `process_mock_canister_https_response` documents.
#[test]
fn test_canister_http_uniform_mock_of_flexible_outcall() {
    let pic = flexible_outcalls_pic();
    let canister_id = deploy_test_canister(&pic);
    let outcall = FLEXIBLE_2_1_2;
    let label = outcall.label();
    let body = b"hello".to_vec();
    let (call_id, request) = submit(&pic, canister_id, &outcall);

    mock_uniform(&pic, &request, reply(&body));

    let outcome = await_outcome(&pic, call_id, &outcall);
    let payloads = outcome.payloads(&label);
    assert!(!payloads.is_empty(), "{label}: no response was delivered");
    for payload in payloads {
        assert_eq!(payload.body, body, "{label}");
    }
    assert!(pic.get_canister_http().is_empty(), "{label}");
}

/// An outcall that is not flexible cannot be mocked through the flexible endpoint.
#[test]
#[should_panic(expected = "NotAFlexibleCanisterHttpRequest")]
fn test_flexible_mock_of_fully_replicated_outcall() {
    mock_invalid_response(
        FULLY_REPLICATED,
        InvalidMock::FlexibleMockOfNonFlexibleOutcall,
    );
}

#[test]
#[should_panic(expected = "NotAFlexibleCanisterHttpRequest")]
fn test_flexible_mock_of_non_replicated_outcall() {
    mock_invalid_response(
        Outcall::NonReplicated {
            pay_as_you_go: true,
        },
        InvalidMock::FlexibleMockOfNonFlexibleOutcall,
    );
}

/// A reject code outside `RejectCode` is not one any node could have reported —
/// through either mock endpoint.
#[test]
#[should_panic(expected = "InvalidRejectCode(0)")]
fn test_canister_http_invalid_reject_code() {
    mock_invalid_response(FULLY_REPLICATED, InvalidMock::InvalidRejectCode);
}

#[test]
#[should_panic(expected = "InvalidRejectCode(0)")]
fn test_flexible_canister_http_invalid_reject_code() {
    mock_invalid_response(FLEXIBLE_2_1_2, InvalidMock::InvalidRejectCode);
}

/// A response can only be mocked for an outcall that is actually pending — through
/// either mock endpoint.
#[test]
#[should_panic(expected = "InvalidCanisterHttpRequestId")]
fn test_canister_http_unknown_request_id() {
    mock_invalid_response(FULLY_REPLICATED, InvalidMock::UnknownRequestId);
}

#[test]
#[should_panic(expected = "InvalidCanisterHttpRequestId")]
fn test_flexible_canister_http_unknown_request_id() {
    mock_invalid_response(FLEXIBLE_2_1_2, InvalidMock::UnknownRequestId);
}

#[test]
fn subnet_metrics() {
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    assert!(
        pic.get_subnet_metrics(Principal::management_canister())
            .is_none()
    );

    deploy_counter_canister(&pic);

    fn get_subnet_metrics(pic: &PocketIc, subnet_id: Principal) -> SubnetMetrics {
        // Advance 10 rounds, to ensure that `canister_state_bytes` (only recomputed
        // every 10 rounds) is updated.
        for _ in 0..10 {
            pic.tick();
        }
        pic.get_subnet_metrics(subnet_id).unwrap()
    }

    pic.tick();
    let metrics = get_subnet_metrics(&pic, app_subnet);
    assert_eq!(metrics.num_canisters, 1);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));

    let canister_id = deploy_counter_canister(&pic);

    let metrics = get_subnet_metrics(&pic, app_subnet);
    assert_eq!(metrics.num_canisters, 2);
    assert!((1 << 17) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 18));

    pic.uninstall_canister(canister_id, None).unwrap();
    pic.stop_canister(canister_id, None).unwrap();

    let metrics = get_subnet_metrics(&pic, app_subnet);
    assert_eq!(metrics.num_canisters, 2);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));

    pic.delete_canister(canister_id, None).unwrap();

    let metrics = get_subnet_metrics(&pic, app_subnet);
    assert_eq!(metrics.num_canisters, 1);
    assert!((1 << 16) < metrics.canister_state_bytes && metrics.canister_state_bytes < (1 << 17));
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

    pic.drop().await;
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
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{test_driver_pid}.port"));
    let port = std::fs::read_to_string(port_file_path).unwrap();

    let server_url = format!("http://localhost:{port}");
    match pocket_ic::get_default_effective_canister_id(server_url).unwrap_err() {
        DefaultEffectiveCanisterIdError::ReqwestError(_) => (),
        err => panic!("Unexpected error: {err}"),
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

    pic.stop_canister(canister_id, None).unwrap();
    // We take another snapshot replacing the first one.
    let second_snapshot = pic
        .take_canister_snapshot(canister_id, None, Some(first_snapshot.id))
        .unwrap();
    pic.start_canister(canister_id, None).unwrap();

    // There should only be the second snapshot in the list of canister snapshots.
    let snapshots = pic.list_canister_snapshots(canister_id, None).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, second_snapshot.id);
    assert_eq!(snapshots[0].total_size, second_snapshot.total_size);
    assert_eq!(
        snapshots[0].taken_at_timestamp,
        second_snapshot.taken_at_timestamp
    );

    // Attempt to take another snapshot without providing a replace_id. The second snapshot
    // should be still there.
    pic.stop_canister(canister_id, None).unwrap();
    let third_snapshot = pic.take_canister_snapshot(canister_id, None, None).unwrap();
    pic.start_canister(canister_id, None).unwrap();
    let snapshots = pic.list_canister_snapshots(canister_id, None).unwrap();
    assert_eq!(snapshots[0].id, second_snapshot.id);

    // Finally, we delete the second snapshot which leaves the canister with the third snapshot
    // only.
    pic.delete_canister_snapshot(canister_id, None, second_snapshot.id)
        .unwrap();
    let snapshots = pic.list_canister_snapshots(canister_id, None).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, third_snapshot.id);
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
        status => panic!("Unexpected ingress status: {status:?}"),
    }

    pic.tick();

    let reply = pic.ingress_status(msg_id.clone()).unwrap().unwrap();
    let principal = Decode!(&reply, String).unwrap();
    assert_eq!(principal, canister_id.to_string());

    // now that the ingress status is available, the caller must match
    let expected_err = "The user tries to access Request ID not signed by the caller.";
    match pic.ingress_status_as(msg_id.clone(), Principal::anonymous()) {
        IngressStatusResult::Forbidden(msg) => assert_eq!(msg, expected_err,),
        status => panic!("Unexpected ingress status: {status:?}"),
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
        ingress_expiry: pic.get_time().as_nanos_since_unix_epoch() + 240_000_000_000,
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
fn call_ingress_expiry() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // submit an update call via /api/v2/canister/.../call using an ingress expiry in the future
    let unix_time_nanos = 2272143600000000000; // Wed Jan 01 2042 00:00:00 GMT+0100
    let time = Time::from_nanos_since_unix_epoch(unix_time_nanos);
    pic.set_certified_time(time);
    let ingress_expiry = pic.get_time().as_nanos_since_unix_epoch() + 240_000_000_000;
    let (resp, msg_id) = call_request(
        &pic,
        Principal::anonymous(),
        ingress_expiry,
        canister_id,
        "v2",
    );
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    // execute a round on the PocketIC instance to process that update call
    pic.tick();

    // check the update call status
    let raw_message_id = RawMessageId {
        effective_principal: RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
        message_id: msg_id.to_vec(),
    };
    let reply = pic.ingress_status(raw_message_id).unwrap().unwrap();
    let principal = Decode!(&reply, String).unwrap();
    assert_eq!(principal, canister_id.to_string());

    // use an invalid ingress expiry
    let ingress_expiry = SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        + 240_000_000_000;
    let (resp, _msg_id) = call_request(
        &pic,
        Principal::anonymous(),
        ingress_expiry,
        canister_id,
        "v2",
    );
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let err = String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap();
    assert!(
        err.contains("Invalid request expiry: Specified ingress_expiry not within expected range")
    );
}

fn call_request(
    pic: &PocketIc,
    sender: Principal,
    ingress_expiry: u64,
    canister_id: Principal,
    version: &str,
) -> (reqwest::blocking::Response, [u8; 32]) {
    let content = Call {
        nonce: None,
        ingress_expiry,
        sender,
        canister_id,
        method_name: "whoami".to_string(),
        arg: Encode!(&()).unwrap(),
        sender_info: None,
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
        "instances/{}/api/{}/canister/{}/call",
        pic.instance_id(),
        version,
        canister_id.to_text()
    );
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(pic.get_server_url().join(&endpoint).unwrap())
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(serialized_bytes)
        .send()
        .unwrap();
    (resp, *content.to_request_id())
}

#[test]
fn call_request_versions() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_auto_progress()
        .build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    // submit an update call via /api/<version>/canister/.../call
    for version in ["v2", "v3", "v4"] {
        let ingress_expiry = pic.get_time().as_nanos_since_unix_epoch() + 240_000_000_000;
        let (resp, _msg_id) = call_request(
            &pic,
            Principal::anonymous(),
            ingress_expiry,
            canister_id,
            version,
        );
        let status = resp.status();
        if version == "v2" {
            assert_eq!(status, reqwest::StatusCode::ACCEPTED);
        } else {
            assert_eq!(status, reqwest::StatusCode::OK);
        }
    }
}

// Sends an update call to a newly created canister using the endpoint `/api/v4/canister/.../call`
// and impersonating the sender.
fn update_call_via_call_request(pic: &PocketIc) -> Response {
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    let ingress_expiry = pic.get_time().as_nanos_since_unix_epoch() + 240_000_000_000;
    // because `call_request` does not include any signature
    // the sender `Principal::from_slice(&[42; 29])` is being impersonated
    let (resp, _msg_id) = call_request(
        pic,
        Principal::from_slice(&[42; 29]),
        ingress_expiry,
        canister_id,
        "v4",
    );

    resp
}

#[test]
fn impersonate_sender_in_call_request_fails() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_auto_progress()
        .build();

    // an update call to /api/v4/canister/.../call impersonating the sender
    // fails because ingress validation is enabled (by default)
    let resp = update_call_via_call_request(&pic);

    let status = resp.status();
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    let response_bytes = String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap();
    assert!(
        response_bytes.contains("Missing signature"),
        "Unexpected response {response_bytes}"
    );
}

#[test]
fn impersonate_sender_in_call_request_succeeds() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_auto_progress()
        .disable_ingress_validation()
        .build();

    // an update call to /api/v4/canister/.../call impersonating the sender
    // succeeds with disabled ingress validation
    let resp = update_call_via_call_request(&pic);

    let status = resp.status();
    assert_eq!(status, reqwest::StatusCode::OK);
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
                let method_name = format!("{action}_{method}");
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
                assert!(
                    err.reject_message
                        .contains(&format!("{action} in {method} method"))
                );
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

#[test]
fn test_http_methods() {
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
    pic.make_live(None);

    // We request the path `/` with various HTTP methods.
    // We use raw endpoints as the test canister does not support certification.
    for method in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::HEAD,
        Method::PATCH,
    ] {
        let (client, url) = frontend_canister(&pic, canister, true, "/");
        let res = client.request(method.clone(), url.clone()).send().unwrap();
        // The test canister rejects all request to the path `/` with `StatusCode::BAD_REQUEST`
        // and the error message "The request is not supported by the test canister.".
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let content_length: usize = res
            .headers()
            .get(CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let expected_page = "The request is not supported by the test canister.";
        assert_eq!(content_length, expected_page.len());
        let page = String::from_utf8(res.bytes().unwrap().to_vec()).unwrap();
        if let Method::HEAD = method {
            assert!(page.is_empty());
        } else {
            assert_eq!(page, expected_page);
        }
    }
}

#[test]
fn state_handle() {
    let state = PocketIcState::new();

    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(state)
        .build();
    let canister_id = pic.create_canister();
    let state = pic.drop_and_take_state().unwrap();

    let pic = PocketIcBuilder::new().with_state(state).build();
    assert!(pic.canister_exists(canister_id));
    let state = pic.drop_and_take_state().unwrap();

    let path = state.into_path();
    let state = PocketIcState::new_from_path(path);

    let pic1 = PocketIcBuilder::new().with_read_only_state(&state).build();
    assert!(pic1.canister_exists(canister_id));

    let pic2 = PocketIcBuilder::new().with_read_only_state(&state).build();
    assert!(pic2.canister_exists(canister_id));
}

#[tokio::test]
async fn state_handle_async() {
    let state = PocketIcState::new();

    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(state)
        .build_async()
        .await;
    let canister_id = pic.create_canister().await;
    let state = pic.drop_and_take_state().await.unwrap();

    let pic = PocketIcBuilder::new().with_state(state).build_async().await;
    assert!(pic.canister_exists(canister_id).await);
    let state = pic.drop_and_take_state().await.unwrap();

    let path = state.into_path();
    let state = PocketIcState::new_from_path(path);

    let pic1 = PocketIcBuilder::new()
        .with_read_only_state(&state)
        .build_async()
        .await;
    assert!(pic1.canister_exists(canister_id).await);
    pic1.drop().await;

    let pic2 = PocketIcBuilder::new()
        .with_read_only_state(&state)
        .build_async()
        .await;
    assert!(pic2.canister_exists(canister_id).await);
    pic2.drop().await;
}

#[test]
#[should_panic(expected = "PocketIC instance state must be empty if a read-only state is mounted.")]
fn non_empty_state_and_read_only_state() {
    let state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(state)
        .build();
    let _canister_id = pic.create_canister();
    let state = pic.drop_and_take_state().unwrap();

    let read_only_state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(read_only_state)
        .build();
    let _canister_id = pic.create_canister();
    let read_only_state = pic.drop_and_take_state().unwrap();

    let _pic = PocketIcBuilder::new()
        .with_state(state)
        .with_read_only_state(&read_only_state)
        .build();
}

const MAINNET_CANISTER_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);

static POCKET_IC_STATE: OnceLock<PocketIcState> = OnceLock::new();

fn init_state() -> &'static PocketIcState {
    POCKET_IC_STATE.get_or_init(|| {
        // create an empty PocketIC state to be set up later
        let state = PocketIcState::new();
        // create a PocketIC instance used to set up the state
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_state(state)
            .build();

        // set up the state to be used in multiple tests later
        pic.create_canister_with_id(None, None, MAINNET_CANISTER_ID)
            .unwrap();

        // serialize and expose the state
        pic.drop_and_take_state().unwrap()
    })
}

#[test]
fn pocket_ic_init_state_1() {
    // mount the state set up before
    let pic1 = PocketIcBuilder::new()
        .with_read_only_state(init_state())
        .build();

    // assert that the state is properly set up
    assert!(pic1.canister_exists(MAINNET_CANISTER_ID));
}

#[test]
fn pocket_ic_init_state_2() {
    // mount the state set up before
    let pic2 = PocketIcBuilder::new()
        .with_read_only_state(init_state())
        .build();

    // assert that the state is properly set up
    assert!(pic2.canister_exists(MAINNET_CANISTER_ID));
}

#[test]
fn stack_overflow() {
    const STACK_OVERFLOW_WAT: &str = r#"
        (module
            (func $f (export "canister_update foo")
                ;; Define many local variables to quickly overflow the stack
                (local i64) (local i64) (local i64) (local i64) (local i64)
                (local i64) (local i64) (local i64) (local i64) (local i64)
                (local i64) (local i64) (local i64) (local i64) (local i64)
                (local i64) (local i64) (local i64) (local i64) (local i64)
                ;; call "f" recursively
                (call $f)
            )
            (memory 0)
        )
    "#;
    let stack_overflow_wasm = wat::parse_str(STACK_OVERFLOW_WAT).unwrap();

    let pic = PocketIc::new();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, stack_overflow_wasm, vec![], None);

    let err = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "foo",
            encode_one(()).unwrap(),
        )
        .unwrap_err();
    assert!(
        err.reject_message
            .contains("Canister trapped: stack overflow")
    );
}

fn test_specified_id(pic: &PocketIc) {
    // We define a "specified" canister ID that belongs to the canister ranges of a mainnet subnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    // Its hexadecimal representation is `0000000001CFFFFF0101` and thus
    // this is the last canister ID in the default canister ranges of the `0x1C`-th subnet.
    let specified_id = Principal::from_text("jujpo-eqaaa-aaaao-p777q-cai").unwrap();

    let canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_id, specified_id);

    let subnet_id = pic.get_subnet(canister_id).unwrap();
    assert_eq!(
        subnet_id,
        Principal::from_text("o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae")
            .unwrap()
    );
}

#[test]
fn test_specified_id_on_fresh_instance() {
    // create a fresh PocketIC instance
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    test_specified_id(&pic);
}

#[test]
fn test_specified_id_on_resumed_state() {
    // create an empty PocketIC state to be set up later
    let state = PocketIcState::new();
    // create a PocketIC instance used to set up the state
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_state(state)
        .build();
    // serialize the state
    let state = pic.drop_and_take_state().unwrap();

    // create a PocketIC instance resuming from the existing state
    let pic = PocketIcBuilder::new().with_state(state).build();

    test_specified_id(&pic);
}

#[test]
#[should_panic(expected = "is not a (subnet state) directory")]
fn with_subnet_state_file() {
    let state_file = NamedTempFile::new().unwrap();
    let state_file_path_buf = state_file.path().to_path_buf();

    let _pic = PocketIcBuilder::new()
        .with_subnet_state(SubnetKind::Application, state_file_path_buf)
        .build();
}

#[test]
#[should_panic(expected = "Provided an empty state directory at path")]
fn with_empty_subnet_state() {
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    let _pic = PocketIcBuilder::new()
        .with_subnet_state(SubnetKind::Application, state_dir_path_buf)
        .build();
}

#[test]
fn test_invalid_specified_id() {
    // First determine an invalid `specified_id` by creating a canister on a PocketIC instance
    // whose canister ID belongs to the canister allocation ranges of the PocketIC instance.
    let pic = PocketIcBuilder::new().with_application_subnet().build();
    let specified_id = pic.create_canister();
    drop(pic);

    // Now create a fresh PocketIC instance with the same topology.
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // Using the invalid `specified_id` should result in an error.
    let err = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap_err();
    let expected_err = format!(
        "The `specified_id` {specified_id} is invalid because it belongs to the canister allocation ranges of the test environment.\\nUse a `specified_id` that matches a canister ID on the ICP mainnet and a test environment that supports canister creation with `specified_id` (e.g., PocketIC)."
    );
    assert!(err.contains(&expected_err));
}

#[test]
fn with_http_gateway_config_but_no_auto_progress() {
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
        domain_custom_provider_local_file: None,
    };
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_http_gateway(http_gateway_config)
        .build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    let (client, url) = frontend_canister(&pic, canister_id, true, "/asset.txt");
    let resp = client.get(url).send().unwrap();
    assert!(resp.status().is_success());
    let msg = String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap();
    assert_eq!(msg, "My sample asset.");

    assert!(!pic.auto_progress_enabled());
}

// We already have a function `PocketIc::list_instances`,
// but that function does not take a server URL as argument
// (it tries to reuse an existing PocketIC server based on PID).
async fn list_instances(server_url: &Url) -> Vec<String> {
    let url = server_url.join("instances").unwrap();
    reqwest::Client::new()
        .get(url)
        .send()
        .await
        .expect("Failed to get result")
        .json()
        .await
        .expect("Failed to get json")
}

async fn list_http_gateways(server_url: &Url) -> Vec<HttpGatewayDetails> {
    let url = server_url.join("http_gateway").unwrap();
    reqwest::Client::new()
        .get(url)
        .send()
        .await
        .expect("Failed to get result")
        .json()
        .await
        .expect("Failed to get json")
}

#[tokio::test]
async fn with_http_gateway_config_and_cleanup_works() {
    // We start a fresh server so that we can easily list instances and HTTP gateways
    // created by this test (without filtering those created by other tests).
    let server_params = StartServerParams {
        server_binary: None,
        reuse: false,
        ttl: None,
        hard_ttl: None,
    };
    let (_child, server_url) = start_server(server_params).await;

    // Assert that
    // - an instance exists on the server iff `instance_exists` is set to `true`;
    // - the number of HTTP gateways on the server matches `gateway_count`.
    let assert_server_state = |server_url: Url, instance_exists: bool, gateway_count: usize| async move {
        let instances = list_instances(&server_url).await;
        assert_eq!(instances.len(), 1);
        assert!(instances[0].contains("Deleted") != instance_exists);
        assert_eq!(list_http_gateways(&server_url).await.len(), gateway_count);
    };

    // We create a PocketIC instance and its HTTP gateway.
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
        domain_custom_provider_local_file: None,
    };
    let pic = PocketIcBuilder::new()
        .with_server_url(server_url.clone())
        .with_application_subnet()
        .with_http_gateway(http_gateway_config)
        .with_auto_progress()
        .build_async()
        .await;
    assert_server_state(server_url.clone(), true, 1).await;

    // We create an additional handle for the existing PocketIC instance and start an additional HTTP gateway.
    let mut pic_handle =
        PocketIcAsync::new_from_existing_instance(server_url.clone(), pic.instance_id, None);
    pic_handle.make_live(None).await;
    assert_server_state(server_url.clone(), true, 2).await;

    // We create yet another handle for the existing PocketIC instance and start an additional HTTP gateway.
    let mut yet_another_pic_handle =
        PocketIcAsync::new_from_existing_instance(server_url.clone(), pic.instance_id, None);
    yet_another_pic_handle.make_live(None).await;
    assert_server_state(server_url.clone(), true, 3).await;

    // Dropping one of the extra handles for the existing PocketIC instance only stops its new HTTP gateway.
    pic_handle.drop().await;
    assert_server_state(server_url.clone(), true, 2).await;

    // The instance is still in auto progress mode.
    assert!(pic.auto_progress_enabled().await);

    // Dropping the original handle deletes the PocketIC instance and stops all its HTTP gateways.
    pic.drop().await;
    assert_server_state(server_url.clone(), false, 0).await;

    // Dropping the other extra handle for the existing PocketIC instance succeeds, but is a no-op.
    yet_another_pic_handle.drop().await;
    assert_server_state(server_url.clone(), false, 0).await;
}

async fn assert_create_instance_failure(
    server_url: &Url,
    instance_config: InstanceConfig,
    expected_msg: &str,
) {
    // We cannot use `PocketIcBuilder` since we don't want the test to panic at this point.
    let res = reqwest::Client::new()
        .post(server_url.join("instances").unwrap())
        .json(&instance_config)
        .send()
        .await
        .expect("Failed to get result")
        .json::<CreateInstanceResponse>()
        .await
        .expect("Could not parse response for create instance request");
    match res {
        CreateInstanceResponse::Error { message } => {
            assert!(message.contains(expected_msg));
        }
        _ => panic!("Unexpected result: {res:?}"),
    };
}

#[tokio::test]
async fn with_http_gateway_config_invalid_instance_config() {
    let server_params = StartServerParams {
        server_binary: None,
        reuse: false,
        ttl: None,
        hard_ttl: None,
    };
    let (_child, server_url) = start_server(server_params).await;

    // We provide an invalid log level.
    let subnet_config_set = SubnetConfigSet {
        application: 1,
        ..Default::default()
    };
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
        domain_custom_provider_local_file: None,
    };
    let auto_progress_config = AutoProgressConfig {
        artificial_delay_ms: None,
    };
    let instance_config = InstanceConfig {
        subnet_config_set: subnet_config_set.into(),
        http_gateway_config: Some(http_gateway_config),
        state_dir: None,
        icp_config: None,
        log_level: Some("invalid".to_string()),
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: None,
        incomplete_state: None,
        initial_time: Some(InitialTime::AutoProgress(auto_progress_config)),
        mainnet_nns_subnet_id: None,
        disable_ingress_validation: None,
    };
    assert_create_instance_failure(&server_url, instance_config, "Failed to parse log level").await;

    // We confirm that there are no instances and HTTP gateways
    // after the failure, i.e., cleanup works.
    let instances = list_instances(&server_url).await;
    assert!(instances.is_empty());
    let http_gateways = list_http_gateways(&server_url).await;
    assert!(http_gateways.is_empty());
}

#[tokio::test]
async fn with_http_gateway_config_invalid_gateway_port() {
    let server_params = StartServerParams {
        server_binary: None,
        reuse: false,
        ttl: None,
        hard_ttl: None,
    };
    let (_child, server_url) = start_server(server_params).await;

    // We first successfully create an instance with an HTTP gateway
    // to later craft an invalid HTTP gateway configuration
    // reusing the same port.
    let mut http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
        domain_custom_provider_local_file: None,
    };
    let pic = PocketIcBuilder::new()
        .with_server_url(server_url.clone())
        .with_application_subnet()
        .with_http_gateway(http_gateway_config.clone())
        .with_auto_progress()
        .build_async()
        .await;

    let instances = list_instances(&server_url).await;
    assert_eq!(instances.len(), 1);
    assert!(!instances[0].contains("Deleted"));
    let http_gateways = list_http_gateways(&server_url).await;
    assert_eq!(http_gateways.len(), 1);

    // We try to bind to the HTTP gateway to the same port which fails.
    let http_gateway_port = http_gateways[0].port;
    http_gateway_config.port = Some(http_gateway_port);
    let subnet_config_set = SubnetConfigSet {
        application: 1,
        ..Default::default()
    };
    let auto_progress_config = AutoProgressConfig {
        artificial_delay_ms: None,
    };
    let instance_config = InstanceConfig {
        subnet_config_set: subnet_config_set.into(),
        http_gateway_config: Some(http_gateway_config),
        state_dir: None,
        icp_config: None,
        log_level: None,
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: None,
        incomplete_state: None,
        initial_time: Some(InitialTime::AutoProgress(auto_progress_config)),
        mainnet_nns_subnet_id: None,
        disable_ingress_validation: None,
    };
    assert_create_instance_failure(&server_url, instance_config, "Failed to bind to address").await;

    // We confirm that there are no new instances and HTTP gateways
    // after the failure, i.e., cleanup works.
    let instances = list_instances(&server_url).await;
    assert_eq!(instances.len(), 1);
    assert!(!instances[0].contains("Deleted"));
    let http_gateways = list_http_gateways(&server_url).await;
    assert_eq!(http_gateways.len(), 1);

    pic.drop().await;
}

#[tokio::test]
async fn with_http_gateway_config_invalid_gateway_https_config() {
    let server_params = StartServerParams {
        server_binary: None,
        reuse: false,
        ttl: None,
        hard_ttl: None,
    };
    let (_child, server_url) = start_server(server_params).await;

    // We provide invalid paths in `HttpsConfig` which makes HTTP gateway creation fail.
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: Some(HttpsConfig {
            cert_path: "".to_string(),
            key_path: "".to_string(),
        }),
        domain_custom_provider_local_file: None,
    };
    let subnet_config_set = SubnetConfigSet {
        application: 1,
        ..Default::default()
    };
    let auto_progress_config = AutoProgressConfig {
        artificial_delay_ms: None,
    };
    let instance_config = InstanceConfig {
        subnet_config_set: subnet_config_set.into(),
        http_gateway_config: Some(http_gateway_config),
        state_dir: None,
        icp_config: None,
        log_level: None,
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: None,
        incomplete_state: None,
        initial_time: Some(InitialTime::AutoProgress(auto_progress_config)),
        mainnet_nns_subnet_id: None,
        disable_ingress_validation: None,
    };
    assert_create_instance_failure(
        &server_url,
        instance_config,
        "TLS config could not be created",
    )
    .await;

    // We confirm that there are no new instances and HTTP gateways
    // after the failure, i.e., cleanup works.
    let instances = list_instances(&server_url).await;
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0], "Deleted"); // an instance was temporarily created, but deleted before returning an error
    let http_gateways = list_http_gateways(&server_url).await;
    assert!(http_gateways.is_empty());
}

#[test]
fn make_live_after_auto_progress() {
    let mut pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_auto_progress()
        .build();
    pic.make_live(None);
}

#[test]
fn canister_not_found() {
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
        domain_custom_provider_local_file: None,
    };
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_http_gateway(http_gateway_config)
        .build();

    // Canister ID that cannot exist on the ICP mainnet.
    let canister_id_not_found =
        Principal::from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01]);
    // Subnet ID that cannot exist in PocketIC (because it is not a self-authenticating principal).
    let subnet_id_not_found = Principal::from_slice(&[42; 29]);

    // API requests for canister via /instances API and proxied through HTTP gateway.
    let instances_url = format!(
        "{}instances/{}/api/v2/canister/{}/read_state",
        pic.get_server_url(),
        pic.instance_id(),
        canister_id_not_found,
    );
    let gateway_url = format!(
        "{}api/v2/canister/{}/read_state",
        pic.url().unwrap(),
        canister_id_not_found,
    );
    for url in [instances_url, gateway_url] {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .send()
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // API requests for subnet via /instances API and proxied through HTTP gateway.
    let instances_url = format!(
        "{}instances/{}/api/v2/subnet/{}/read_state",
        pic.get_server_url(),
        pic.instance_id(),
        subnet_id_not_found,
    );
    let gateway_url = format!(
        "{}api/v2/subnet/{}/read_state",
        pic.url().unwrap(),
        subnet_id_not_found,
    );
    for url in [instances_url, gateway_url] {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .send()
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Frontend request for canister via HTTP gateway.
    let (client, url) = frontend_canister(&pic, canister_id_not_found, false, "/index.html");
    let resp = client.get(url).send().unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn deterministic_registry() {
    let registry_bytes = || {
        // Create a temporary state directory from which the test can retrieve PocketIC registry.
        let state_dir = TempDir::new().unwrap();
        let state_dir_path_buf = state_dir.path().to_path_buf();

        let pocket_ic = PocketIcBuilder::new()
            .with_state_dir(state_dir_path_buf.clone())
            .with_nns_subnet()
            .with_ii_subnet()
            .with_fiduciary_subnet()
            .with_application_subnet()
            .build();
        // On WSL, the registry file is only available after the PocketIC instance is dropped.
        drop(pocket_ic);

        let registry_proto_path = state_dir_path_buf.join("registry.proto");
        std::fs::read(registry_proto_path).unwrap()
    };

    assert_eq!(registry_bytes(), registry_bytes());
}

#[test]
fn fiduciary_subnet_id() {
    let pic = PocketIcBuilder::new().with_fiduciary_subnet().build();

    let subnet_id = pic.topology().get_fiduciary().unwrap();
    assert_eq!(
        subnet_id,
        Principal::from_text("pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae")
            .unwrap()
    );
}

#[test]
fn default_nns_subnet_id() {
    let pic = PocketIcBuilder::new().with_nns_subnet().build();

    let subnet_id = pic.topology().get_nns().unwrap();
    assert_ne!(
        subnet_id,
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap()
    );
}

#[test]
fn mainnet_nns_subnet_id() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_mainnet_nns_subnet_id()
        .build();

    let subnet_id = pic.topology().get_nns().unwrap();
    assert_eq!(
        subnet_id,
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap()
    );
}

/// Used to enumerate subnets with the "free" cost schedule in subnet admins tests.
enum FreeSubnet {
    RentalSubnet,
    CloudEngine,
}

async fn test_subnet_admins(free_subnet: FreeSubnet) {
    // Create a PocketIC instance with a single subnet on the "free" cost schedule.
    let admin = Principal::anonymous();
    let subnet_spec = SubnetSpec::default()
        .with_subnet_admins(vec![admin])
        .with_cost_schedule(CanisterCyclesCostSchedule::Free);
    let config = match free_subnet {
        FreeSubnet::RentalSubnet => ExtendedSubnetConfigSet {
            application: vec![subnet_spec],
            ..Default::default()
        },
        FreeSubnet::CloudEngine => ExtendedSubnetConfigSet {
            cloud_engine: vec![subnet_spec],
            ..Default::default()
        },
    };
    let mut pic = PocketIcBuilder::new_with_config(config).build_async().await;

    // Derive the subnet ID.
    let topology = pic.topology().await;
    let subnet_id = match free_subnet {
        FreeSubnet::RentalSubnet => topology.get_app_subnets()[0],
        FreeSubnet::CloudEngine => topology.get_cloud_engines()[0],
    };

    // Derive an effective canister ID for canister creation.
    let topology = pic.topology().await;
    let config = topology.subnet_configs.get(&subnet_id).unwrap();
    let effective_canister_id: Principal = config.canister_ranges[0].start.clone().into();

    // Create an IC agent to interact with the (live) PocketIC instance.
    let url = pic.make_live(None).await;
    let agent = Agent::builder().with_url(url).build().unwrap();
    agent.fetch_root_key().await.unwrap();

    // Create a canister on the respective subnet via the IC agent.
    let mgr = ManagementCanister::create(&agent);
    let canister_id: Principal = mgr
        .create_canister()
        .with_effective_canister_id(effective_canister_id)
        .await
        .unwrap()
        .0;

    // Check that the canister has been deployed to the respective subnet
    // and has zero balance.
    assert_eq!(topology.get_subnet(canister_id).unwrap(), subnet_id);
    assert_eq!(pic.cycle_balance(canister_id).await, 0);

    // The canister can be installed on the subnet even if it has zero balance.
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None)
        .await;
}

#[tokio::test]
async fn rental_subnet_with_subnet_admins() {
    test_subnet_admins(FreeSubnet::RentalSubnet).await;
}

#[tokio::test]
async fn cloud_engine_with_subnet_admins() {
    test_subnet_admins(FreeSubnet::CloudEngine).await;
}

/// Make an update call with an effective subnet ID (instead of an effective canister ID)
/// using `ic-agent`: the request is routed to the subnet-scoped `/api/v4/subnet/<id>/call`
/// endpoint. Per the IC interface spec, subnet-scoped update calls are only valid for
/// canister creation calls to the management canister.
#[tokio::test]
async fn update_call_with_effective_subnet_id() {
    // Create a PocketIC instance with an NNS subnet (providing an NNS delegation)
    // and an application subnet to be targeted by the effective subnet ID.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let app_subnet = pic.topology().await.get_app_subnets()[0];

    // Create an IC agent to interact with the (live) PocketIC instance.
    let url = pic.make_live(None).await;
    let agent = Agent::builder().with_url(url).build().unwrap();
    agent.fetch_root_key().await.unwrap();

    // Sign an update call to the management canister's `provisional_create_canister_with_cycles`
    // method and submit it routed via the effective subnet ID of the application subnet.
    let arg = Encode!(&ProvisionalCreateCanisterWithCyclesArgs {
        amount: Some(INIT_CYCLES.into()),
        settings: None,
        specified_id: None,
        sender_canister_version: None,
    })
    .unwrap();
    let signed_update = agent
        .update(
            &Principal::management_canister(),
            "provisional_create_canister_with_cycles",
        )
        .with_arg(arg)
        .sign()
        .unwrap();
    let reply = match agent
        .update_signed(EffectiveId::Subnet(app_subnet), signed_update.signed_update)
        .await
        .unwrap()
    {
        CallResponse::Response(reply) => reply,
        CallResponse::Poll(request_id) => {
            agent
                .wait(&request_id, EffectiveId::Subnet(app_subnet))
                .await
                .unwrap()
                .0
        }
    };
    let canister_id = Decode!(&reply, CanisterIdRecord).unwrap().canister_id;

    // The canister has been created on the targeted application subnet.
    assert_eq!(pic.get_subnet(canister_id).await.unwrap(), app_subnet);
}

/// Response type for the management canister's `list_canisters` query method.
#[derive(CandidType, Deserialize)]
struct ListCanistersResult {
    canisters: Vec<ListCanistersRange>,
}

/// A closed range of canister IDs returned by `list_canisters`.
#[derive(CandidType, Deserialize)]
struct ListCanistersRange {
    start: Principal,
    end: Principal,
}

/// Make a query call with an effective subnet ID (instead of an effective canister ID)
/// using `ic-agent`: the request is routed to the subnet-scoped `/api/v3/subnet/<id>/query`
/// endpoint. Per the IC interface spec, subnet-scoped queries are only valid for the
/// `list_canisters` method of the management canister, which in turn is only available on
/// subnets with subnet admins.
#[tokio::test]
async fn query_call_with_effective_subnet_id() {
    // Create a PocketIC instance with a single application subnet on the "free" cost schedule
    // and the anonymous principal (the agent's default identity) as a subnet admin.
    let admin = Principal::anonymous();
    let config = ExtendedSubnetConfigSet {
        application: vec![
            SubnetSpec::default()
                .with_subnet_admins(vec![admin])
                .with_cost_schedule(CanisterCyclesCostSchedule::Free),
        ],
        ..Default::default()
    };
    let mut pic = PocketIcBuilder::new_with_config(config).build_async().await;
    let app_subnet = pic.topology().await.get_app_subnets()[0];

    // Create a canister on the application subnet so that `list_canisters` returns a non-empty range.
    let canister_id = pic.create_canister_on_subnet(None, None, app_subnet).await;

    // Create an IC agent to interact with the (live) PocketIC instance.
    let url = pic.make_live(None).await;
    let agent = Agent::builder().with_url(url).build().unwrap();
    agent.fetch_root_key().await.unwrap();

    // Sign a query call to the management canister's `list_canisters` method and submit it
    // routed via the effective subnet ID of the application subnet.
    let signed_query = agent
        .query(&Principal::management_canister(), "list_canisters")
        .with_arg(Encode!(&()).unwrap())
        .sign()
        .unwrap();
    let reply = agent
        .query_signed(EffectiveId::Subnet(app_subnet), signed_query.signed_query)
        .await
        .unwrap();
    let ranges = Decode!(&reply, ListCanistersResult).unwrap().canisters;

    // The created canister is contained in one of the returned canister ID ranges.
    assert!(
        ranges
            .iter()
            .any(|range| range.start <= canister_id && canister_id <= range.end)
    );
}

/// Make a `read_state` request with an effective subnet ID (instead of an effective canister ID)
/// using `ic-agent`: the request is routed to the subnet-scoped `/api/v3/subnet/<id>/read_state`
/// endpoint. Here we exercise `Agent::fetch_subnet_by_id`, which reads the subnet state tree.
#[tokio::test]
async fn read_state_with_effective_subnet_id() {
    // Create a PocketIC instance with an NNS subnet (providing an NNS delegation)
    // and an application subnet to be targeted by the effective subnet ID.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let app_subnet = pic.topology().await.get_app_subnets()[0];

    // Create a canister on the application subnet.
    let canister_id = pic.create_canister_on_subnet(None, None, app_subnet).await;

    // Create an IC agent to interact with the (live) PocketIC instance.
    let url = pic.make_live(None).await;
    let agent = Agent::builder().with_url(url).build().unwrap();
    agent.fetch_root_key().await.unwrap();

    // Fetch the subnet information via a `read_state` request routed to the subnet-scoped endpoint.
    let subnet = agent.fetch_subnet_by_id(&app_subnet).await.unwrap();

    // The subnet's certified canister ID ranges contain the created canister.
    assert!(subnet.contains_canister(&canister_id));
}

#[test]
#[should_panic(
    expected = "Subnet admins can only be specified for subnet of kind `Application` or `CloudEngine`"
)]
fn subnet_admins_on_nns() {
    // Creating the NNS subnet with subnet admins set (even to an empty list) should fail.
    let subnet_spec = SubnetSpec::default().with_subnet_admins(vec![]);
    let config = ExtendedSubnetConfigSet {
        nns: Some(subnet_spec),
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new_with_config(config).build();
}

#[test]
#[should_panic(
    expected = "Non-default cost schedule can only be specified for subnet of kind `Application` or `CloudEngine`"
)]
fn free_cost_schedule_on_nns() {
    // Creating the NNS subnet with free cost schedule should fail.
    let subnet_spec = SubnetSpec::default().with_cost_schedule(CanisterCyclesCostSchedule::Free);
    let config = ExtendedSubnetConfigSet {
        nns: Some(subnet_spec),
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new_with_config(config).build();
}

#[test]
#[should_panic(
    expected = "Subnet admins can only be specified for subnet with cost schedule of kind `Free`"
)]
fn subnet_admins_on_default_cost_schedule() {
    // Creating a subnet with subnet admins set (even to an empty list) on a default cost schedule should fail.
    let subnet_spec = SubnetSpec::default().with_subnet_admins(vec![]);
    let config = ExtendedSubnetConfigSet {
        application: vec![subnet_spec],
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new_with_config(config).build();
}

#[test]
#[should_panic(
    expected = "Every subnet of kind `CloudEngine` must have cost schedule of kind `Free`"
)]
fn default_cost_schedule_on_cloud_engine() {
    // Creating a cloud engine with the default cost schedule should fail.
    let config = ExtendedSubnetConfigSet {
        cloud_engine: vec![SubnetSpec::default()],
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new_with_config(config).build();
}

#[test]
fn cloud_engine_with_registry() {
    // Regression test: creating a cloud engine subnet with the registry ICP feature enabled
    // must not trigger the registry invariant check failure
    // "is a cloud engine subnet but some nodes do not have reward type 4".
    let icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let subnet_spec = SubnetSpec::default().with_cost_schedule(CanisterCyclesCostSchedule::Free);
    let config = ExtendedSubnetConfigSet {
        nns: Some(SubnetSpec::default()),
        cloud_engine: vec![subnet_spec],
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new_with_config(config)
        .with_icp_features(icp_features)
        .build();
}

#[test]
fn cloud_engine_default_effective_canister_id() {
    // Create a PocketIC instance with a single (cloud) engine and NNS subnet.
    let admin = Principal::anonymous();
    let subnet_spec = SubnetSpec::default()
        .with_subnet_admins(vec![admin])
        .with_cost_schedule(CanisterCyclesCostSchedule::Free);
    let config = ExtendedSubnetConfigSet {
        nns: Some(SubnetSpec::default()),
        cloud_engine: vec![subnet_spec],
        ..Default::default()
    };
    let pic = PocketIcBuilder::new_with_config(config).build();

    // Derive the engine's subnet ID and an effective canister ID for canister creation.
    let topology = pic.topology();
    let cloud_engine = topology.get_cloud_engines()[0];
    let config = topology.subnet_configs.get(&cloud_engine).unwrap();
    let effective_canister_id: Principal = config.canister_ranges[0].start.clone().into();
    let default_effective_canister_id: Principal =
        topology.default_effective_canister_id.clone().into();
    assert_eq!(effective_canister_id, default_effective_canister_id);
}

#[test]
fn test_delete_subnet() {
    // Create a PocketIC instance with an NNS subnet, two application subnets,
    // and the `registry` ICP feature enabled. The `registry` ICP feature is
    // important here: after every operation the server syncs its local registry
    // from the registry canister, and deleting a subnet writes registry records
    // directly to the local registry. Without keeping the registry canister in
    // sync, this sync would loop forever (regression test).
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_icp_features(IcpFeatures {
            registry: Some(IcpFeaturesConfig::DefaultConfig),
            ..Default::default()
        })
        .with_application_subnet()
        .with_application_subnet()
        .build();

    // The subnet hosting the default effective canister ID cannot be deleted, so
    // we keep it (as `subnet_id_1`) and delete the other application subnet.
    let topology = pic.topology();
    let default_effective_canister_id: Principal =
        topology.default_effective_canister_id.clone().into();
    let subnet_id_1 = topology
        .get_subnet(default_effective_canister_id)
        .expect("default effective canister ID must belong to a subnet");
    let subnet_id_2 = topology
        .get_app_subnets()
        .into_iter()
        .find(|subnet_id| *subnet_id != subnet_id_1)
        .expect("there must be a second application subnet");
    assert_ne!(subnet_id_1, subnet_id_2);

    // Deploy test canisters on both subnets.
    let canister_1 = pic.create_canister_on_subnet(None, None, subnet_id_1);
    pic.add_cycles(canister_1, INIT_CYCLES);
    pic.install_canister(canister_1, test_canister_wasm(), vec![], None);

    let canister_2 = pic.create_canister_on_subnet(None, None, subnet_id_2);
    pic.add_cycles(canister_2, INIT_CYCLES);
    pic.install_canister(canister_2, test_canister_wasm(), vec![], None);

    // (1) Verify that ingress message and inter-canister call to canister_2 work.
    let reply = pic
        .update_call(
            canister_2,
            Principal::anonymous(),
            "whoami",
            encode_one(()).unwrap(),
        )
        .expect("ingress call to canister_2 failed before subnet deletion");
    assert_eq!(Decode!(&reply, String).unwrap(), canister_2.to_string());

    let reply = pic
        .update_call(
            canister_1,
            Principal::anonymous(),
            "call_and_get_rejection_code",
            Encode!(&canister_2).unwrap(),
        )
        .expect("inter-canister call via canister_1 failed before subnet deletion");
    assert_eq!(Decode!(&reply, u32).unwrap(), 0);

    // (2) Delete subnet_2.
    pic.delete_subnet(subnet_id_2);

    // (3) Verify that ingress message to canister_2 fails after subnet deletion.
    // The server rejects the message with a 4xx HTTP status (BadIngressMessage), causing the client to panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.update_call(
            canister_2,
            Principal::anonymous(),
            "whoami",
            encode_one(()).unwrap(),
        )
    }));
    assert!(
        result.is_err(),
        "ingress call to canister_2 should fail after subnet deletion"
    );

    // (4) Verify that inter-canister call to canister_2 fails with DestinationInvalid (3).
    let reply = pic
        .update_call(
            canister_1,
            Principal::anonymous(),
            "call_and_get_rejection_code",
            Encode!(&canister_2).unwrap(),
        )
        .expect("inter-canister call via canister_1 should succeed");
    assert_eq!(
        Decode!(&reply, u32).unwrap(),
        RejectCode::DestinationInvalid as u32
    );
}

#[test]
fn test_delete_default_effective_canister_id_subnet_fails() {
    // Create a PocketIC instance with one NNS subnet and two application subnets.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    let topology = pic.topology();
    let default_effective_canister_id =
        Principal::from(topology.default_effective_canister_id.clone());

    // Identify which app subnet contains the default effective canister ID.
    let default_subnet_id = topology
        .get_subnet(default_effective_canister_id)
        .expect("default effective canister ID must belong to a subnet");
    let other_subnet_id = topology
        .get_app_subnets()
        .into_iter()
        .find(|&id| id != default_subnet_id)
        .expect("there must be a second app subnet");

    // The app subnet containing the default effective canister ID cannot be deleted.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.delete_subnet(default_subnet_id);
    }));
    assert!(
        result.is_err(),
        "deleting the subnet containing the default effective canister ID should fail"
    );

    // The other app subnet can be deleted.
    pic.delete_subnet(other_subnet_id);
    assert_eq!(pic.topology().get_app_subnets(), vec![default_subnet_id]);
}

#[test]
fn test_delete_named_subnet_fails() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .build();

    let nns_subnet_id = pic.topology().get_nns().unwrap();
    let fiduciary_subnet_id = pic.topology().get_fiduciary().unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.delete_subnet(nns_subnet_id);
    }));
    assert!(result.is_err(), "deleting NNS subnet should fail");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.delete_subnet(fiduciary_subnet_id);
    }));
    assert!(result.is_err(), "deleting fiduciary subnet should fail");
}

#[test]
fn test_delete_root_app_subnet_fails() {
    // Create a PocketIC instance with a single application subnet.
    // The first subnet created becomes the root subnet and cannot be deleted.
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    let app_subnet_id = pic.topology().get_app_subnets()[0];

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pic.delete_subnet(app_subnet_id);
    }));
    assert!(result.is_err(), "deleting the root app subnet should fail");
}

#[test]
fn test_delete_subnet_state_dir() {
    let state_dir = TempDir::new().unwrap();
    let state_dir_path = state_dir.path().to_path_buf();

    // Create two application subnets so that we can delete the one that does not
    // host the default effective canister ID (the subnet hosting it cannot be
    // deleted).
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    let subnet_dirs_count = || {
        std::fs::read_dir(&state_dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .count()
    };

    let topology = pic.topology();
    let default_effective_canister_id: Principal =
        topology.default_effective_canister_id.clone().into();
    let default_subnet_id = topology
        .get_subnet(default_effective_canister_id)
        .expect("default effective canister ID must belong to a subnet");
    let other_subnet_id = topology
        .get_app_subnets()
        .into_iter()
        .find(|&id| id != default_subnet_id)
        .expect("there must be a second application subnet");

    // On Windows, the state_dir is only synced back from the WSL-native state directory on drop.
    #[cfg(not(windows))]
    assert_eq!(subnet_dirs_count(), 3);

    pic.delete_subnet(other_subnet_id);
    assert_eq!(pic.topology().get_app_subnets(), vec![default_subnet_id]);

    // Drop to flush state to disk.
    drop(pic);

    // After deletion, only the NNS subnet's and the remaining application subnet's
    // state directories should exist.
    assert_eq!(subnet_dirs_count(), 2);
}
