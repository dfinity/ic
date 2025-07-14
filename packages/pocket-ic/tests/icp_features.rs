use candid::{CandidType, Principal};
use pocket_ic::common::rest::{ExtendedSubnetConfigSet, IcpFeatures, InstanceConfig, SubnetSpec};
use pocket_ic::{start_or_reuse_server, update_candid, PocketIc, PocketIcBuilder, PocketIcState};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::BTreeMap;
use tempfile::TempDir;
#[cfg(windows)]
use wslpath::windows_to_wsl;

#[test]
fn with_all_icp_features() {
    let _pic = PocketIcBuilder::new().with_all_icp_features().build();
}

#[derive(CandidType, Deserialize)]
struct IcpXdrConversionRate {
    timestamp_seconds: u64,
    xdr_permyriad_per_icp: u64,
}

fn get_icp_exchange_rate(pic: &PocketIc) -> IcpXdrConversionRate {
    #[derive(CandidType, Deserialize)]
    struct IcpXdrConversionRateResponse {
        data: IcpXdrConversionRate,
        hash_tree: Vec<u8>,
        certificate: Vec<u8>,
    }

    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    update_candid::<_, (IcpXdrConversionRateResponse,)>(
        pic,
        cmc_id,
        "get_icp_xdr_conversion_rate",
        (),
    )
    .unwrap()
    .0
    .data
}

fn get_authorized_subnets(pic: &PocketIc) -> Vec<Principal> {
    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    update_candid::<_, (Vec<Principal>,)>(pic, cmc_id, "get_default_subnets", ())
        .unwrap()
        .0
}

fn get_subnet_types(pic: &PocketIc) -> BTreeMap<String, Vec<Principal>> {
    #[derive(CandidType, Deserialize)]
    pub struct SubnetTypesToSubnetsResponse {
        pub data: BTreeMap<String, Vec<Principal>>,
    }

    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    update_candid::<_, (SubnetTypesToSubnetsResponse,)>(
        pic,
        cmc_id,
        "get_subnet_types_to_subnets",
        (),
    )
    .unwrap()
    .0
    .data
}

fn check_cmc_state(pic: &PocketIc, expect_fiduciary: bool) {
    // check XDR exchange rate
    // these values are hard-coded in the PocketIC server implementation
    // including steps how they were obtained
    let icp_exchange_rate = get_icp_exchange_rate(pic);
    assert_eq!(icp_exchange_rate.timestamp_seconds, 1_751_617_980);
    assert_eq!(icp_exchange_rate.xdr_permyriad_per_icp, 35_200);

    // check authorized (application) subnets
    let mut authorized_subnets = get_authorized_subnets(pic);
    authorized_subnets.sort();
    let mut app_subnets = pic.topology().get_app_subnets();
    app_subnets.sort();
    assert_eq!(authorized_subnets, app_subnets);

    // check fiduciary subnet
    assert_eq!(pic.topology().get_fiduciary().is_some(), expect_fiduciary);
    let subnet_types = get_subnet_types(pic);
    let subnet_types_len = if expect_fiduciary { 1 } else { 0 };
    assert_eq!(subnet_types.len(), subnet_types_len);
    let fiduciary_subnet_ids = pic
        .topology()
        .get_fiduciary()
        .map(|subnet_id| vec![subnet_id]);
    assert_eq!(subnet_types.get("fiduciary").cloned(), fiduciary_subnet_ids);
}

#[test]
fn test_cmc_fiduciary_subnet() {
    let pic = PocketIcBuilder::new()
        .with_fiduciary_subnet()
        .with_all_icp_features()
        .build();

    check_cmc_state(&pic, true);
}

#[test]
fn test_cmc_fiduciary_subnet_creation() {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_all_icp_features()
        .build();

    check_cmc_state(&pic, false);

    create_mainnet_subnet(&pic, 0x23); // fiduciary subnet

    check_cmc_state(&pic, true);
}

#[test]
fn test_cmc_state() {
    let state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_fiduciary_subnet()
        .with_all_icp_features()
        .with_state(state)
        .build();

    check_cmc_state(&pic, true);

    for i in 1..3 {
        create_mainnet_subnet(&pic, i);
        check_cmc_state(&pic, true);
    }

    // Restart the instance from its state.
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    check_cmc_state(&pic, true);

    for i in 3..5 {
        create_mainnet_subnet(&pic, i);
        check_cmc_state(&pic, true);
    }
}

fn create_mainnet_subnet(pic: &PocketIc, i: u64) {
    // We derive a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    // That "specified" canister ID has the form: <i> 00000 01 01,
    // i.e., it is the first canister ID on the <i>-th subnet.
    let mut slice = [0_u8; 10];
    slice[..8].copy_from_slice(&(i << 20).to_be_bytes());
    slice[8] = 0x01;
    slice[9] = 0x01;
    let specified_id = Principal::from_slice(&slice);
    assert!(pic.get_subnet(specified_id).is_none());

    let num_subnets = pic.topology().subnet_configs.len();

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_id, specified_id);
    pic.get_subnet(specified_id).unwrap();

    assert_eq!(pic.topology().subnet_configs.len(), num_subnets + 1);
}

#[test]
fn registry_after_instance_restart() {
    // Create a PocketIC instance with NNS, SNS, II, fiduciary, bitcoin,
    // 5 application, and 5 system subnets
    // (a sufficiently high number so that the order of their creation
    // is different from the order of their subnet IDs and
    // other hash-based footprints).
    let state = PocketIcState::new();
    let mut builder = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .with_bitcoin_subnet();
    for _ in 0..5 {
        builder = builder.with_application_subnet();
        builder = builder.with_system_subnet();
    }
    let pic = builder.with_state(state).build();

    // Create 10 more application subnets dynamically after the instance has already been created.
    for i in 1..=10_u64 {
        create_mainnet_subnet(&pic, i);
    }

    // Restart the instance (failures to restore the registry
    // would result in a panic when restarting the instance).
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    // Create 10 more application subnets dynamically after the instance has already been restarted.
    for i in 11..=20_u64 {
        create_mainnet_subnet(&pic, i);
    }

    // Restart the instance (failures to restore the registry
    // would result in a panic when restarting the instance).
    let state = pic.drop_and_take_state().unwrap();
    let _pic = PocketIcBuilder::new().with_state(state).build();
}

fn get_subnet_from_registry(pic: &PocketIc, canister_id: Principal) -> Principal {
    #[derive(CandidType)]
    pub struct GetSubnetForCanisterRequest {
        pub principal: Option<Principal>,
    }
    #[derive(CandidType, Deserialize)]
    pub struct SubnetForCanister {
        pub subnet_id: Option<Principal>,
    }

    let registry_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    update_candid::<_, (Result<SubnetForCanister, String>,)>(
        pic,
        registry_canister_id,
        "get_subnet_for_canister",
        (GetSubnetForCanisterRequest {
            principal: Some(canister_id),
        },),
    )
    .unwrap()
    .0
    .unwrap()
    .subnet_id
    .unwrap()
}

#[test]
fn read_registry() {
    let state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_all_icp_features()
        .with_state(state)
        .build();

    let subnet_0 = pic.topology().get_app_subnets()[0];
    let canister_0 = pic.create_canister_on_subnet(None, None, subnet_0);
    assert_eq!(get_subnet_from_registry(&pic, canister_0), subnet_0);

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_1 = Principal::from_text("v7pvf-xyaaa-aaaao-aaaaa-cai").unwrap();
    assert!(pic.get_subnet(specified_1).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_1 = pic
        .create_canister_with_id(None, None, specified_1)
        .unwrap();
    assert_eq!(canister_1, specified_1);
    let subnet_1 = pic.get_subnet(specified_1).unwrap();
    assert_ne!(subnet_0, subnet_1);

    // Check that the subnet from the registry matches
    // the subnet from the PocketIC topology.
    assert_eq!(get_subnet_from_registry(&pic, canister_1), subnet_1);

    // Restart the instance from its state.
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    // Check that the registry contains the expected associations of canisters to subnets.
    assert_eq!(get_subnet_from_registry(&pic, canister_0), subnet_0);
    assert_eq!(get_subnet_from_registry(&pic, canister_1), subnet_1);

    // We define another "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_2 = Principal::from_text("z474k-xiaaa-aaaao-qaaaa-cai").unwrap();

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_2 = pic
        .create_canister_with_id(None, None, specified_2)
        .unwrap();
    assert_eq!(canister_2, specified_2);
    let subnet_2 = pic.get_subnet(specified_2).unwrap();
    assert_ne!(subnet_0, subnet_2);
    assert_ne!(subnet_1, subnet_2);

    // Check that the subnet from the registry matches
    // the subnet from the PocketIC topology.
    assert_eq!(get_subnet_from_registry(&pic, canister_2), subnet_2);
}

#[test]
#[should_panic(
    expected = "The NNS subnet must be empty when specifying the `registry` ICP feature."
)]
fn with_all_icp_features_and_nns_state() {
    let state_dir = TempDir::new().unwrap();
    #[cfg(not(windows))]
    let state_dir_path_buf = state_dir.path().to_path_buf();
    #[cfg(windows)]
    let state_dir_path_buf = windows_to_wsl(state_dir.path().as_os_str().to_str().unwrap())
        .unwrap()
        .into();

    let _pic = PocketIcBuilder::new()
        .with_all_icp_features()
        .with_nns_state(state_dir_path_buf)
        .build();
}

#[tokio::test]
async fn with_all_icp_features_and_nns_subnet_state() {
    let state_dir = TempDir::new().unwrap();
    #[cfg(not(windows))]
    let state_dir_path_buf = state_dir.path().to_path_buf();
    #[cfg(windows)]
    let state_dir_path_buf = windows_to_wsl(state_dir.path().as_os_str().to_str().unwrap())
        .unwrap()
        .into();

    let url = start_or_reuse_server(None).await;
    let client = reqwest::Client::new();
    let instance_config = InstanceConfig {
        subnet_config_set: ExtendedSubnetConfigSet {
            nns: Some(SubnetSpec::default().with_state_dir(state_dir_path_buf)),
            ..Default::default()
        },
        state_dir: None,
        nonmainnet_features: false,
        log_level: None,
        bitcoind_addr: None,
        icp_features: Some(IcpFeatures::all_icp_features()),
    };
    let response = client
        .post(url.join("instances").unwrap())
        .json(&instance_config)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.text().await.unwrap().contains("Subnet config failed to validate: The NNS subnet must be empty when specifying the `registry` ICP feature."));
}
