use candid::Principal;
use ic_registry_routing_table::CanisterIdRange;
use ic_types::PrincipalId;
use pocket_ic::common::rest::{
    CanisterIdRange as RawCanisterIdRange, CreateInstanceResponse, DtsFlag,
    ExtendedSubnetConfigSet, InstanceId, RawTime, SubnetConfig, SubnetConfigSet, SubnetId,
};
use reqwest::blocking::Client;
use reqwest::{StatusCode, Url};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime};

pub const LOCALHOST: &str = "127.0.0.1";

pub fn raw_canister_id_range_into(r: &RawCanisterIdRange) -> CanisterIdRange {
    CanisterIdRange {
        start: PrincipalId(Principal::from_slice(&r.start.canister_id))
            .try_into()
            .unwrap(),
        end: PrincipalId(Principal::from_slice(&r.end.canister_id))
            .try_into()
            .unwrap(),
    }
}

pub fn start_server_helper(
    parent_pid: u32,
    ttl: Option<u64>,
    capture_stderr: bool,
) -> (Url, Child) {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let mut cmd = Command::new(PathBuf::from(bin_path));
    cmd.arg("--pid").arg(parent_pid.to_string());
    if let Some(ttl) = ttl {
        cmd.arg("--ttl").arg(ttl.to_string());
    }
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.spawn().expect("Failed to start PocketIC binary");
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
    let start = Instant::now();
    let url = loop {
        match ready_file_path.try_exists() {
            Ok(true) => {
                let port_string = std::fs::read_to_string(port_file_path)
                    .expect("Failed to read port from port file");
                let port: u16 = port_string.parse().expect("Failed to parse port to number");
                break Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    };
    (url, out)
}

pub fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    start_server_helper(parent_pid, None, false).0
}

pub fn create_live_instance(
    url: &Url,
    client: &Client,
    dts_flag: DtsFlag,
) -> (InstanceId, SubnetId, SubnetConfig, SubnetId, SubnetConfig) {
    let subnet_config_set = SubnetConfigSet {
        nns: true,
        application: 1,
        ..Default::default()
    };
    let mut extended_subnet_config_set: ExtendedSubnetConfigSet = subnet_config_set.into();
    extended_subnet_config_set = extended_subnet_config_set.with_dts_flag(dts_flag);
    let response = client
        .post(url.join("instances").unwrap())
        .json(&extended_subnet_config_set)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response_json: CreateInstanceResponse = response.json().unwrap();
    let CreateInstanceResponse::Created {
        instance_id,
        topology,
    } = response_json
    else {
        panic!("instance must be created");
    };

    // set time of the IC instance to the current time
    let time_url = url
        .join(&format!("instances/{instance_id}/update/set_time"))
        .unwrap();
    let now = std::time::SystemTime::now();
    let body = RawTime {
        nanos_since_epoch: now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos() as u64,
    };
    client.post(time_url.clone()).json(&body).send().unwrap();

    // set auto_progress on the IC instance
    let progress_url = url
        .join(&format!("instances/{instance_id}/auto_progress",))
        .unwrap();
    client.post(progress_url).send().unwrap();

    let nns_subnet_id = topology.get_nns().unwrap();
    let nns_config = topology.0.get(&nns_subnet_id).unwrap();
    let app_subnet_id = topology.get_app_subnets()[0];
    let app_config = topology.0.get(&app_subnet_id).unwrap();

    (
        instance_id,
        nns_subnet_id,
        nns_config.clone(),
        app_subnet_id,
        app_config.clone(),
    )
}
