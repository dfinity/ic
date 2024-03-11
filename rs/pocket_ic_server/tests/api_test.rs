use candid::Principal;
use ic_registry_routing_table::{canister_id_into_u64, CanisterIdRange};
use ic_registry_subnet_type::SubnetType;
use ic_types::PrincipalId;
use pocket_ic::common::rest::{
    CanisterIdRange as RawCanisterIdRange, CreateInstanceResponse, RawTime, SubnetConfigSet,
    Topology,
};
use reqwest::blocking::Client;
use reqwest::{StatusCode, Url};
use spec_compliance::run_ic_ref_test;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

const LOCALHOST: &str = "127.0.0.1";

#[test]
fn test_status() {
    let url = start_server();
    let client = Client::new();

    let response = client.get(url.join("status/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn test_creation_of_instance_extended() {
    use pocket_ic::common::rest::ExtendedSubnetConfigSet;
    let url = start_server();
    let client = Client::new();
    let response = client
        .post(url.join("instances").unwrap())
        .json(&Into::<ExtendedSubnetConfigSet>::into(SubnetConfigSet {
            application: 1,
            ..Default::default()
        }))
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(!response.text().unwrap().is_empty());
}

#[test]
fn test_blob_store() {
    let url = start_server();
    let client = Client::new();
    let blob_1 = "decafbad".as_bytes();
    let blob_2 = "deadbeef".as_bytes();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob_1)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let blob_id_1 = response.text().unwrap();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob_2)
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let blob_id_2 = response.text().unwrap();

    let response = client
        .get(url.join(&format!("blobstore/{blob_id_1}")).unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert!(response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_none());

    let blob = response.bytes().unwrap();
    assert_eq!(blob, "decafbad".as_bytes());

    let response = client
        .get(url.join(&format!("blobstore/{blob_id_2}")).unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let header = response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .unwrap()
        .as_bytes();
    assert_eq!(header, b"gzip");

    let blob = response.bytes().unwrap();
    assert_eq!(blob, "deadbeef".as_bytes());

    let nonexistent_blob_id = "does not exist".to_owned();
    let response = client
        .get(
            url.join(&format!("blobstore/{nonexistent_blob_id}"))
                .unwrap(),
        )
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_blob_store_wrong_encoding() {
    let url = start_server();
    let client = Client::new();
    let blob = "decafbad".as_bytes();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob)
        .header(reqwest::header::CONTENT_ENCODING, "bad_encoding")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .unwrap()
        .to_lowercase()
        .contains("bad encoding"));
}

const EXCLUDED: &[&str] = &[
    // blocked on canister https outcalls in PocketIC
    "$0 ~ /canister http outcalls/",
    // replica issues
    "$0 ~ /wrong effective canister id.in management call/",
    "$0 ~ /access denied with different effective canister id/",
    "$0 ~ /Call from query method traps (in query call)/",
];

#[test]
fn ic_ref_test_nns_group_01() {
    let mut excluded = vec!["$0 ~ /API availability/"];
    excluded.append(&mut EXCLUDED.to_vec());
    setup_and_run_ic_ref_test(true, excluded, vec![])
}

#[test]
fn ic_ref_test_nns_group_02() {
    setup_and_run_ic_ref_test(true, EXCLUDED.to_vec(), vec!["$0 ~ /API availability/"])
}

#[test]
fn ic_ref_test_app_group_01() {
    let mut excluded = vec!["$0 ~ /API availability/"];
    excluded.append(&mut EXCLUDED.to_vec());
    setup_and_run_ic_ref_test(false, excluded, vec![])
}

#[test]
fn ic_ref_test_app_group_02() {
    setup_and_run_ic_ref_test(false, EXCLUDED.to_vec(), vec!["$0 ~ /API availability/"])
}

fn subnet_config(
    subnet_id: Principal,
    subnet_type: SubnetType,
    canister_ranges: Vec<CanisterIdRange>,
) -> String {
    format!(
        "(\"{}\",{},[{}],[{}],[])",
        subnet_id,
        match subnet_type {
            SubnetType::VerifiedApplication => "verified_application",
            SubnetType::Application => "application",
            SubnetType::System => "system",
        },
        "",
        canister_ranges
            .iter()
            .map(|r| format!(
                "({},{})",
                canister_id_into_u64(r.start),
                canister_id_into_u64(r.end)
            ))
            .collect::<Vec<String>>()
            .join(","),
    )
}

fn raw_canister_id_range_into(r: &RawCanisterIdRange) -> CanisterIdRange {
    CanisterIdRange {
        start: PrincipalId(Principal::from_slice(&r.start.canister_id))
            .try_into()
            .unwrap(),
        end: PrincipalId(Principal::from_slice(&r.end.canister_id))
            .try_into()
            .unwrap(),
    }
}

fn setup_and_run_ic_ref_test(test_nns: bool, excluded_tests: Vec<&str>, included_tests: Vec<&str>) {
    let url = start_server();
    let client = Client::new();
    let (instance_id, topo) = create_instance(
        &client,
        &url,
        &SubnetConfigSet {
            nns: true,
            application: 1,
            ..Default::default()
        },
    );
    let endpoint = url.join(&format!("instances/{instance_id}/")).unwrap();

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

    // derive artifact paths
    let ic_ref_test_root = std::env::var_os("IC_REF_TEST_ROOT")
        .expect("Missing ic-hs directory")
        .into_string()
        .unwrap();
    let root_dir = std::path::PathBuf::from(ic_ref_test_root);
    let mut ic_ref_test_path = root_dir.clone();
    ic_ref_test_path.push("bin");
    ic_ref_test_path.push("ic-ref-test");
    let mut ic_test_data_path = root_dir.clone();
    ic_test_data_path.push("test-data");

    // NNS subnet config
    let nns_subnet_id = topo.get_nns().unwrap();
    let nns_config = topo.0.get(&nns_subnet_id).unwrap();
    let nns_canister_ranges = nns_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let nns_subnet_config = subnet_config(nns_subnet_id, SubnetType::System, nns_canister_ranges);

    // app subnet config
    let app_subnet_id = topo.get_app_subnets()[0];
    let app_config = topo.0.get(&app_subnet_id).unwrap();
    let app_canister_ranges = app_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let app_subnet_config =
        subnet_config(app_subnet_id, SubnetType::Application, app_canister_ranges);

    // decide on which subnet to test
    let test_subnet_config = if test_nns {
        nns_subnet_config.clone()
    } else {
        app_subnet_config.clone()
    };
    let peer_subnet_config = if test_nns {
        app_subnet_config
    } else {
        nns_subnet_config
    };

    run_ic_ref_test(
        None,
        ic_ref_test_path.into_os_string().into_string().unwrap(),
        ic_test_data_path,
        endpoint.to_string(),
        test_subnet_config,
        peer_subnet_config,
        excluded_tests,
        included_tests,
        16,
    );
}

fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    Command::new(PathBuf::from(bin_path))
        .arg("--pid")
        .arg(parent_pid.to_string())
        .spawn()
        .expect("Failed to start PocketIC binary");
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
    let start = Instant::now();
    loop {
        match ready_file_path.try_exists() {
            Ok(true) => {
                let port_string = std::fs::read_to_string(port_file_path)
                    .expect("Failed to read port from port file");
                let port: u16 = port_string.parse().expect("Failed to parse port to number");
                return Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    }
}

fn create_instance(
    client: &Client,
    url: &Url,
    subnet_config_set: &SubnetConfigSet,
) -> (usize, Topology) {
    use pocket_ic::common::rest::ExtendedSubnetConfigSet;
    let response = client
        .post(url.join("instances").unwrap())
        .json(&Into::<ExtendedSubnetConfigSet>::into(
            subnet_config_set.clone(),
        ))
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
    (instance_id, topology)
}
