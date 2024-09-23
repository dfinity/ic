mod common;

use crate::common::raw_canister_id_range_into;
use candid::Principal;
use ic_registry_routing_table::{canister_id_into_u64, CanisterIdRange};
use ic_registry_subnet_type::SubnetType;
use pocket_ic::common::rest::DtsFlag;
use pocket_ic::PocketIcBuilder;
use spec_compliance::run_ic_ref_test;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const LOCALHOST: &str = "127.0.0.1";

const EXCLUDED: &[&str] = &[
    // we do not enforce https in PocketIC
    "$0 ~ /url must start with https:/",
    // replica issues
    "$0 ~ /wrong effective canister id.in management call/",
    "$0 ~ /access denied with different effective canister id/",
    "$0 ~ /Call from query method traps (in query call)/",
];

fn subnet_config(
    subnet_id: Principal,
    subnet_type: SubnetType,
    node_ids: Vec<Principal>,
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
        node_ids
            .into_iter()
            .map(|n| format!("\"{}\"", n))
            .collect::<Vec<String>>()
            .join(","),
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

fn setup_and_run_ic_ref_test(test_nns: bool, excluded_tests: Vec<&str>, included_tests: Vec<&str>) {
    // start httpbin webserver to test canister HTTP outcalls
    let httpbin_path = std::env::var_os("HTTPBIN_BIN").expect("Missing httpbin binary path");
    let mut cmd = Command::new(httpbin_path);
    let port_file = NamedTempFile::new().unwrap();
    let port_file_path = port_file.path().to_path_buf();
    cmd.arg("--port-file")
        .arg(port_file_path.as_os_str().to_str().unwrap());
    cmd.stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("httpbin binary crashed");
    let httpbin_url = loop {
        let port_string = std::fs::read_to_string(port_file_path.clone())
            .expect("Failed to read port from port file");
        if !port_string.is_empty() {
            let port: u16 = port_string
                .trim_end()
                .parse()
                .expect("Failed to parse port to number");
            break format!("{}:{}", LOCALHOST, port);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // create live PocketIc instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_dts_flag(DtsFlag::Disabled)
        .build();
    let endpoint = pic.make_live(None);
    let topo = pic.topology();
    let app_subnet_id = topo.get_app_subnets()[0];
    let app_config = topo.0.get(&app_subnet_id).unwrap();
    let app_node_ids = app_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();
    let nns_subnet_id = topo.get_nns().unwrap();
    let nns_config = topo.0.get(&nns_subnet_id).unwrap();
    let nns_node_ids = nns_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();

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
    let nns_canister_ranges = nns_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let nns_subnet_config = subnet_config(
        nns_subnet_id,
        SubnetType::System,
        nns_node_ids,
        nns_canister_ranges,
    );

    // app subnet config
    let app_canister_ranges = app_config
        .canister_ranges
        .iter()
        .map(raw_canister_id_range_into)
        .collect();
    let app_subnet_config = subnet_config(
        app_subnet_id,
        SubnetType::Application,
        app_node_ids,
        app_canister_ranges,
    );

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
        Some("http://".to_string()),
        Some(httpbin_url),
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

#[test]
fn ic_ref_test_nns() {
    setup_and_run_ic_ref_test(true, EXCLUDED.to_vec(), vec![])
}

#[test]
fn ic_ref_test_app() {
    setup_and_run_ic_ref_test(false, EXCLUDED.to_vec(), vec![])
}
