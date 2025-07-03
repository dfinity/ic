mod common;

use crate::common::raw_canister_id_range_into;
use candid::Principal;
use ic_registry_routing_table::{canister_id_into_u64, CanisterIdRange};
use ic_registry_subnet_type::SubnetType;
use pocket_ic::PocketIcBuilder;
use rcgen::{CertificateParams, KeyPair};
use spec_compliance::run_ic_ref_test;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

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

// `httpbin_https` can only be set to `true` in a single test
fn setup_and_run_ic_ref_test(
    test_nns: bool,
    httpbin_https: bool,
    excluded_tests: Vec<&str>,
    included_tests: Vec<&str>,
) {
    // start httpbin webserver to test canister http outcalls
    let httpbin_path = std::env::var_os("HTTPBIN_BIN").expect("Missing httpbin binary path");
    let mut cmd = Command::new(httpbin_path);
    let port_file = NamedTempFile::new().unwrap();
    let port_file_path = port_file.path().to_path_buf();
    cmd.arg("--port-file")
        .arg(port_file_path.as_os_str().to_str().unwrap());

    if httpbin_https {
        // generate root TLS certificate
        let root_key_pair = KeyPair::generate().unwrap();
        let root_cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&root_key_pair)
            .unwrap();
        let (mut cert_file, cert_path) = NamedTempFile::new().unwrap().keep().unwrap();
        cert_file.write_all(root_cert.pem().as_bytes()).unwrap();
        let (mut key_file, key_path) = NamedTempFile::new().unwrap().keep().unwrap();
        key_file
            .write_all(root_key_pair.serialize_pem().as_bytes())
            .unwrap();

        // set `SSL_CERT_FILE` so that the canister http outcalls adapter accepts the self-signed certificate
        // (this affects all tests and thus `httbin_https` should only be set to `true` in a single test)
        std::env::set_var("SSL_CERT_FILE", cert_path.clone());
        std::env::remove_var("NIX_SSL_CERT_FILE");

        cmd.arg("--cert-file").arg(cert_path);
        cmd.arg("--key-file").arg(key_path);
    }

    let mut process = cmd
        .stdout(Stdio::inherit())
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
            break format!("localhost:{}", port);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // create live PocketIc instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build();
    let endpoint = pic.make_live(None);
    let topo = pic.topology();
    let app_subnet_id = topo.get_app_subnets()[0];
    let app_config = topo.subnet_configs.get(&app_subnet_id).unwrap();
    let app_node_ids = app_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();
    let nns_subnet_id = topo.get_nns().unwrap();
    let nns_config = topo.subnet_configs.get(&nns_subnet_id).unwrap();
    let nns_node_ids = nns_config
        .node_ids
        .iter()
        .map(|n| Principal::from_slice(&n.node_id))
        .collect();

    let ic_ref_test_path = std::env::var_os("IC_REF_TEST_BIN")
        .expect("Missing ic-ref-test")
        .into_string()
        .unwrap()
        .into();

    // derive artifact paths
    let ic_ref_test_root = std::env::var_os("IC_REF_TEST_ROOT")
        .expect("Missing ic-hs directory")
        .into_string()
        .unwrap();
    let root_dir = std::path::PathBuf::from(ic_ref_test_root);
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

    let httpbin_proto = if httpbin_https {
        Some("https://".to_string())
    } else {
        Some("http://".to_string())
    };
    run_ic_ref_test(
        httpbin_proto,
        Some(httpbin_url),
        ic_ref_test_path,
        ic_test_data_path,
        endpoint.to_string(),
        test_subnet_config,
        peer_subnet_config,
        excluded_tests,
        included_tests,
        32,
    );

    process.kill().unwrap();
    process.wait().unwrap();
}

#[test]
fn ic_ref_test_nns() {
    setup_and_run_ic_ref_test(true, false, EXCLUDED.to_vec(), vec![])
}

#[test]
fn ic_ref_test_app() {
    setup_and_run_ic_ref_test(false, true, EXCLUDED.to_vec(), vec![])
}

#[test]
fn ic_ref_test_canister_http() {
    setup_and_run_ic_ref_test(
        false,
        false,
        EXCLUDED.to_vec(),
        vec!["$0 ~ /canister http/"],
    )
}
