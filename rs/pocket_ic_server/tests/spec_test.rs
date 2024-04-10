mod common;

use crate::common::{create_live_instance, raw_canister_id_range_into, start_server};
use candid::Principal;
use ic_registry_routing_table::{canister_id_into_u64, CanisterIdRange};
use ic_registry_subnet_type::SubnetType;
use pocket_ic::common::rest::DtsFlag;
use reqwest::blocking::Client;
use spec_compliance::run_ic_ref_test;

const EXCLUDED: &[&str] = &[
    // blocked on canister https outcalls in PocketIC
    "$0 ~ /canister http outcalls/",
    // replica issues
    "$0 ~ /wrong effective canister id.in management call/",
    "$0 ~ /access denied with different effective canister id/",
    "$0 ~ /Call from query method traps (in query call)/",
];

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

fn setup_and_run_ic_ref_test(test_nns: bool, excluded_tests: Vec<&str>, included_tests: Vec<&str>) {
    let url = start_server();
    let client = Client::new();
    let (instance_id, nns_subnet_id, nns_config, app_subnet_id, app_config) =
        create_live_instance(&url, &client, DtsFlag::Disabled);
    let endpoint = url.join(&format!("instances/{instance_id}/")).unwrap();

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
    let nns_subnet_config = subnet_config(nns_subnet_id, SubnetType::System, nns_canister_ranges);

    // app subnet config
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
