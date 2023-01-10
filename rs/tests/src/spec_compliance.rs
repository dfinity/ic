use crate::canister_http::lib::{
    get_pem_content, get_universal_vm_activation_script, get_universal_vm_address, PemType,
};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasDependencies, HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    SubnetSnapshot, TopologySnapshot,
};
use crate::driver::universal_vm::{insert_file_to_config, UniversalVm, UniversalVms};
use ic_registry_routing_table::canister_id_into_u64;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::SubnetId;
use slog::{info, Logger};
use std::process::{Command, Stdio};

pub const UNIVERSAL_VM_NAME: &str = "httpbin";

const REPLICATION_FACTOR: usize = 2;

const EXCLUDED: &[&str] = &[
    // to start with something that is always false
    "(1 == 0)",
    // tECDSA is not enabled in the test yet
    "$0 ~ /tECDSA/",
    // the replica does not yet check that the effective canister id is valid in all cases
    "$0 ~ /wrong effective canister id.in mangement call/",
    "$0 ~ /access denied two status to different canisters/",
    // the replica does not implement proofs of path non-existence
    "$0 ~ /non-existence proofs for non-existing request id/",
    "$0 ~ /module_hash of empty canister/",
    "$0 ~ /metadata.absent/",
];

pub fn config_impl(env: TestEnv) {
    use crate::driver::test_env_api::{retry, secs};
    use crate::util::block_on;
    use hyper::client::connect::HttpConnector;
    use hyper::Client;
    use hyper_tls::HttpsConnector;
    use std::env;

    env.ensure_group_setup_created();

    // Set up Universal VM with HTTP Bin testing service
    let activate_script = &get_universal_vm_activation_script(&env)[..];
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();
    let _ = insert_file_to_config(
        config_dir.clone(),
        "cert.pem",
        get_pem_content(&env, &PemType::PemCert).as_bytes(),
    );
    let _ = insert_file_to_config(
        config_dir.clone(),
        "key.pem",
        get_pem_content(&env, &PemType::PemKey).as_bytes(),
    );
    env::set_var("SSL_CERT_FILE", config_dir.as_path().join("cert.pem"));
    env::remove_var("NIX_SSL_CERT_FILE");
    env::set_var("IC_TEST_DATA", env.get_dependency_path("rs/tests/ic-hs"));

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to set up universal VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(REPLICATION_FACTOR),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(REPLICATION_FACTOR),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    let log = env.logger();
    retry(log.clone(), secs(300), secs(10), || {
        block_on(async {
            let mut http_connector = HttpConnector::new();
            http_connector.enforce_http(false);
            let mut https_connector = HttpsConnector::new_with_connector(http_connector);
            https_connector.https_only(true);
            let client = Client::builder().build::<_, hyper::Body>(https_connector);

            let webserver_ipv6 = get_universal_vm_address(&env);
            let httpbin = format!("https://[{webserver_ipv6}]:20443");
            let req = hyper::Request::builder()
                .method(hyper::Method::GET)
                .uri(httpbin)
                .body(hyper::Body::from(""))?;

            let resp = client.request(req).await?;

            let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
            let body = String::from_utf8(body_bytes.to_vec()).unwrap();

            info!(log, "response body from httpbin: {}", body);

            Ok(())
        })
    })
    .expect("Httpbin server should respond to incoming requests!");
}

fn find_subnet(
    topology_snapshot: &TopologySnapshot,
    subnet_type: Option<SubnetType>,
    skip: Vec<SubnetId>,
) -> SubnetSnapshot {
    match subnet_type {
        None => topology_snapshot.root_subnet(),
        Some(subnet_type) => topology_snapshot
            .subnets()
            .find(|s| s.subnet_type() == subnet_type && !skip.contains(&s.subnet_id))
            .unwrap(),
    }
}

pub fn test_subnet(
    env: TestEnv,
    test_subnet_type: Option<SubnetType>,
    peer_subnet_type: Option<SubnetType>,
) {
    let log = env.logger();
    let topology_snapshot = &env.topology_snapshot();
    let test_subnet = find_subnet(topology_snapshot, test_subnet_type, vec![]);
    let peer_subnet = find_subnet(
        topology_snapshot,
        peer_subnet_type,
        vec![test_subnet.subnet_id],
    );
    let webserver_ipv6 = get_universal_vm_address(&env);
    let httpbin = format!("[{webserver_ipv6}]:20443");
    let ic_ref_test_path = env
        .get_dependency_path("rs/tests/ic-hs/ic-ref-test")
        .into_os_string()
        .into_string()
        .unwrap();
    with_endpoint(
        test_subnet,
        peer_subnet,
        httpbin,
        ic_ref_test_path,
        log,
        EXCLUDED.to_vec(),
    );
}

fn subnet_config(subnet: &SubnetSnapshot) -> String {
    format!(
        "(\"{}\",{},{},[{}])",
        subnet.subnet_id,
        match subnet.subnet_type() {
            SubnetType::VerifiedApplication => "verified_application",
            SubnetType::Application => "application",
            SubnetType::System => "system",
        },
        REPLICATION_FACTOR,
        subnet
            .subnet_canister_ranges()
            .iter()
            .map(|r| format!(
                "({},{})",
                canister_id_into_u64(r.start),
                canister_id_into_u64(r.end)
            ))
            .collect::<Vec<String>>()
            .join(",")
    )
}

pub fn with_endpoint(
    test_subnet: SubnetSnapshot,
    peer_subnet: SubnetSnapshot,
    httpbin: String,
    ic_ref_test_path: String,
    log: Logger,
    excluded_tests: Vec<&str>,
) {
    let node = test_subnet.nodes().next().unwrap();
    let test_subnet_config = subnet_config(&test_subnet);
    let peer_subnet_config = subnet_config(&peer_subnet);
    info!(log, "test-subnet-config: {}", test_subnet_config);
    info!(log, "peer-subnet-config: {}", peer_subnet_config);
    let status = Command::new(ic_ref_test_path)
        .arg("-j20")
        .arg("--pattern")
        .arg(tests_to_pattern(excluded_tests))
        .arg("--endpoint")
        .arg(node.get_public_url().to_string())
        .arg("--httpbin")
        .arg(&httpbin)
        .arg("--test-subnet-config")
        .arg(test_subnet_config)
        .arg("--peer-subnet-config")
        .arg(peer_subnet_config)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("ic-ref-test binary crashed");
    info!(log, "{}", format!("Status of ic-ref-test: {:?}", &status));
    assert!(status.success());
}

fn tests_to_pattern(tests: Vec<&str>) -> String {
    format!("!({})", tests.join(" || "))
}
