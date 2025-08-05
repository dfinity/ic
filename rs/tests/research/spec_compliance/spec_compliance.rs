use canister_http::get_universal_vm_address;
use ic_registry_routing_table::canister_id_into_u64;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, NrOfVCPUs, Subnet, VmResources};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    NnsInstallationBuilder, SubnetSnapshot, TopologySnapshot,
};
use ic_system_test_driver::driver::universal_vm::UniversalVm;
use ic_system_test_driver::util::timeit;
use ic_types::SubnetId;
use slog::{info, Logger};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::{spawn, JoinHandle};

pub const UNIVERSAL_VM_NAME: &str = "httpbin";

const REPLICATION_FACTOR: usize = 2;

const EXCLUDED: &[&str] = &[
    // to start with something that is always false
    "(1 == 0)",
    // the replica does not yet check that the effective canister id is valid in all cases
    "$0 ~ /wrong effective canister id.in management call/",
    "$0 ~ /access denied with different effective canister id/",
    // Recursive calls from queries are now allowed.
    // When composite queries are enabled, we should clean up and re-enable this test
    "$0 ~ /Call from query method traps (in query call)/",
];

pub fn group_01() -> Vec<&'static str> {
    vec![
        "($0 ~ /stable memory/)",
        "($0 ~ /inter-canister calls/)",
        "($0 ~ /uninstall/)",
        "($0 ~ /read state/)",
        "($0 ~ /cycles/)",
    ]
}

pub fn setup_impl(env: TestEnv, deploy_nns_canisters: bool, http_requests: bool) {
    use ic_system_test_driver::driver::test_env_api::secs;
    use ic_system_test_driver::util::block_on;
    use std::env;

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(16)),
        memory_kibibytes: None,
        boot_image_minimal_size_gibibytes: None,
    };

    // If requested, deploy the httpbin UVM concurrently with deploying the rest of the testnet:
    let mut deploy_httpbin_uvm_thread: Option<JoinHandle<()>> = None;
    let cloned_env = env.clone();
    if http_requests {
        deploy_httpbin_uvm_thread = Some(spawn(move || {
            env::set_var(
                "SSL_CERT_FILE",
                get_dependency_path(
                    "ic-os/components/networking/dev-certs/canister_http_test_ca.cert",
                ),
            );
            env::remove_var("NIX_SSL_CERT_FILE");

            // Set up Universal VM for httpbin testing service
            UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
                .with_config_img(get_dependency_path(
                    "rs/tests/networking/canister_http/http_uvm_config_image.zst",
                ))
                .start(&cloned_env)
                .expect("failed to set up universal VM");
            canister_http::start_httpbin_on_uvm(&cloned_env);
        }))
    }
    let cloned_env = env.clone();
    timeit(cloned_env.logger(), "deploying IC", move || {
        InternetComputer::new()
            .add_subnet(
                Subnet::new(SubnetType::System)
                    .with_default_vm_resources(vm_resources)
                    .with_features(SubnetFeatures {
                        http_requests,
                        ..SubnetFeatures::default()
                    })
                    .add_nodes(REPLICATION_FACTOR),
            )
            .add_subnet(
                Subnet::new(SubnetType::Application)
                    .with_default_vm_resources(vm_resources)
                    .with_features(SubnetFeatures {
                        http_requests,
                        ..SubnetFeatures::default()
                    })
                    .add_nodes(REPLICATION_FACTOR),
            )
            .with_api_boundary_nodes(1)
            .setup_and_start(&cloned_env)
            .expect("failed to setup IC under test");
    });
    if deploy_nns_canisters {
        let cloned_env: TestEnv = env.clone();
        timeit(cloned_env.logger(), "installing NNS", move || {
            let nns_node = cloned_env
                .topology_snapshot()
                .root_subnet()
                .nodes()
                .next()
                .unwrap();
            NnsInstallationBuilder::new()
                .install(&nns_node, &cloned_env)
                .expect("NNS canisters not installed");
            info!(cloned_env.logger(), "NNS canisters are installed.");
        });
    }
    let cloned_env = env.clone();
    timeit(
        cloned_env.logger(),
        "waiting until all IC nodes are healthy",
        move || {
            cloned_env.topology_snapshot().subnets().for_each(|subnet| {
                subnet
                    .nodes()
                    .for_each(|node| node.await_status_is_healthy().unwrap())
            });

            cloned_env
                .topology_snapshot()
                .api_boundary_nodes()
                .for_each(|api_bn| api_bn.await_status_is_healthy().unwrap());
        },
    );
    if http_requests {
        timeit(env.logger(), "waiting on httpbin deployment", move || {
            deploy_httpbin_uvm_thread.unwrap().join().unwrap();
        });
        let cloned_env = env.clone();
        timeit(
            cloned_env.logger(),
            "waiting until httpbin responds to requests",
            move || {
                let log = cloned_env.logger();
                ic_system_test_driver::retry_with_msg!(
                    "check if httpbin is responding to requests",
                    log.clone(),
                    secs(300),
                    secs(10),
                    || {
                        block_on(async {
                            let client = reqwest::Client::builder()
                                .use_rustls_tls()
                                .https_only(true)
                                .http1_only()
                                .build()?;

                            let webserver_ipv6 = get_universal_vm_address(&cloned_env);
                            let httpbin = format!("https://[{webserver_ipv6}]:20443");

                            let resp = client.get(httpbin).send().await?;

                            let body = String::from_utf8(resp.bytes().await?.to_vec()).unwrap();

                            info!(log, "response body from httpbin: {}", body);

                            Ok(())
                        })
                    }
                )
                .expect("Httpbin server should respond to incoming requests!");
            },
        );
    }
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
    use_api_bn: bool,
    http_requests: bool,
    test_subnet_type: Option<SubnetType>,
    peer_subnet_type: Option<SubnetType>,
    excluded_tests: Vec<&str>,
    included_tests: Vec<&str>,
) {
    let log = env.logger();
    let topology_snapshot = &env.topology_snapshot();
    let test_subnet = find_subnet(topology_snapshot, test_subnet_type, vec![]);
    let peer_subnet = find_subnet(
        topology_snapshot,
        peer_subnet_type,
        vec![test_subnet.subnet_id],
    );
    let httpbin_proto = if http_requests {
        Some("https://".to_string())
    } else {
        None
    };
    let httpbin = if http_requests {
        let webserver_ipv6 = get_universal_vm_address(&env);
        Some(format!("[{webserver_ipv6}]:20443"))
    } else {
        None
    };
    let mut all_excluded_tests = excluded_tests;
    all_excluded_tests.append(&mut EXCLUDED.to_vec());
    with_endpoint(
        env,
        test_subnet,
        peer_subnet,
        use_api_bn,
        httpbin_proto,
        httpbin,
        log,
        all_excluded_tests,
        included_tests,
    );
}

fn subnet_config(subnet: &SubnetSnapshot) -> String {
    format!(
        "(\"{}\",{},[{}],[{}],[{}])",
        subnet.subnet_id,
        match subnet.subnet_type() {
            SubnetType::VerifiedApplication => "verified_application",
            SubnetType::Application => "application",
            SubnetType::System => "system",
        },
        subnet
            .nodes()
            .map(|n| format!("\"{}\"", n.node_id))
            .collect::<Vec<String>>()
            .join(","),
        subnet
            .subnet_canister_ranges()
            .iter()
            .map(|r| format!(
                "({},{})",
                canister_id_into_u64(r.start),
                canister_id_into_u64(r.end)
            ))
            .collect::<Vec<String>>()
            .join(","),
        subnet
            .nodes()
            .map(|n| format!("\"{}\"", n.get_public_url()))
            .collect::<Vec<String>>()
            .join(",")
    )
}

pub fn run_ic_ref_test(
    httpbin_proto: Option<String>,
    httpbin: Option<String>,
    ic_ref_test_path: PathBuf,
    ic_test_data_path: PathBuf,
    endpoint: String,
    test_subnet_config: String,
    peer_subnet_config: String,
    excluded_tests: Vec<&str>,
    included_tests: Vec<&str>,
    jobs: u32,
) {
    let mut cmd = Command::new(ic_ref_test_path);
    cmd.env("IC_TEST_DATA", ic_test_data_path)
        .arg("+RTS")
        .arg(format!("-N{}", jobs))
        .arg("-RTS")
        .arg(format!("-j{}", jobs))
        .arg("--pattern")
        .arg(tests_to_pattern(excluded_tests, included_tests))
        .arg("--endpoint")
        .arg(endpoint)
        .arg("--test-subnet-config")
        .arg(test_subnet_config)
        .arg("--peer-subnet-config")
        .arg(peer_subnet_config)
        .arg("--allow-self-signed-certs")
        .arg("True");
    if let Some(httpbin_proto) = httpbin_proto {
        cmd.arg("--httpbin-proto").arg(&httpbin_proto);
    }
    if let Some(httpbin) = httpbin {
        cmd.arg("--httpbin").arg(&httpbin);
    }
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("ic-ref-test binary crashed");
    assert!(status.success());
}

pub fn with_endpoint(
    env: TestEnv,
    test_subnet: SubnetSnapshot,
    peer_subnet: SubnetSnapshot,
    use_api_bn: bool,
    httpbin_proto: Option<String>,
    httpbin: Option<String>,
    log: Logger,
    excluded_tests: Vec<&str>,
    included_tests: Vec<&str>,
) {
    let endpoint = if use_api_bn {
        env.topology_snapshot()
            .api_boundary_nodes()
            .next()
            .expect("No API boundary node found")
            .get_public_url()
            .to_string()
    } else {
        test_subnet
            .nodes()
            .next()
            .unwrap()
            .get_public_url()
            .to_string()
    };
    let test_subnet_config = subnet_config(&test_subnet);
    let peer_subnet_config = subnet_config(&peer_subnet);
    info!(log, "test-subnet-config: {}", test_subnet_config);
    info!(log, "peer-subnet-config: {}", peer_subnet_config);

    let ic_ref_test_path =
        get_dependency_path(std::env::var("IC_REF_TEST_BIN").expect("Missing ic-ref-test"));
    let ic_test_data_path = get_dependency_path("rs/tests/research/ic-hs/test-data");

    run_ic_ref_test(
        httpbin_proto,
        httpbin,
        ic_ref_test_path,
        ic_test_data_path,
        endpoint,
        test_subnet_config,
        peer_subnet_config,
        excluded_tests,
        included_tests,
        16,
    );
}

fn tests_to_pattern(excluded_tests: Vec<&str>, included_tests: Vec<&str>) -> String {
    let excluded = format!("!({})", excluded_tests.join(" || "));
    if included_tests.is_empty() {
        excluded
    } else {
        let included = format!("({})", included_tests.join(" || "));
        format!("{} && {}", excluded, included)
    }
}
