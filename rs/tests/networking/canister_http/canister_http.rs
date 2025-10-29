use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::prometheus_vm::HasPrometheus;
use ic_system_test_driver::driver::prometheus_vm::PrometheusVm;
use ic_system_test_driver::driver::simulate_network::ProductionSubnetTopology;
use ic_system_test_driver::driver::simulate_network::SimulateNetwork;
use ic_system_test_driver::driver::test_env_api::{
    HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr,
};
use ic_system_test_driver::nns::{vote_execute_proposal_assert_executed, await_proposal_execution, submit_external_proposal_with_test_id};
use ic_system_test_driver::driver::test_setup::InfraProvider;
use ic_system_test_driver::driver::universal_vm::*;
use ic_system_test_driver::driver::{
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::*,
};
use ic_system_test_driver::util::{self, block_on, create_and_install, create_and_install_with_cycles};
pub use ic_types::{CanisterId, Cycles, PrincipalId};
use slog::info;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

//use anyhow::Result;
use candid::CandidType; 
use ic_nns_governance_api::NnsFunction; 
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule, FirewallRuleDirection}; 
use ic_registry_keys::FirewallRulesScope; 
use registry_canister::mutations::firewall::{
    AddFirewallRulesPayload, compute_firewall_ruleset_hash,
};
use slog::Logger;
use url::Url;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

const INITIAL_WAIT: Duration = Duration::from_secs(10);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_WAIT: Duration = Duration::from_secs(120);

const APP_SUBNET_SIZES: [usize; 3] = [13, 28, 40];
pub const CONCURRENCY_LEVELS: [u64; 3] = [200, 500, 1000];
const PROXY_CANISTER_ID_PATH: &str = "proxy_canister_id";

pub enum PemType {
    PemCert,
    PemKey,
}

pub fn await_nodes_healthy(env: &TestEnv) {
    info!(&env.logger(), "Checking readiness of all replica nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    info!(
        &env.logger(),
        "Checking readiness of all API boundary nodes..."
    );
    env.topology_snapshot()
        .api_boundary_nodes()
        .for_each(|api_bn| api_bn.await_status_is_healthy().unwrap());
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

pub fn setup(env: TestEnv) {
    std::thread::scope(|s| {
        // Set up IC with 1 system subnet with one node, and one application subnet with 4 nodes.
        s.spawn(|| {
            InternetComputer::new()
                .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
                .add_subnet(
                    Subnet::new(SubnetType::Application)
                        .with_features(SubnetFeatures {
                            http_requests: true,
                            ..SubnetFeatures::default()
                        })
                        .add_nodes(4),
                )
                .setup_and_start(&env)
                .expect("failed to setup IC under test");

            await_nodes_healthy(&env);

            s.spawn(|| {
                install_nns_canisters(&env);
            });
            s.spawn(|| {
                // Get application subnet node to deploy canister to.
                let mut nodes = get_node_snapshots(&env);
                let node = nodes.next().expect("there is no application node");
                let runtime = get_runtime_from_node(&node);
                let _ = create_proxy_canister(&env, &runtime, &node);
            });
        });
        // Set up Universal VM with HTTP Bin testing service
        s.spawn(|| {
            UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
                .with_config_img(get_dependency_path(
                    "rs/tests/networking/canister_http/http_uvm_config_image.zst",
                ))
                .enable_ipv4()
                .start(&env)
                .expect("failed to set up universal VM");
        });
    });

    start_httpbin_on_uvm(&env);
}

pub fn stress_setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .start(&env)
        .expect("failed to set up universal VM");

    let mut ic = InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1));
    for subnet_size in APP_SUBNET_SIZES {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(subnet_size),
        );
    }
    ic.with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);

    start_httpbin_on_uvm(&env);

    env.topology_snapshot()
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .for_each(|s| match s.nodes().count() {
            28 => s.apply_network_settings(ProductionSubnetTopology::UZR34),
            13 => s.apply_network_settings(ProductionSubnetTopology::IO67),
            _ => {}
        });

    env.sync_with_prometheus();
}

pub fn get_universal_vm_address(env: &TestEnv) -> Ipv6Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let webserver_ipv6: Ipv6Addr = universal_vm.ipv6;
    info!(&env.logger(), "Webserver has IPv6 {:?}", webserver_ipv6);
    webserver_ipv6
}

pub fn get_universal_vm_ipv4_address(env: &TestEnv) -> Ipv4Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    match InfraProvider::read_attribute(env) {
        InfraProvider::Farm => deployed_universal_vm
            .block_on_ipv4()
            .expect("Universal VM IPv4 not found."),
    }
}

// This function starts the httpbin service on the universal VM and creates firewall rules on all nodes to
// allow access to it. This means that this must only be called after all nodes are up and healthy.
pub fn start_httpbin_on_uvm(env: &TestEnv) {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let vm = deployed_universal_vm.get_vm().unwrap();
    let ipv6 = vm.ipv6.to_string();
    let ipv4 = vm.ipv4.map_or("".to_string(), |ipv4| ipv4.to_string());
    // We need to use port 443 as it's among the only ports that the Dante socks server can proxy to.
    let http_bin_port = 443;
    info!(
        &env.logger(),
        "Starting httpbin service on UVM '{UNIVERSAL_VM_NAME}' ..."
    );
    deployed_universal_vm
        .block_on_bash_script(&format!(
            r#"
        set -e -o pipefail
        ipv6="{ipv6}"
        ipv4="{ipv4}"

        nip_io_hostname="${{ipv6//:/-}}.ipv6.nip.io"
        echo "Calculated nip.io hostname: $nip_io_hostname"

        if [[ "$ipv4" == "" ]] && ip link show dev enp2s0 >/dev/null; then
            count=0
            until ipv4=$(ip -j address show dev enp2s0 \
                        | jq -r -e \
                        '.[0].addr_info | map(select(.scope == "global")) | .[0].local'); \
            do
                if [ "$count" -ge 120 ]; then
                    exit 1
                fi
                sleep 1
                count=$((count+1))
            done
        fi
        echo "IPv4 is ${{ipv4:-disabled}}"

        echo "Generate ipv6 service cert with root cert and key, using minica ..."
        mkdir certs
        cd certs
        cp /config/cert.pem minica.pem
        cp /config/key.pem minica-key.pem
        chmod -R 755 ./

        echo "Making certs directory in $(pwd) ..."
        docker load -i /config/minica.tar
        docker run \
            -v "$(pwd)":/output \
            minica:image \
            -ip-addresses="$ipv6${{ipv4:+,$ipv4}}" \
            -domains="$nip_io_hostname"

        echo "Updating service certificate folder name so it can be fed to ssl-proxy container ..."

        if [ -d "$nip_io_hostname" ]; then
            sudo mv "$nip_io_hostname" service_cert
        elif [ -d "$ipv6" ]; then
            sudo mv "$ipv6" service_cert
        elif [ ! -z "$ipv4" ] && [ -d "$ipv4" ]; then
            sudo mv "$ipv4" service_cert
        else
            echo "Error: Could not find minica output directory!"
            exit 1
        fi

        sudo chmod -R 755 service_cert

        echo "Setting up httpbin on port {http_bin_port} ..."
        docker load -i /config/httpbin.tar
        sudo docker run \
            --rm \
            -d \
            --network host \
            -u root \
            -v "$(pwd)/service_cert":/certs \
            --name httpbin \
            httpbin:image \
            --cert-file /certs/cert.pem --key-file /certs/key.pem --port {http_bin_port}
    "#
        ))
        .unwrap_or_else(|e| panic!("Could not start httpbin on {UNIVERSAL_VM_NAME} because {e:?}"));

    // Allow list all nodes to access the UVM httpbin service.
    create_accept_fw_rules_via_proposal(env, SocketAddr::new(IpAddr::V6(vm.ipv6), http_bin_port));

    info!(&env.logger(), "httpbin service started on UVM");
}

// helper
enum Proposal<T: CandidType> {
    Add(T, NnsFunction),
}

// helper
async fn execute_proposal<T: Clone + CandidType>(
    log: &Logger,
    nns_node: &ic_system_test_driver::driver::test_env_api::IcNodeSnapshot, // Added full path
    proposal: Proposal<T>,
) {
    let (proposal_payload, function) = match proposal {
        Proposal::Add(payload, func) => (payload, func),
    };
    let nns_runtime =
        util::runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = ic_system_test_driver::nns::get_governance_canister(&nns_runtime);
    let nns = util::runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = ic_system_test_driver::nns::get_governance_canister(&nns);

    info!(log, "Submitting proposal to add firewall rules...");

    let proposal_id =
        submit_external_proposal_with_test_id(&governance, function, proposal_payload.clone())
            .await;

    info!(log, "Proposal submitted with ID {}", proposal_id);
    
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    info!(log, "Proposal with ID {} executed.", proposal_id);

    // wait until proposal is executed
    await_proposal_execution(log, &governance, proposal_id, BACKOFF_DELAY, WAIT_TIMEOUT).await;

    info!(log, "Proposal with ID {} is fully executed.", proposal_id);
}

// helper
fn prepare_add_rules_proposal(
    scope: FirewallRulesScope,
    new_rules: Vec<FirewallRule>,
    positions_sorted: Vec<i32>,
    previous_rules: Vec<FirewallRule>, // Caller needs to provide this
) -> AddFirewallRulesPayload {
    let mut all_rules = previous_rules;
    for (rule, &pos) in new_rules.iter().zip(&positions_sorted) {
        if pos < 0 || pos as usize > all_rules.len() {
            panic!("Invalid insertion position {} for rule", pos);
        }
        all_rules.insert(pos as usize, rule.clone());
    }
    AddFirewallRulesPayload {
        scope,
        rules: new_rules,
        positions: positions_sorted,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    }
}

fn create_accept_fw_rules_via_proposal(env: &TestEnv, target_socket_addr: SocketAddr) {
    let log = env.logger();
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    let ip_addr = target_socket_addr.ip();
    let port = target_socket_addr.port();
    let (ipv4_prefixes, ipv6_prefixes) = match ip_addr {
        std::net::IpAddr::V4(ip) => (vec![ip.to_string()], vec![]),
        std::net::IpAddr::V6(ip) => (vec![], vec![ip.to_string()]),
    };
    let new_rule = FirewallRule {
        ipv4_prefixes,
        ipv6_prefixes,
        ports: vec![port as u32],
        action: FirewallAction::Allow.into(),
        comment: format!("Allow egress to {}", target_socket_addr),
        user: Some("ic-http-adapter".to_string()),
        direction: Some(FirewallRuleDirection::Outbound as i32),
    };
    
    let previous_rules: Vec<FirewallRule> = Vec::new(); 
    let positions_sorted: Vec<i32> = vec![0]; 

    let proposal_payload = prepare_add_rules_proposal(
        FirewallRulesScope::ReplicaNodes,
        vec![new_rule],
        positions_sorted,
        previous_rules,
    );

    info!(
        &log,
        "Submitting proposal to add firewall rule to allow access to {} ...",
        target_socket_addr
    );

    block_on(execute_proposal(
        &log,
        &nns_node,
        Proposal::Add(proposal_payload, NnsFunction::AddFirewallRules),
    ));

    info!(
        &log,
        "Proposal to add firewall rule to allow access to {} executed.",
        target_socket_addr
    );
}

// helper
fn await_rule_execution_with_backoff(
    log: &slog::Logger,
    test: &dyn Fn() -> bool,
    initial_wait: Duration,
    linear_backoff: Duration,
    max_wait: Duration,
) -> bool {
    let mut total_duration = initial_wait;
    std::thread::sleep(initial_wait);
    if test() {
        info!(
            log,
            "(Waited {} seconds, succeeded)",
            total_duration.as_secs()
        );
        return true;
    }
    while total_duration < max_wait {
        std::thread::sleep(linear_backoff);
        total_duration += linear_backoff;
        if test() {
            info!(
                log,
                "(Waited {} seconds, succeeded)",
                total_duration.as_secs()
            );
            return true;
        }
    }
    info!(log, "(Waited {} seconds, failed)", total_duration.as_secs());
    false
}

// helper
fn check_port_connectable(target: SocketAddr) -> bool {
    // Convert SocketAddr to something reqwest can use (like a URL string)
    // Note: reqwest usually needs a scheme like http/https.
    // If just checking TCP, std::net::TcpStream::connect_timeout might be better.
    // This is a placeholder - adapt based on your actual check_port logic.
    let url_str = format!("https://{}", target); 
    let url = Url::parse(&url_str).unwrap();

    let client = reqwest::blocking::ClientBuilder::new()
        .timeout(Duration::from_secs(2)) 
        .build()
        .expect("Could not build reqwest client.");

    client.head(url).send().is_ok()
}

// Create firewall rules on all nodes to allow connections from canister http adapter to the target socket address.
// This is usually called because by default outbound connections from the ic-http-adapter to most internal
// IPv6 ranges are blocked.
fn create_accept_fw_rules(env: &TestEnv, target_socket_addr: SocketAddr) {
    let all_nodes: Vec<IcNodeSnapshot> = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .collect();

    for node in all_nodes {
        node.insert_egress_accept_rule_for_outcalls_adapter(target_socket_addr)
            .expect("Failed to add accept firewall rule to allow access to UVM httpbin service");
    }
}

// Create firewall rules on all nodes to allow connections from canister http adapter to the API BN.
// This is necessary because by default outbound connections from the ic-http-adapter to most internal
// IPv6 ranges are blocked.
// API BNs are used as proxies to reach the UVM from the canister http adapter when the direct request
// fails.
// This should be called only after all nodes are up and healthy.
pub fn whitelist_nodes_access_to_apibns(env: &TestEnv) {
    let api_bns = env.topology_snapshot().api_boundary_nodes();

    for apibn in api_bns {
        let apibn_ip = apibn.get_ip_addr();
        let apibn_socket_addr = SocketAddr::new(apibn_ip, 1080);
        create_accept_fw_rules(env, apibn_socket_addr);
    }

    info!(
        &env.logger(),
        "Firewall rules to allow access to API BNs successfully applied on all nodes."
    );
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
}

pub fn get_all_application_subnets(env: &TestEnv) -> Vec<SubnetSnapshot> {
    env.topology_snapshot()
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect()
}

pub fn get_system_subnet_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("there is no system subnet")
        .nodes()
}

pub fn get_runtime_from_node(node: &IcNodeSnapshot) -> Runtime {
    util::runtime_from_url(node.get_public_url(), node.effective_canister_id())
}

pub fn create_proxy_canister_with_name<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
    canister_name: &str,
) -> Canister<'a> {
    info!(&env.logger(), "Installing proxy_canister.");

    // Create proxy canister with maximum canister cycles.
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let proxy_canister_id = rt.block_on(create_and_install(
        &node.build_default_agent(),
        node.effective_canister_id(),
        &load_wasm(env::var("PROXY_WASM_PATH").expect("PROXY_WASM_PATH not set")),
    ));
    info!(
        &env.logger(),
        "proxy_canister {} installed", proxy_canister_id
    );

    let principal_id = PrincipalId::from(proxy_canister_id);

    // write proxy canister id to TestEnv
    env.write_json_object(canister_name, &principal_id)
        .expect("Could not write proxy canister id to TestEnv.");

    Canister::new(runtime, CanisterId::unchecked_from_principal(principal_id))
}

pub fn create_proxy_canister_with_name_and_cycles<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
    canister_name: &str,
    cycles: Cycles,
) -> Canister<'a> {
    info!(
        &env.logger(),
        "Installing proxy_canister with a custom cycle amount ({cycles:?})."
    );

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let proxy_canister_id = rt.block_on(create_and_install_with_cycles(
        &node.build_default_agent(),
        node.effective_canister_id(),
        &load_wasm(
            env::var("PROXY_WASM_PATH").expect("Environment variable PROXY_WASM_PATH not set"),
        ),
        cycles,
    ));

    info!(
        &env.logger(),
        "Proxy canister {:?} installed with cycles {:?}", proxy_canister_id, cycles
    );

    let principal_id = PrincipalId::from(proxy_canister_id);

    env.write_json_object(canister_name, &principal_id)
        .expect("Could not write proxy canister ID to TestEnv.");

    Canister::new(runtime, CanisterId::unchecked_from_principal(principal_id))
}

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
) -> Canister<'a> {
    create_proxy_canister_with_name(env, runtime, node, PROXY_CANISTER_ID_PATH)
}

pub fn create_proxy_canister_with_cycles<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
    cycles: Cycles,
) -> Canister<'a> {
    create_proxy_canister_with_name_and_cycles(env, runtime, node, PROXY_CANISTER_ID_PATH, cycles)
}

pub fn get_proxy_canister_id_with_name(env: &TestEnv, name: &str) -> PrincipalId {
    env.read_json_object(name)
        .expect("Proxy canister should should .")
}

pub fn get_proxy_canister_id(env: &TestEnv) -> PrincipalId {
    get_proxy_canister_id_with_name(env, PROXY_CANISTER_ID_PATH)
}
