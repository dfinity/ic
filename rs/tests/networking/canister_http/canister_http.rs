use candid::{CandidType, Decode, Deserialize, Encode};
use canister_test::Canister;
use canister_test::Runtime;
use ic_config::subnet_config::{CyclesAccountManagerConfig, DEFAULT_REFERENCE_SUBNET_SIZE};
use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerSubnetConfig};
use ic_https_outcalls_pricing::MAX_RESPONSE_TIME;
use ic_protobuf::registry::subnet::v1::CanisterCyclesCostSchedule as CanisterCyclesCostScheduleProto;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::simulate_network::ProductionSubnetTopology;
use ic_system_test_driver::driver::simulate_network::SimulateNetwork;
use ic_system_test_driver::driver::test_env_api::{
    HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr,
};
use ic_system_test_driver::driver::universal_vm::*;
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::util::{self, create_and_install, create_and_install_with_cycles};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::RegistryVersion;
use ic_types::canister_http::CanisterHttpRequestContext;
use ic_types::time::UNIX_EPOCH;
pub use ic_types::{CanisterId, PrincipalId};
use ic_types::{
    NumBytes, NumInstructions, NumberOfNodes,
    canister_http::{Replication, ReplicationKind},
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use slog::info;
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

const APP_SUBNET_SIZES: [usize; 3] = [13, 28, 40];
pub const CONCURRENCY_LEVELS: [u64; 3] = [200, 500, 1000];
const SYSTEM_PROXY_CANISTER_ID_PATH: &str = "system_proxy_canister_id";

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
    setup_with_app_subnets(env, &[CanisterCyclesCostSchedule::Normal]);
}

/// Like [`setup`], but with a second application subnet on a free cost schedule,
/// where HTTP outcalls cost nothing.
pub fn setup_with_free_and_paying_subnets(env: TestEnv) {
    setup_with_app_subnets(
        env,
        &[
            CanisterCyclesCostSchedule::Free,
            CanisterCyclesCostSchedule::Normal,
        ],
    )
}

/// Sets up an IC with a 1-node system subnet and one 4-node application subnet per
/// entry in `app_subnets`, which gives each its cost schedule.
///
/// HTTP outcalls are enabled on every subnet, including the system one, which is
/// free for outcalls despite its normal cost schedule. Every subnet gets a proxy
/// canister: the system subnet's is reached through
/// [`get_system_proxy_canister_id`] and each application subnet's through
/// [`get_proxy_canister_id_for`], or through [`get_proxy_canister_id`] when there
/// is only one.
///
/// Cost schedules in `app_subnets` must be distinct.
pub fn setup_with_app_subnets(env: TestEnv, app_subnets: &[CanisterCyclesCostSchedule]) {
    std::thread::scope(|s| {
        s.spawn(|| {
            let with_outcalls = SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            };
            let mut ic = InternetComputer::new().add_subnet(
                Subnet::new(SubnetType::System)
                    .with_features(with_outcalls)
                    .add_nodes(1),
            );
            for &cost_schedule in app_subnets {
                ic = ic.add_subnet(
                    Subnet::new(SubnetType::Application)
                        .with_features(with_outcalls)
                        .with_cost_schedule(cost_schedule)
                        .add_nodes(4),
                );
            }
            ic.setup_and_start(&env)
                .expect("failed to setup IC under test");

            await_nodes_healthy(&env);

            s.spawn(|| {
                install_nns_canisters(&env);
                let node = get_system_subnet_node_snapshots(&env)
                    .next()
                    .expect("there is no system-subnet node");
                let runtime = get_runtime_from_node(&node);
                let _ = create_proxy_canister_with_name(
                    &env,
                    &runtime,
                    &node,
                    SYSTEM_PROXY_CANISTER_ID_PATH,
                );
            });
            // `cost_schedule` is per-iteration, so it has to be moved in; `env` is
            // only borrowed, hence the explicit reference.
            let env = &env;
            for &cost_schedule in app_subnets {
                s.spawn(move || {
                    let node = get_app_subnet_node_snapshots_with_schedule(env, cost_schedule)
                        .next()
                        .expect("there is no application node");
                    let runtime = get_runtime_from_node(&node);
                    let _ = create_proxy_canister_with_name(
                        env,
                        &runtime,
                        &node,
                        &proxy_canister_id_path(cost_schedule),
                    );
                });
            }
        });
        // Set up Universal VM with HTTP Bin testing service
        s.spawn(|| {
            UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
                .with_config_img(get_dependency_path_from_env("HTTP_UVM_CONFIG_IMAGE_PATH"))
                .enable_ipv4()
                .start(&env)
                .expect("failed to set up universal VM");
        });
    });

    start_httpbin_on_uvm(&env);
}

pub fn stress_setup(env: TestEnv) {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path_from_env("HTTP_UVM_CONFIG_IMAGE_PATH"))
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
    deployed_universal_vm
        .block_on_ipv4()
        .expect("Universal VM IPv4 not found.")
}

/// This function starts the httpbin service on the universal VM and creates firewall rules on all nodes to
/// allow access to it. This means that this must only be called after all nodes are up and healthy.
pub fn start_httpbin_on_uvm(env: &TestEnv) {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let vm = deployed_universal_vm.get_vm().unwrap();
    let ipv6 = vm.ipv6.to_string();
    let session = deployed_universal_vm
        .block_on_ssh_session()
        .expect("Failed to establish SSH session to UVM");
    // Retrieve the UVM's IPv4 address directly from the guest if it's configured
    // with an IPv4 interface. This polls the guest until DHCP assigns a globally
    // scoped address.
    let has_ipv4_iface = deployed_universal_vm
        .block_on_bash_script_from_session(
            &session,
            "if ip link show dev enp2s0 >/dev/null 2>&1; then echo yes; else echo no; fi",
        )
        .map(|s| s.trim() == "yes")
        .unwrap();
    let ipv4 = if has_ipv4_iface {
        deployed_universal_vm
            .block_on_ipv4_from_session(&session)
            .expect("Failed to retrieve IPv4 address from UVM")
            .to_string()
    } else {
        "".to_string()
    };
    // We need to use port 443 as it's among the only ports that the Dante socks server can proxy to.
    let http_bin_port = 443;
    info!(
        &env.logger(),
        "Starting httpbin service on UVM '{UNIVERSAL_VM_NAME}' ..."
    );
    deployed_universal_vm
        .block_on_bash_script_from_session(
            &session,
            &format!(
                r#"
        set -e -o pipefail
        ipv6="{ipv6}"
        ipv4="{ipv4}"

        nip_io_hostname="${{ipv6//:/-}}.ipv6.nip.io"
        echo "Calculated nip.io hostname: $nip_io_hostname"

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
            ),
        )
        .unwrap_or_else(|e| panic!("Could not start httpbin on {UNIVERSAL_VM_NAME} because {e:?}"));

    wait_for_orchestrator_fw_rules(env);

    // Allow list all nodes to access the UVM httpbin service.
    create_accept_fw_rules(env, SocketAddr::new(IpAddr::V6(vm.ipv6), http_bin_port));

    info!(&env.logger(), "httpbin service started on UVM");
}

/// This waits for the orchestrator to apply the firewall rules on all nodes.
fn wait_for_orchestrator_fw_rules(env: &TestEnv) {
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.wait_for_orchestrator_fw_rule(&env.logger())
                .expect("Orchestrator rule did not appear in time.");
        }
    }
}

/// Create firewall rules on all nodes to allow connections from canister http adapter to the target socket address.
/// This is usually called because by default outbound connections from the ic-http-adapter to most internal
/// IPv6 ranges are blocked.
fn create_accept_fw_rules(env: &TestEnv, target_socket_addr: SocketAddr) {
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.insert_egress_accept_rule_for_outcalls_adapter(target_socket_addr)
                .expect(
                    "Failed to add accept firewall rule to allow access to UVM httpbin service",
                );
        }
    }
}

/// Create firewall rules on all nodes to allow connections from canister http adapter to the API BN.
/// This is necessary because by default outbound connections from the ic-http-adapter to most internal
/// IPv6 ranges are blocked.
/// API BNs are used as proxies to reach the UVM from the canister http adapter when the direct request
/// fails.
/// This should be called only after all nodes are up and healthy.
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

/// The `TestEnv` key under which the proxy canister of the application subnet on
/// `schedule` is recorded.
///
/// Derived from the schedule rather than from the order the subnets were created,
/// so a setup with more than one application subnet cannot mix their proxies up.
fn proxy_canister_id_path(schedule: CanisterCyclesCostSchedule) -> String {
    format!("proxy_canister_id_{schedule:?}")
}

/// The cost schedule `subnet` runs on.
fn subnet_cost_schedule(subnet: &SubnetSnapshot) -> CanisterCyclesCostSchedule {
    CanisterCyclesCostScheduleProto::try_from(
        subnet.raw_subnet_record().canister_cycles_cost_schedule,
    )
    .expect("unrecognized cost schedule in the subnet record")
    .into()
}

/// The cost schedule of the subnet `node` belongs to.
fn node_cost_schedule(env: &TestEnv, node: &IcNodeSnapshot) -> CanisterCyclesCostSchedule {
    let subnet_id = node
        .subnet_id()
        .expect("node does not belong to any subnet");
    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_id == subnet_id)
        .expect("no subnet for node");
    subnet_cost_schedule(&subnet)
}

/// The cost schedule of the only application subnet, for the setups that have one.
fn sole_app_subnet_schedule(env: &TestEnv) -> CanisterCyclesCostSchedule {
    let mut app_subnets = env
        .topology_snapshot()
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application);
    let subnet = app_subnets.next().expect("there is no application subnet");
    assert!(
        app_subnets.next().is_none(),
        "there is more than one application subnet; name the cost schedule explicitly"
    );
    subnet_cost_schedule(&subnet)
}

/// The nodes of the application subnet running on the given cost schedule.
///
/// A setup with more than one application subnet
/// ([`setup_with_free_and_paying_subnets`]) tells them apart this way rather than
/// by position, which the topology does not promise to preserve.
pub fn get_app_subnet_node_snapshots_with_schedule(
    env: &TestEnv,
    cost_schedule: CanisterCyclesCostSchedule,
) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application
                && subnet_cost_schedule(subnet) == cost_schedule
        })
        .unwrap_or_else(|| {
            panic!("there is no application subnet on a {cost_schedule:?} cost schedule")
        })
        .nodes()
}

/// The nodes of the application subnet that actually charges for HTTP outcalls.
pub fn get_paying_app_subnet_node_snapshots(
    env: &TestEnv,
) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    get_app_subnet_node_snapshots_with_schedule(env, CanisterCyclesCostSchedule::Normal)
}

pub fn get_cloud_engine_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::CloudEngine)
        .expect("there is no cloud engine")
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
    create_proxy_canister_with_name(
        env,
        runtime,
        node,
        &proxy_canister_id_path(node_cost_schedule(env, node)),
    )
}

pub fn create_proxy_canister_with_cycles<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
    cycles: Cycles,
) -> Canister<'a> {
    create_proxy_canister_with_name_and_cycles(
        env,
        runtime,
        node,
        &proxy_canister_id_path(node_cost_schedule(env, node)),
        cycles,
    )
}

pub fn get_proxy_canister_id_with_name(env: &TestEnv, name: &str) -> PrincipalId {
    env.read_json_object(name)
        .unwrap_or_else(|e| panic!("proxy canister id '{name}' not found in TestEnv: {e}"))
}

/// The proxy canister of the only application subnet.
///
/// Setups with more than one ([`setup_with_free_and_paying_subnets`]) have to name
/// the cost schedule instead — see [`get_proxy_canister_id_for`].
pub fn get_proxy_canister_id(env: &TestEnv) -> PrincipalId {
    get_proxy_canister_id_for(env, sole_app_subnet_schedule(env))
}

/// The proxy canister of the application subnet running on `schedule`.
pub fn get_proxy_canister_id_for(
    env: &TestEnv,
    schedule: CanisterCyclesCostSchedule,
) -> PrincipalId {
    get_proxy_canister_id_with_name(env, &proxy_canister_id_path(schedule))
}

/// The proxy canister installed on the system subnet (available only with a
/// setup that enables HTTP outcalls there, e.g. [`setup_with_free_cost_schedule`]).
pub fn get_system_proxy_canister_id(env: &TestEnv) -> PrincipalId {
    get_proxy_canister_id_with_name(env, SYSTEM_PROXY_CANISTER_ID_PATH)
}

/// The proxy canister on the application subnet that charges for HTTP outcalls
/// (only with [`setup_with_free_and_paying_subnets`]).
pub fn get_paying_proxy_canister_id(env: &TestEnv) -> PrincipalId {
    get_proxy_canister_id_for(env, CanisterCyclesCostSchedule::Normal)
}

// ================ Consumed cycles, by use case ================

/// Nominal cycles consumed by a canister, by use case.
#[derive(CandidType, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsumedCycles {
    pub memory: u128,
    pub compute_allocation: u128,
    pub ingress_induction: u128,
    pub instructions: u128,
    pub request_and_response_transmission: u128,
    pub uninstall: u128,
    pub canister_creation: u128,
    pub http_outcalls: u128,
    pub burned_cycles: u128,
}

impl ConsumedCycles {
    /// Everything the canister has been charged for, whatever the reason.
    pub fn total(&self) -> u128 {
        self.memory
            + self.compute_allocation
            + self.ingress_induction
            + self.instructions
            + self.request_and_response_transmission
            + self.uninstall
            + self.canister_creation
            + self.http_outcalls
            + self.burned_cycles
    }

    /// What was charged for everything other than outcalls themselves.
    pub fn carrier(&self) -> u128 {
        self.total() - self.http_outcalls
    }

    /// What has been charged since `earlier`.
    pub fn since(&self, earlier: &ConsumedCycles) -> ConsumedCycles {
        let field = |name: &str, now: u128, before: u128| {
            now.checked_sub(before)
                .unwrap_or_else(|| panic!("consumed cycles for {name} fell from {before} to {now}"))
        };
        ConsumedCycles {
            memory: field("memory", self.memory, earlier.memory),
            compute_allocation: field(
                "compute_allocation",
                self.compute_allocation,
                earlier.compute_allocation,
            ),
            ingress_induction: field(
                "ingress_induction",
                self.ingress_induction,
                earlier.ingress_induction,
            ),
            instructions: field("instructions", self.instructions, earlier.instructions),
            request_and_response_transmission: field(
                "request_and_response_transmission",
                self.request_and_response_transmission,
                earlier.request_and_response_transmission,
            ),
            uninstall: field("uninstall", self.uninstall, earlier.uninstall),
            canister_creation: field(
                "canister_creation",
                self.canister_creation,
                earlier.canister_creation,
            ),
            http_outcalls: field("http_outcalls", self.http_outcalls, earlier.http_outcalls),
            burned_cycles: field("burned_cycles", self.burned_cycles, earlier.burned_cycles),
        }
    }

    /// Checks that the change in canister cycle balance `balance_diff` is consistent
    /// with the change in cycles consumption counters `self`, within the bounds of what the
    /// canister was charged for existing.
    pub fn check_against_balance(&self, balance_diff: u128) -> Result<(), String> {
        let total_diff = self.total();
        if balance_diff > total_diff {
            return Err(format!(
                "took {balance_diff} cycles out of the balance but recorded only {total_diff} as \
                 consumed ({} of it for the outcall itself, {} for the messages carrying \
                 it) — cycles left the balance that nothing was charged for",
                self.http_outcalls,
                self.carrier(),
            ));
        }
        // The cycles that were charged to the canister for existing.
        let drift = self.memory + self.compute_allocation;
        if balance_diff < total_diff - drift {
            return Err(format!(
                "recorded {total_diff} cycles as consumed ({} of it for the outcall itself, {} \
                 for the messages carrying it) but took only {balance_diff} out of the balance, \
                 a discrepancy beyond the {drift} charged for occupying memory across the \
                 window",
                self.http_outcalls,
                self.carrier(),
            ));
        }
        // total_diff - drift <= balance_diff <= total_diff
        Ok(())
    }
}

#[derive(CandidType, Deserialize)]
struct CanisterMetricsReply {
    cycles_consumed: ConsumedCycles,
}

#[derive(CandidType)]
struct CanisterMetricsRequest {
    canister_id: candid::Principal,
}

/// Reads what `canister` has been charged for, broken down by use case.
pub async fn consumed_cycles(
    node: &IcNodeSnapshot,
    canister: PrincipalId,
) -> Result<ConsumedCycles, String> {
    let agent = node.build_default_agent_async().await;
    let canister: candid::Principal = canister.into();
    let bytes = agent
        .query(
            &candid::Principal::management_canister(),
            "canister_metrics",
        )
        .with_effective_canister_id(canister)
        .with_arg(
            Encode!(&CanisterMetricsRequest {
                canister_id: canister
            })
            .unwrap(),
        )
        .call()
        .await
        .map_err(|err| format!("querying canister_metrics for {canister} failed: {err}"))?;

    Decode!(&bytes, CanisterMetricsReply)
        .map_err(|err| format!("decoding the canister_metrics reply failed: {err}"))
        .map(|reply| reply.cycles_consumed)
}

/// Reads `canister`'s own cycle balance.
pub async fn cycle_balance(node: &IcNodeSnapshot, canister: PrincipalId) -> Result<u128, String> {
    let agent = node.build_default_agent_async().await;
    let bytes = agent
        .query(&canister.0, "cycle_balance")
        .with_arg(Encode!(&()).unwrap())
        .call()
        .await
        .map_err(|err| format!("querying {canister}'s cycle balance failed: {err}"))?;

    Decode!(&bytes, u128).map_err(|err| format!("decoding the cycle balance failed: {err}"))
}

/// Reads `canister`'s balance once nothing is owed to it any more.
///
/// Waiting for the balance to stop *rising* rather than to stop moving is
/// deliberate: on a subnet that charges, the balance drifts downwards on its own as
/// the canister pays to exist, so "holding still" never happens. A refund is the
/// only thing that adds to it.
pub async fn settled_balance(node: &IcNodeSnapshot, canister: PrincipalId) -> Result<u128, String> {
    /// Long enough to outlast a delivered request context, after which nothing can
    /// still be owed.
    const ATTEMPTS: usize = 10;
    const INTERVAL: Duration = Duration::from_secs(10);

    let mut previous = cycle_balance(node, canister).await?;
    for _ in 0..ATTEMPTS {
        tokio::time::sleep(INTERVAL).await;
        let current = cycle_balance(node, canister).await?;
        if current <= previous {
            return Ok(current);
        }
        previous = current;
    }
    Err(format!(
        "{canister} kept being credited, last seen at {previous}"
    ))
}

/// A baseline to measure an outcall against, taken once the balance has settled.
///
/// Reads the consumption counters *before* the balance, which is what makes the
/// span they cover a superset of the span the balance covers — see
/// [`ConsumedCycles::check_against_balance`]. Pair it with [`settled_outcome`],
/// which reads them the other way round.
pub async fn settled_baseline(
    node: &IcNodeSnapshot,
    canister: PrincipalId,
) -> Result<(ConsumedCycles, u128), String> {
    settled_balance(node, canister).await?;
    let consumed = consumed_cycles(node, canister).await?;
    let balance = cycle_balance(node, canister).await?;
    Ok((consumed, balance))
}

/// The far end of a window opened by [`settled_baseline`]: the balance once it has
/// settled, then the consumption counters.
pub async fn settled_outcome(
    node: &IcNodeSnapshot,
    canister: PrincipalId,
) -> Result<(u128, ConsumedCycles), String> {
    let balance = settled_balance(node, canister).await?;
    let consumed = consumed_cycles(node, canister).await?;
    Ok((balance, consumed))
}

/// What an out-of-cycles rejection reports the replicas collectively spent.
///
/// Tying that figure to the caller's accounting is what makes a failed outcall
/// checkable at all: nothing else says how much of the withheld allowance was
/// actually used before the outcall gave up.
pub fn reported_spend(reject_message: &str) -> u128 {
    const PREFIX: &str = "collective spend of ";
    reject_message
        .split_once(PREFIX)
        .and_then(|(_, rest)| rest.split_whitespace().next())
        // `Cycles` renders with underscore separators.
        .map(|cycles| cycles.replace('_', ""))
        .and_then(|cycles| cycles.parse().ok())
        .unwrap_or_else(|| {
            panic!("expected a rejection naming what was spent, got: '{reject_message}'")
        })
}

// ===================== Pay-as-you-go fees =====================

/// What pay-as-you-go withholds up front for an outcall, and what it is quoted.
pub struct PaygFees {
    /// Charged up front and never refunded.
    pub base_fee: u128,
    /// The most the outcall could ever spend beyond the base fee. Withheld as
    /// per-replica allowances whenever the payment covers it.
    pub max_usage_fee: u128,
    /// How many replicas the allowances are split between.
    pub node_count: usize,
    request_size: NumBytes,
    replication_kind: ReplicationKind,
    subnet_size: usize,
}

/// Prices an outcall of the given `replication` the way the replica does, on a
/// `subnet_size`-node subnet that charges.
///
/// `request_size` is the size of the request's variable parts — its URL, headers,
/// body and transform context — which is what the base fee is charged on.
pub fn payg_fees(
    replication: &Replication,
    request_size: NumBytes,
    max_response_bytes: Option<NumBytes>,
    subnet_size: usize,
) -> PaygFees {
    let subnet_nodes = NumberOfNodes::from(subnet_size as u32);
    let cycles_config = CyclesAccountManagerSubnetConfig::new(
        subnet_size,
        CanisterCyclesCostSchedule::Normal,
        DEFAULT_REFERENCE_SUBNET_SIZE,
    );

    PaygFees {
        base_fee: paying_cycles_account_manager()
            .http_request_base_fee(request_size, replication, cycles_config)
            .real()
            .get(),
        max_usage_fee: paying_cycles_account_manager()
            .max_http_request_usage_fee(replication, max_response_bytes, subnet_nodes)
            .get(),
        node_count: replication.node_count(subnet_nodes),
        request_size,
        replication_kind: replication.kind(),
        subnet_size,
    }
}

/// Prices the non-flexible `request` the way the replica will, deriving its replication and
/// the size of its variable parts from the request itself.
pub fn fees_for(
    proxy_canister: CanisterId,
    request: UnvalidatedCanisterHttpRequestArgs,
    subnet_size: usize,
) -> PaygFees {
    let max_response_bytes = request.max_response_bytes.map(NumBytes::from);
    // The replication is whatever the request asks for, which is what the fees
    // depend on; the single node stands in for the subnet only to build a context.
    let dummy_context = CanisterHttpRequestContext::generate_from_args(
        UNIX_EPOCH,
        &RequestBuilder::default()
            .receiver(CanisterId::from(1))
            .sender(proxy_canister)
            .build(),
        request.into(),
        &BTreeSet::from([PrincipalId::new_node_test_id(0).into()]),
        RegistryVersion::from(1),
        CanisterCyclesCostSchedule::Normal,
        &mut rand::thread_rng(),
        /* pay_as_you_go_enabled = */ true,
    )
    .expect("the request should be valid enough to price");

    payg_fees(
        &dummy_context.replication,
        dummy_context.variable_parts_size(),
        max_response_bytes,
        subnet_size,
    )
}

/// A cycles account manager configured the way an application subnet that charges
/// is, which is all the fee functions above need of it.
fn paying_cycles_account_manager() -> CyclesAccountManager {
    CyclesAccountManager::new(
        NumInstructions::from(0),
        SubnetType::Application,
        PrincipalId::new_subnet_test_id(0).into(),
        CyclesAccountManagerConfig::application_subnet(),
    )
}

impl PaygFees {
    /// What the request has withheld from it up front out of a `payment`: the base
    /// fee, plus one allowance for each replica.
    pub fn withheld(&self, payment: u128) -> u128 {
        // The allowances are a per-replica share, so the total is rounded down to a
        // whole number of shares.
        self.base_fee + self.allowance(payment) * self.node_count as u128
    }

    /// What each replica may spend on the outcall, out of a `payment`.
    /// This is `min(payment - base_fee, max_usage_fee) / node_count`.
    pub fn allowance(&self, payment: u128) -> u128 {
        let refundable = payment.checked_sub(self.base_fee).unwrap_or_else(|| {
            panic!(
                "a payment of {payment} does not even cover the {} base fee",
                self.base_fee
            )
        });
        refundable.min(self.max_usage_fee) / self.node_count as u128
    }

    /// Checks what the reply refunded, against what the request withheld.
    /// Everything that wasn't withheld should be refunded.
    pub fn check_reply_refund(&self, payment: u128, refunded: u128) -> Result<(), String> {
        let withheld = self.withheld(payment);
        let expected = payment - withheld;
        if refunded == expected {
            return Ok(());
        }
        Err(format!(
            "returned {refunded} cycles on the reply, not the {expected} left of a \
             {payment}-cycle payment once {withheld} was withheld as {} allowances of {} each",
            self.node_count,
            self.allowance(payment),
        ))
    }

    /// Checks what a *successful* outcall was priced at: more than the base fee,
    /// which is taken at admission, and no more than `ic0.cost_http_request_v2`
    /// quotes for a round trip of `elapsed`.
    ///
    /// Separate from [`Self::check_charge`] because both hold where outcalls are
    /// free, while the balance never moves there. A failed outcall can exceed the
    /// quote — it pays for work that produced nothing deliverable — so assert it
    /// against `base_fee + `[`reported_spend`] instead, which is exact.
    pub fn check_consumption(
        &self,
        consumed_diff: &ConsumedCycles,
        elapsed: Duration,
    ) -> Result<(), String> {
        let outcall = consumed_diff.http_outcalls;
        if outcall <= self.base_fee {
            return Err(format!(
                "consumed {outcall} cycles, no more than the {} base fee taken at admission — \
                 so the spend the replicas reported on delivery was never priced",
                self.base_fee
            ));
        }
        let quoted = self.quote(elapsed);
        if outcall > quoted {
            return Err(format!(
                "consumed {outcall} cycles, more than the {quoted} that \
                 ic0.cost_http_request_v2 recommended"
            ));
        }
        Ok(())
    }

    /// [`Self::check_consumption`], plus [`ConsumedCycles::check_against_balance`].
    /// `balance_diff` and `consumed_diff` must span the same window. A failed outcall
    /// wants the latter on its own.
    pub fn check_charge(
        &self,
        consumed_diff: &ConsumedCycles,
        balance_diff: u128,
        elapsed: Duration,
    ) -> Result<(), String> {
        self.check_consumption(consumed_diff, elapsed)?;
        consumed_diff.check_against_balance(balance_diff)
    }

    /// Whether the `payment` is ample enough that the worst-case usage fee, rather
    /// than the payment itself, is what sizes the allowances.
    pub fn payment_is_ample(&self, payment: u128) -> bool {
        self.base_fee + self.max_usage_fee <= payment
    }

    /// What `ic0.cost_http_request_v2` quotes for an outcall that took the given time.
    pub fn quote(&self, elapsed: Duration) -> u128 {
        // What the server sends back and every replica downloads: a handful of bytes
        // of body plus a few overhead headers, which come to a couple of hundred
        // bytes with their names and values.
        const RAW_RESPONSE_CEILING: u64 = 512;
        // What a transform hands back, and so what consensus puts into a block. This
        // does not actually move the quote — the consensus term is floored at
        // `MAX_CANISTER_HTTP_REJECT_BYTES`, a reject of that size being deliverable
        // in place of any response — but it is the honest figure to quote for.
        const TRANSFORMED_RESPONSE_CEILING: u64 = 512;
        // Decoding half a kilobyte, clearing a vector and re-encoding.
        const TRANSFORM_INSTRUCTIONS: u64 = 100_000;

        paying_cycles_account_manager()
            .http_request_fee_v2(
                self.request_size,
                elapsed.min(MAX_RESPONSE_TIME),
                NumBytes::from(RAW_RESPONSE_CEILING),
                NumInstructions::from(TRANSFORM_INSTRUCTIONS),
                NumBytes::from(TRANSFORMED_RESPONSE_CEILING),
                self.replication_kind,
                CyclesAccountManagerSubnetConfig::new(
                    self.subnet_size,
                    CanisterCyclesCostSchedule::Normal,
                    DEFAULT_REFERENCE_SUBNET_SIZE,
                ),
            )
            .real()
            .get()
    }
}
