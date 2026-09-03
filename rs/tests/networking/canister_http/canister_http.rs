use anyhow::{Result, bail};
use candid::{CandidType, Decode, Deserialize, Encode};
use canister_test::Canister;
use canister_test::Runtime;
use ic_config::subnet_config::{CyclesAccountManagerConfig, DEFAULT_REFERENCE_SUBNET_SIZE};
use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerSubnetConfig};
pub use ic_https_outcalls_pricing::MAX_RESPONSE_TIME;
use ic_https_outcalls_pricing::fees::{consensus_fee, gossip_usage_fee};
use ic_management_canister_types_private::{
    CanisterHttpResponsePayload, HttpMethod, PRICING_VERSION_PAY_AS_YOU_GO, Payload,
    TransformContext, TransformFunc,
};
use ic_protobuf::registry::subnet::v1::CanisterCyclesCostSchedule as CanisterCyclesCostScheduleProto;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
pub use ic_replicated_state::metadata_state::subnet_call_context_manager::DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
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
    canister_http::{Replication, ReplicationKind, canister_http_threshold},
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use slog::info;
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

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

/// The nodes of the only application subnet.
///
/// Panics where there is more than one.
pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    get_app_subnet_node_snapshots_with_schedule(env, sole_app_subnet_schedule(env))
}

/// The `TestEnv` key under which the proxy canister of the application subnet on
/// `schedule` is recorded.
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

/// The proxy canister installed on the system subnet.
pub fn get_system_proxy_canister_id(env: &TestEnv) -> PrincipalId {
    get_proxy_canister_id_with_name(env, SYSTEM_PROXY_CANISTER_ID_PATH)
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
                "took {balance_diff} cycles out of the balance but recorded only {total_diff} as consumed"
            ));
        }
        // The cycles that were charged to the canister for existing.
        let drift = self.memory + self.compute_allocation;
        if balance_diff < total_diff - drift {
            return Err(format!(
                "recorded {total_diff} cycles as consumed but took only {balance_diff} out of the balance, \
                 a discrepancy beyond the {drift} charged for existing",
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
) -> Result<ConsumedCycles> {
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
        .map_err(|err| anyhow::anyhow!("querying canister_metrics for {canister} failed: {err}"))?;

    Decode!(&bytes, CanisterMetricsReply)
        .map_err(|err| anyhow::anyhow!("decoding the canister_metrics reply failed: {err}"))
        .map(|reply| reply.cycles_consumed)
}

/// Reads `canister`'s own cycle balance.
pub async fn cycle_balance(node: &IcNodeSnapshot, canister: PrincipalId) -> Result<u128> {
    let agent = node.build_default_agent_async().await;
    let bytes = agent
        .query(&canister.0, "cycle_balance")
        .with_arg(Encode!(&()).unwrap())
        .call()
        .await
        .map_err(|err| anyhow::anyhow!("querying {canister}'s cycle balance failed: {err}"))?;

    Decode!(&bytes, u128).map_err(|err| anyhow::anyhow!("decoding the cycle balance failed: {err}"))
}

/// How frequently the balance is re-read while waiting for it to settle.
const SETTLE_INTERVAL: Duration = Duration::from_secs(2);

/// How long to keep waiting for the balance to settle.
const SETTLE_BUDGET: Duration =
    Duration::from_secs(DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT.as_secs() + 10);

/// How long the balance has to not increase for it to be considered settled.
const SETTLE_QUIET: Duration = Duration::from_secs(15);

/// Waits for `canister`'s cycle balance to stop increasing, then returns it.
pub async fn settled_balance(node: &IcNodeSnapshot, canister: PrincipalId) -> Result<u128> {
    let deadline = Instant::now() + SETTLE_BUDGET;
    let mut previous = cycle_balance(node, canister).await?;
    let mut last_rise = Instant::now();
    loop {
        tokio::time::sleep(SETTLE_INTERVAL).await;
        let current = cycle_balance(node, canister).await?;
        if current > previous {
            last_rise = Instant::now();
        } else if last_rise.elapsed() >= SETTLE_QUIET {
            return Ok(current);
        }
        previous = current;
        if Instant::now() >= deadline {
            bail!("{canister} was still being credited after {SETTLE_BUDGET:?}");
        }
    }
}

/// The consumed cycles and balance before an outcall is made.
pub struct Baseline {
    pub consumed: ConsumedCycles,
    pub balance: u128,
}

/// Opens a measurement window on `canister`, once nothing is owed to it any more.
pub async fn settled_baseline(node: &IcNodeSnapshot, canister: PrincipalId) -> Result<Baseline> {
    settled_balance(node, canister).await?;
    let consumed = consumed_cycles(node, canister).await?;
    let balance = cycle_balance(node, canister).await?;
    Ok(Baseline { consumed, balance })
}

/// What one outcall cost its caller, over a window opened by [`settled_baseline`].
pub struct SettledCharge {
    /// What the caller consumed over the window, by use case.
    pub consumed: ConsumedCycles,
    /// What left its balance over the window.
    pub charged: u128,
}

/// Closes the window opened by `baseline`: reads the balance and the consumption
/// counters until the two agree, i.e. until every refund the outcall still owed has
/// been credited.
///
/// A per-replica allowance that has not been refunded yet has left the caller's balance
/// with nothing recording it as consumed. This is exactly the discrepancy
/// [`ConsumedCycles::check_against_balance`] rejects.
pub async fn settled_charge(
    node: &IcNodeSnapshot,
    canister: PrincipalId,
    baseline: &Baseline,
) -> Result<SettledCharge> {
    let deadline = Instant::now() + SETTLE_BUDGET;
    loop {
        let balance = cycle_balance(node, canister).await?;
        let consumed = consumed_cycles(node, canister)
            .await?
            .since(&baseline.consumed);
        let disagreement = match baseline.balance.checked_sub(balance) {
            Some(charged) => match consumed.check_against_balance(charged) {
                Ok(()) => return Ok(SettledCharge { consumed, charged }),
                Err(disagreement) => disagreement,
            },
            None => format!(
                "was credited cycles it never paid: its balance grew from {} to {balance}",
                baseline.balance
            ),
        };
        if Instant::now() >= deadline {
            bail!("after {SETTLE_BUDGET:?} of waiting: {canister} {disagreement}");
        }
        tokio::time::sleep(SETTLE_INTERVAL).await;
    }
}

/// What an out-of-cycles rejection reports: how many replicas had reported their
/// spend by the time the outcall was given up on, and what they had spent between
/// them. Determined by parsing the reject message.
pub struct OutOfCyclesReport {
    /// How many replicas had reported when the outcall was given up on.
    pub replicas: usize,
    /// What those replicas had spent between them.
    pub spent: u128,
}

pub fn reported_spend(reject_message: &str) -> Result<u128, String> {
    reported_out_of_cycles(reject_message).map(|report| report.spent)
}

pub fn reported_out_of_cycles(reject_message: &str) -> Result<OutOfCyclesReport, String> {
    let malformed =
        || format!("expected a rejection naming what was spent, got: '{reject_message}'");
    // `Cycles` renders with underscore separators.
    let number = |token: &str| token.replace('_', "").parse().ok();

    let replicas = reject_message
        .split_once("Out of cycles: ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(number)
        .ok_or_else(malformed)?;
    let spent = reject_message
        .split_once("collective spend of ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(number)
        .ok_or_else(malformed)?;
    Ok(OutOfCyclesReport {
        replicas: replicas as usize,
        spent,
    })
}

/// Base arguments for a `GET` outcall to `url` that opts into pay-as-you-go
pub fn pay_as_you_go_args(
    proxy_canister: PrincipalId,
    url: String,
) -> UnvalidatedCanisterHttpRequestArgs {
    UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some(vec![]),
        // Strip all headers, so consensus can be reached
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: proxy_canister.into(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: Some(PRICING_VERSION_PAY_AS_YOU_GO),
    }
}

/// How much the response headers of the httpbin under test may add on top of the
/// body it was asked for.
const HTTPBIN_RESPONSE_HEADER_BYTES: u64 = 512;

/// What a test knows about the response(s) an outcall delivered.
pub struct DeliveredResponse {
    /// A lower bound on what each replica fetched from the server.
    downloaded_at_least: NumBytes,
    /// An upper bound on what each replica fetched from the server.
    downloaded_at_most: NumBytes,
    /// The smallest of the Candid-encoded responses that reached a block, which a
    /// lower bound on the consensus fee is computed from.
    smallest: NumBytes,
    /// The largest of them, which an upper bound is computed from. The same as
    /// `smallest` wherever the replicas had to agree on a single response.
    largest: NumBytes,
    /// How many replicas included a response of their own.
    ///
    /// `None` for non-flexible outcalls.
    delivered_by: Option<u32>,
}

impl DeliveredResponse {
    /// The response the proxy canister's `transform` method makes of the `body` a
    /// non-flexible outcall delivered.
    pub fn transformed(body: &[u8]) -> Self {
        let content = NumBytes::from(
            CanisterHttpResponsePayload {
                status: 200,
                headers: vec![],
                body: body.to_vec(),
            }
            .encode()
            .len() as u64,
        );
        let body = body.len() as u64;
        Self {
            downloaded_at_least: NumBytes::from(body),
            downloaded_at_most: NumBytes::from(body + HTTPBIN_RESPONSE_HEADER_BYTES),
            smallest: content,
            largest: content,
            delivered_by: None,
        }
    }

    /// The `payloads` a flexible outcall with no transform delivered, read off the
    /// responses themselves.
    pub fn untransformed(payloads: &[CanisterHttpResponsePayload]) -> Self {
        let downloaded: Vec<u64> = payloads
            .iter()
            .map(|p| {
                let headers: u64 = p
                    .headers
                    .iter()
                    .map(|h| (h.name.len() + h.value.len()) as u64)
                    .sum();
                headers + p.body.len() as u64
            })
            .collect();
        let encoded: Vec<u64> = payloads.iter().map(|p| p.encode().len() as u64).collect();
        Self {
            downloaded_at_least: NumBytes::from(downloaded.iter().copied().min().unwrap_or(0)),
            downloaded_at_most: NumBytes::from(downloaded.iter().copied().max().unwrap_or(0)),
            smallest: NumBytes::from(encoded.iter().copied().min().unwrap_or(0)),
            largest: NumBytes::from(encoded.iter().copied().max().unwrap_or(0)),
            delivered_by: Some(payloads.len() as u32),
        }
    }
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
    // Dummy context to determine the request size and replication.
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

/// Estimate of what a transform of a `body`-byte response costs.
fn transform_instructions_at_most(body: NumBytes) -> u64 {
    /// Entering the query, decoding a `TransformArgs` header and re-encoding a
    /// response record.
    const ENTRY: u64 = 2_000_000;
    /// Moving each byte of the response through the decode and the re-encode.
    const PER_BYTE: u64 = 200;

    ENTRY.saturating_add(PER_BYTE.saturating_mul(body.get()))
}

/// A cycles account manager for a charging subnet.
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
            "returned {refunded} cycles on the reply, instead of the {expected} expected.",
        ))
    }

    /// Checks what a *successful* outcall was priced at: no less than the parts of
    /// the price the caller can work out from `delivered`, and no more than
    /// `ic0.cost_http_request_v2` quotes for a round trip of `elapsed` that
    /// delivered it.
    pub fn check_consumption(
        &self,
        consumed_diff: &ConsumedCycles,
        delivered: &DeliveredResponse,
        elapsed: Duration,
    ) -> Result<(), String> {
        let outcall = consumed_diff.http_outcalls;
        let floor = self.floor_of(delivered);
        if outcall < floor {
            return Err(format!(
                "consumed {outcall} cycles, less than the {floor} floor price derived \
                from the response"
            ));
        }
        let ceiling = self.quote_of(delivered, elapsed);
        if outcall > ceiling {
            return Err(format!(
                "consumed {outcall} cycles, more than the {ceiling} that \
                 ic0.cost_http_request_v2 recommends for the response it delivered"
            ));
        }
        Ok(())
    }

    /// The least a *successful* outcall delivering `delivered` can have been
    /// charged: its base fee, the consensus fee for the bytes that reached a block,
    /// and the bytes the replicas that delivered them had to download.
    pub fn floor_of(&self, delivered: &DeliveredResponse) -> u128 {
        self.base_fee
            + self.consensus_floor(delivered)
            + self.delivering_replicas(delivered)
                * (self.byte_fee(delivered.downloaded_at_least.get())
                    + self.gossip_floor(delivered))
    }

    /// What one replica that delivered a response was charged for gossiping it to
    /// the rest of the subnet.
    fn gossip_floor(&self, delivered: &DeliveredResponse) -> u128 {
        match self.replication_kind {
            ReplicationKind::FullyReplicated => 0,
            ReplicationKind::NonReplicated | ReplicationKind::Flexible { .. } => gossip_usage_fee(
                delivered.smallest,
                NumberOfNodes::from(self.subnet_size as u32),
            )
            .get(),
        }
    }

    /// How many replicas had to fetch the response for it to be delivered, and were
    /// therefore charged for downloading it.
    fn delivering_replicas(&self, delivered: &DeliveredResponse) -> u128 {
        delivered
            .delivered_by
            .map_or(canister_http_threshold(self.node_count) as u128, u128::from)
    }

    /// The least consensus can have charged for putting `delivered` into a block.
    fn consensus_floor(&self, delivered: &DeliveredResponse) -> u128 {
        let in_block = delivered.delivered_by.map_or(1, u128::from);
        consensus_fee(
            in_block * delivered.smallest.get() as u128,
            NumberOfNodes::from(self.subnet_size as u32),
        )
        .get()
    }

    /// What one replica is charged for downloading `bytes` from the server.
    /// Read out of `ic0.cost_http_request_v2` as the difference between two quotes.
    fn byte_fee(&self, bytes: u64) -> u128 {
        (self.priced_at(Duration::ZERO, bytes, 0, 0) - self.priced_at(Duration::ZERO, 0, 0, 0))
            / self.node_count as u128
    }

    /// Checks what an outcall that failed with "out-of-cycles" was charged: its base fee,
    /// plus what every replica that attempted it spent.
    pub fn check_failed_consumption(
        &self,
        consumed_diff: &ConsumedCycles,
        report: &OutOfCyclesReport,
        payment: u128,
    ) -> Result<(), String> {
        let outcall = consumed_diff.http_outcalls;
        let floor = self.base_fee + report.spent;
        if outcall < floor {
            return Err(format!(
                "consumed {outcall} cycles, less than the {floor} its {} base fee and the \
                 {} the {} replicas that had reported spent between them come to",
                self.base_fee, report.spent, report.replicas
            ));
        }
        let unheard = self.node_count.saturating_sub(report.replicas) as u128;
        let ceiling = floor + unheard * self.allowance(payment);
        if outcall > ceiling {
            return Err(format!(
                "consumed {outcall} cycles, more than the {ceiling} the {} reported spent \
                 comes to once the {unheard} replicas that had yet to report are each \
                 allowed their whole {} allowance — so more was charged than the allowances \
                 could cover",
                report.spent,
                self.allowance(payment)
            ));
        }
        Ok(())
    }

    /// Whether the `payment` is ample enough that the worst-case usage fee, rather
    /// than the payment itself, is what sizes the allowances.
    pub fn payment_is_ample(&self, payment: u128) -> bool {
        self.base_fee + self.max_usage_fee <= payment
    }

    /// What `ic0.cost_http_request_v2` quotes for an outcall that took the given
    /// time and fetched a short response.
    pub fn quote(&self, elapsed: Duration) -> u128 {
        // What the server sends back and every replica downloads: a handful of bytes
        // of body plus a few overhead headers, which come to a couple of hundred
        // bytes with their names and values.
        const RAW_RESPONSE_CEILING: u64 = 512;
        // What a transform hands back, and so what consensus puts into a block.
        const TRANSFORMED_RESPONSE_CEILING: u64 = 512;

        self.priced_at(
            elapsed,
            RAW_RESPONSE_CEILING,
            transform_instructions_at_most(NumBytes::from(RAW_RESPONSE_CEILING)),
            TRANSFORMED_RESPONSE_CEILING,
        )
    }

    /// What `ic0.cost_http_request_v2` quotes for an outcall that took `elapsed` and
    /// delivered `delivered`.
    pub fn quote_of(&self, delivered: &DeliveredResponse, elapsed: Duration) -> u128 {
        self.priced_at(
            elapsed,
            delivered.downloaded_at_most.get(),
            transform_instructions_at_most(delivered.downloaded_at_most),
            delivered.largest.get(),
        )
    }

    /// The least the replicas that delivered `delivered` can have been charged for
    /// a round trip that took at least `response_time`.
    pub fn time_floor(&self, delivered: &DeliveredResponse, response_time: Duration) -> u128 {
        self.delivering_replicas(delivered) * self.time_fee(response_time)
    }

    /// What one replica is charged for a round trip of `response_time`.
    /// Read out of `ic0.cost_http_request_v2` as the difference between two quotes.
    fn time_fee(&self, response_time: Duration) -> u128 {
        (self.priced_at(response_time, 0, 0, 0) - self.priced_at(Duration::ZERO, 0, 0, 0))
            / self.node_count as u128
    }

    /// `ic0.cost_http_request_v2` for an outcall with exactly these resource usages.
    fn priced_at(
        &self,
        elapsed: Duration,
        raw_response_bytes: u64,
        transform_instructions: u64,
        transformed_response_bytes: u64,
    ) -> u128 {
        paying_cycles_account_manager()
            .http_request_fee_v2(
                self.request_size,
                elapsed.min(MAX_RESPONSE_TIME),
                NumBytes::from(raw_response_bytes),
                NumInstructions::from(transform_instructions),
                NumBytes::from(transformed_response_bytes),
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
