use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env_api::{
    HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr,
};
use ic_system_test_driver::driver::test_setup::InfraProvider;
use ic_system_test_driver::driver::universal_vm::*;
use ic_system_test_driver::driver::{
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::*,
};
use ic_system_test_driver::util::{self, create_and_install};
pub use ic_types::{CanisterId, PrincipalId};
use slog::info;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

pub enum PemType {
    PemCert,
    PemKey,
}

pub fn await_nodes_healthy(env: &TestEnv) {
    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
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
    // Set up Universal VM with HTTP Bin testing service
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .enable_ipv4()
        .start(&env)
        .expect("failed to set up universal VM");

    start_httpbin_on_uvm(&env);

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
    install_nns_canisters(&env);
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
        InfraProvider::K8s => deployed_universal_vm.get_vm().unwrap().ipv4.unwrap(),
    }
}

pub fn start_httpbin_on_uvm(env: &TestEnv) {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let vm = deployed_universal_vm.get_vm().unwrap();
    let ipv6 = vm.ipv6.to_string();
    let ipv4 = vm.ipv4.map_or("".to_string(), |ipv4| ipv4.to_string());
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

        echo "Generate ipv6 service cert with root cert and key, using `minica` ..."
        mkdir certs
        cd certs
        cp /config/cert.pem minica.pem
        cp /config/key.pem minica-key.pem
        chmod -R 755 ./

        echo "Making certs directory in $(pwd) ..."
        docker load -i /config/minica.tar
        docker tag bazel/image:image minica
        docker run \
            -v "$(pwd)":/output \
            minica \
            -ip-addresses="$ipv6${{ipv4:+,$ipv4}}"

        echo "Updating service certificate folder name so it can be fed to ssl-proxy container ..."
        sudo mv "$ipv6" ipv6
        sudo chmod -R 755 ipv6

        echo "Setting up httpbin on port 20443 ..."
        docker load -i /config/httpbin_image.tar
        docker tag bazel/rs/tests/httpbin-rs:httpbin_image httpbin
        sudo docker run \
            --rm \
            -d \
            -p 20443:80 \
            -v "$(pwd)/ipv6":/certs \
            --name httpbin \
            httpbin \
            --cert-file /certs/cert.pem --key-file /certs/key.pem --port 80
    "#
        ))
        .unwrap_or_else(|e| panic!("Could not start httpbin on {UNIVERSAL_VM_NAME} because {e:?}"));
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
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

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
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
    Canister::new(
        runtime,
        CanisterId::unchecked_from_principal(PrincipalId::from(proxy_canister_id)),
    )
}
