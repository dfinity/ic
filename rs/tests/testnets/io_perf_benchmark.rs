// This test is designed for scenarios where high IO performance is essential.
// It leverages dedicated performance hosts with LVM partitions composed of multiple high-performance SSDs, mirroring production environments.
// Specify the hosts via the PERF_HOSTS environment variable; each listed host will be allocated to a replica node.
// Alternatively, you can specify the number of hosts via the NUM_PERF_HOSTS environment variable.
//
// Set up a testnet containing:
//   one System subnet with the hosts specified in the PERF_HOSTS environment variable,
//   a single API boundary node, single ic-gateway/s and a p8s (with grafana) VM.
// All replica nodes use the following resources: 64 vCPUs, 480GiB of RAM, and 5 TiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ PERF_HOSTS="dm1-dll29.dm1.dfinity.network" ict testnet create io_perf_benchmark --lifetime-mins=1440 --output-dir=./io_perf_benchmark -- --test_tmpdir=./io_perf_benchmark --test_env=PERF_HOSTS
//
// The --output-dir=./io_perf_benchmark will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./io_perf_benchmark will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i io_perf_benchmark/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae",
//         "ipv6": "2a0b:21c0:4003:2:5034:46ff:fe3c:e76f"
//       },
//       {
//         "id": "df2nt-xpdbh-kekha-igdy2-t2amw-ui36p-dqrte-ojole-syd4u-sfhqz-3ae",
//         "ipv6": "2a0b:21c0:4003:2:50d2:3ff:fe24:32fe"
//       }
//     ],
//     "subnet_id": "5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe",
//     "subnet_type": "system"
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     "prometheus": "Prometheus Web UI at http://prometheus.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems",
//     "grafana": "Grafana at http://grafana.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems",
//     "progress_clock": "IC Progress Clock at http://grafana.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s\u0026from=now-5m\u0026to=now",
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm};
use ic_system_test_driver::driver::pot_dsl::PotSetupFn;
use ic_system_test_driver::driver::vector_vm::VectorVm;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    group::SystemTestGroup,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
};
use nns_dapp::{nns_dapp_customizations, set_authorized_subnets, set_icp_xdr_exchange_rate};
use slog::info;

const NUM_IC_GATEWAYS: u64 = 1;
const DEFAULT_IMAGE_SIZE_GIB: u64 = 5120;
const DEFAULT_NUM_HOSTS: u64 = 1;

fn main() -> Result<()> {
    let perf_hosts = std::env::var("PERF_HOSTS")
        .map(|s| s.split(',').map(|s| s.to_string()).collect::<Vec<String>>())
        .ok();

    // If hosts is not specified, Farm will automatically select this number of available hosts to use.
    // If both hosts and num_hosts are set, hosts will be used and num_hosts will be ignored.
    let num_hosts = std::env::var("NUM_PERF_HOSTS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    // By default, the image size is set to 5 TiB, which supports testing up to 2 TiB of state under heavy write workloads.
    // Note: Migrating such a large image to the LVM partition on the hosts can be time-consuming.
    // To use a different image size, set the `IMAGE_SIZE_GIB` environment variable.
    let image_size_gib = std::env::var("IMAGE_SIZE_GIB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_IMAGE_SIZE_GIB);

    let config = Config::new(perf_hosts, num_hosts, image_size_gib);

    SystemTestGroup::new()
        .with_setup(config.build())
        .with_timeout_per_test(std::time::Duration::MAX) // Switching to SSD takes long time
        .execute_from_args()?;
    Ok(())
}

fn switch_to_ssd(host: &str) {
    let script = r##"
        #!/bin/bash
        set -e
        exec 2>&1

        # Get the name of the currently running VM.
        # virsh prints four lines for a single instance running, two lines of header,
        # VM info and trailing empty line. The script should fail if the format is
        # different or there are multiple VMs running. The trailing line is lost when
        # assigning to a variable.
        virsh_list=$(sudo virsh list)
        if [ $(echo "$virsh_list" | wc -l) -ne 3 ]; then
                echo "Unexpected virsh list output"
                exit 2
        fi
        VMNAME=$(echo "$virsh_list" | awk '{ if (NR==3) print $2 }')

        # Shutdown the VM
        echo "Shutting down $VMNAME"
        for i in {1..300}; do
                if [ $(sudo virsh list | grep $VMNAME | wc -l) -eq 0 ]; then
                        break
                fi
                echo Waiting for shutdown of $VMNAME: retry $i...
                sleep 1
                sudo virsh shutdown $VMNAME || true
        done

        # Get the file name and dd it to disk device
        CONFIG=$(mktemp)
        trap "rm -f $CONFIG" INT TERM EXIT
        sudo virsh dumpxml $VMNAME > $CONFIG
        IMAGE="$(xmlstarlet sel -t -v "string(/domain/devices/disk[target[@dev='vda']]/source/@file)" "$CONFIG")"
        echo "Moving $VMNAME to /dev/hostlvm/guest"

        # Patch the config to point to the disk device
        xmlstarlet ed --inplace -a "//domain/devices/disk[target[@dev='vda']]/driver" -t attr -n discard -v unmap "$CONFIG"
        xmlstarlet ed --inplace -a "//domain/devices/disk[target[@dev='vda']]/driver" -t attr -n cache -v none "$CONFIG"
        xmlstarlet ed --inplace -u "//domain/devices/disk[target[@dev='vda']]/@type" -v block "$CONFIG"
        xmlstarlet ed --inplace -d "//domain/devices/disk[target[@dev='vda']]/source/@file" "$CONFIG"
        xmlstarlet ed --inplace -a "//domain/devices/disk[target[@dev='vda']]/source" -t attr -n dev -v "/dev/hostlvm/guestos" "$CONFIG"
        sudo dd if=$IMAGE of=/dev/hostlvm/guestos status=progress bs=512MiB oflag=direct iflag=direct

        sudo virsh create $CONFIG
        echo "Migration done"
    "##;

    if std::env::var("SSH_AUTH_SOCK") == Err(std::env::VarError::NotPresent) {
        panic!("No $SSH_AUTH_SOCK vairable provided");
    }
    let mut ssh = Command::new("ssh")
        .arg("farm@".to_owned() + host)
        .arg(script)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    for l in BufReader::new(ssh.stdout.as_mut().unwrap()).lines() {
        println!("SSH out: {}", l.unwrap());
    }

    assert!(ssh.wait().unwrap().success());
}

#[derive(Clone, Debug)]
pub struct Config {
    hosts: Option<Vec<String>>,
    num_hosts: Option<u64>,
    image_size_gib: u64,
}

impl Config {
    pub fn new(hosts: Option<Vec<String>>, num_hosts: Option<u64>, image_size_gib: u64) -> Config {
        Config {
            hosts,
            num_hosts,
            image_size_gib,
        }
    }

    /// Builds the IC instance.
    pub fn build(self) -> impl PotSetupFn {
        move |env: TestEnv| setup(env, self)
    }
}

pub fn setup(env: TestEnv, config: Config) {
    // start p8s for metrics and dashboards
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");
    let mut vector_vm = VectorVm::new().with_required_host_features(vec![HostFeature::Performance]);
    vector_vm.start(&env).expect("Failed to start Vector VM");

    // set up IC overriding the default resources to be more powerful
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(config.image_size_gib)),
    };
    let mut ic = InternetComputer::new()
        .with_api_boundary_nodes(1)
        .with_default_vm_resources(vm_resources);

    // `HostFeature::IoPerformance` is required for the system subnet to use the performance hosts even if hosts are specified.
    let mut subnet = Subnet::new(SubnetType::System)
        .with_required_host_features(vec![HostFeature::IoPerformance]);

    let logger = env.logger();

    if let Some(hosts) = config.hosts {
        info!(
            logger,
            "Adding {} nodes with specified hosts: {:?}",
            hosts.len(),
            hosts
        );
        for host in hosts.iter() {
            subnet =
                subnet.add_node_with_required_host_features(vec![HostFeature::Host(host.clone())]);
        }
    } else {
        let num_hosts = config.num_hosts.unwrap_or(DEFAULT_NUM_HOSTS);
        info!(
            logger,
            "Farm is automatically selecting {} avaliable hosts", num_hosts
        );
        subnet = subnet.add_nodes(num_hosts as usize);
    }

    ic = ic.add_subnet(subnet);

    let vms = ic
        .setup_and_start_return_vms(&env)
        .expect("Failed to setup IC under test");

    let topology_snapshot = env.topology_snapshot();
    let mut switch_to_ssd_handles = Vec::new();
    for node in topology_snapshot.subnets().next().unwrap().nodes() {
        let node_id = node.node_id.to_string();
        let vm = vms.get(&node_id).expect("Failed to get VM for node");
        info!(
            env.logger(),
            "Node {} is allocated to host: {}", node_id, vm.hostname
        );
    }

    // set up NNS canisters
    // Installing the NNS canisters enables submitting proposals to upgrade the replica version without needing to redeploy the testnet.
    install_nns_with_customizations_and_check_progress(
        topology_snapshot,
        nns_dapp_customizations(),
    );

    // sets the exchange rate to 12 XDR per 1 ICP
    set_icp_xdr_exchange_rate(&env, 12_0000);

    // sets the exchange rate to 12 XDR per 1 ICP
    set_authorized_subnets(&env);

    // deploys the ic-gateway/s
    for i in 0..NUM_IC_GATEWAYS {
        let ic_gateway_name = format!("ic-gateway-{}", i);
        IcGatewayVm::new(&ic_gateway_name)
            .with_required_host_features(vec![HostFeature::Performance])
            .start(&env)
            .expect("failed to setup ic-gateway");
    }
    let ic_gateway = env.get_deployed_ic_gateway("ic-gateway-0").unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    env.sync_with_prometheus_by_name("", Some(ic_gateway_domain.to_string()));
    vector_vm
        .sync_targets(&env)
        .expect("Failed to sync Vector targets");
}
