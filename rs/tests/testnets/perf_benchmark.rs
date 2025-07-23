// Set up a small high performance testnet containing:
//   one 1-node System and one 1-node Application subnets, single API boundary node, single ic-gateway and a p8s (with grafana) VM.
// The single system subnet node uses the default: 6 vCPUs, 24 GiB of RAM, and 50 GiB disk,
// while the single application subnet node uses: 64 vCPUs, 512 GiB of RAM, and 500 GiB disk
// and uses physical SSDs for the image liek the production machines.
//
// You can setup this testnet with a lifetime of 1800 mins by assigning an unused machine to PERF_HOST and
// executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create perf_benchmark --lifetime-mins=1800 --output-dir=./perf_benchmark --with_ssh_auth_sock -- --test_tmpdir=./perf_benchmark
//
// The --output-dir=./perf_benchmark will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./perf_benchmark will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i perf_benchmarking/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the address of the IC node from the ict console output:
//
//   {
//     nodes: [
//       {
//         id: y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae,
//         ipv6: 2a0b:21c0:4003:2:5034:46ff:fe3c:e76f
//       }
//     ],
//     subnet_id: 5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe,
//     subnet_type: application
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.perf_benchmarking--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.perf_benchmarking--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.perf_benchmarking--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy benchmarking!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::{
    farm::HostFeature,
    group::SystemTestGroup,
    ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm, IC_GATEWAY_VM_NAME},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

const PERF_HOST: &str = "dm1-dll29.dm1.dfinity.network";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(std::time::Duration::MAX)
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
	sudo virsh dumpxml $VMNAME > $CONFIG
	IMAGE=$(cat $CONFIG | sed -n 45p | cut -d\' -f 2)
	echo "Moving $VMNAME to /dev/hostlvm/guest"
	sudo dd if=$IMAGE of=/dev/hostlvm/guestos status=progress bs=512MiB oflag=direct iflag=direct

        # Patch the config to point to the disk device
	sed -i '43s/file/block/' $CONFIG
	sed -i "44s/\/>/ discard=\'unmap\' cache=\'none\'\/>/" $CONFIG
	sed -i "45s/file.*/dev='\/dev\/hostlvm\/guestos'\/>/" $CONFIG
	sudo virsh create $CONFIG
        echo "Migration done"
	rm $CONFIG
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

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .with_required_host_features(vec![HostFeature::Host(PERF_HOST.to_string())])
                .add_nodes(1),
        )
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    switch_to_ssd(PERF_HOST);

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    env.sync_with_prometheus_by_name("", Some(ic_gateway_domain.to_string()));
}
