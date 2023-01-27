use crate::driver::farm::HostFeature;
use crate::driver::ic::AmountOfMemoryKiB;
use crate::driver::ic::ImageSizeGiB;
use crate::driver::ic::NrOfVCPUs;
use crate::driver::ic::VmResources;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::retry;
use crate::driver::test_env_api::HasDependencies;
use crate::driver::test_env_api::HasVmName;
use crate::driver::test_env_api::ADMIN;
use crate::driver::test_env_api::{HasGroupSetup, HasTestEnv, SshSession};
use crate::driver::universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms};
use anyhow::bail;
use reqwest;
use slog::info;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

const SSH_FIRST_COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const SSH_FIRST_COMMAND_BACKOFF: Duration = Duration::from_secs(5);

const SSH_SINGLE_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const SSH_SINGLE_COMMAND_BACKOFF: Duration = Duration::from_secs(2);

const DOCKER_OPTS: &str = "-e DFX_NETWORK=small03 -e WDIO_BROWSER=chrome -e WDIO_REPETITIONS=10000";
const DOCKER_IMAGE_NAME: &str = "bazel/rs/tests/replicated_tests:nns_dapp_specs_image";
const DOCKER_COMMAND: &str = "npm run test-fast -- --spec specs/launchpad.e2e.ts";

const UVM_LOG_FILE: &str = "/home/admin/docker.log";
const UVM_CONTAINER_FILE: &str = "/home/admin/CONTAINER.txt";

const NNS_DAPP_SPECS_UVM_CONFIG_IMAGE_PATH: &str = "rs/tests/nns_dapp_specs_uvm_config_image.zst";

const UVM_NUM_CPUS: NrOfVCPUs = NrOfVCPUs::new(2);
const UVM_MEMORY_SIZE: AmountOfMemoryKiB = AmountOfMemoryKiB::new(16777216); // 16 GiB
const UVM_BOOT_IMAGE_MIN_SIZE: ImageSizeGiB = ImageSizeGiB::new(4);

fn workload_vm_name(vm_id: &str) -> String {
    format!("workload_vm_{}", vm_id)
}

pub fn distributed_config(env: TestEnv, uvm_labels: Vec<String>) {
    env.ensure_group_setup_created();
    let log = env.logger();
    uvm_labels.into_iter().for_each(|label| {
        let uvm_name = workload_vm_name(&label);
        info!(log, "Preparing Universal VM {uvm_name} ...");

        UniversalVm::new(uvm_name.clone())
            .with_config_img(env.get_dependency_path(NNS_DAPP_SPECS_UVM_CONFIG_IMAGE_PATH))
            .disable_ipv4()
            .with_required_host_features(vec![
                HostFeature::SnsLoadTest,
                HostFeature::Host("fr1-dll07.fr1.dfinity.network".to_string()),
            ])
            .with_vm_resources(VmResources {
                vcpus: Some(UVM_NUM_CPUS),
                memory_kibibytes: Some(UVM_MEMORY_SIZE),
                boot_image_minimal_size_gibibytes: Some(UVM_BOOT_IMAGE_MIN_SIZE),
            })
            .start(&env)
            .unwrap_or_else(|_| panic!("failed to set up {uvm_name}"));
        info!(log, "Universal VM {uvm_name} installed!");

        let deployed_uvm = env.get_deployed_universal_vm(&uvm_name).unwrap();
        let uvm = deployed_uvm.get_vm().unwrap();
        let uvm_ipv6 = uvm.ipv6;
        let uvm_url = format!("http://[{uvm_ipv6:?}]:8080");
        let uvm_url = reqwest::Url::parse(&uvm_url)
            .unwrap_or_else(|_| panic!("Could not parse URL: {uvm_url}"));
        info!(log, "Started Universal VM at {uvm_url}");

        await_docker_start(&deployed_uvm);
    });
}

/// Installs a Universal VM that generates workload for the production IC
pub fn distributed_test(env: TestEnv, label: &str, timeout: Duration) {
    let uvm_name = workload_vm_name(label);
    let deployed_uvm = env.get_deployed_universal_vm(&uvm_name).unwrap();

    await_docker_completion(&deployed_uvm, timeout);

    fetch_docker_log(&deployed_uvm);
}

fn await_docker_start(universal_vm: &DeployedUniversalVm) {
    let env = universal_vm.test_env();
    let f = || -> Result<(), anyhow::Error> {
        let log = env.logger();
        let uvm_name = universal_vm.vm_name();

        info!(log, "Obtaining SSH session for {} ...", uvm_name);

        let session = universal_vm.get_ssh_session(ADMIN)?;

        info!(log, "Obtained SSH session for {}", uvm_name);

        let res = universal_vm.block_on_bash_script_from_session(&session, &format!("docker run -d --network=host {DOCKER_OPTS} {DOCKER_IMAGE_NAME} {DOCKER_COMMAND} > {UVM_CONTAINER_FILE}"));
        if let Ok(res) = res {
            info!(
                log,
                "Got Ok result from ssh docker start command: `{}`", res
            );
            Ok(())
        } else {
            bail!("Got Error result from ssh docker start command: {:?}", res);
        }
    };
    retry(
        env.logger(),
        SSH_FIRST_COMMAND_TIMEOUT,
        SSH_FIRST_COMMAND_BACKOFF,
        f,
    )
    .map(|_| {
        info!(
            env.logger(),
            "Started workload generation on {}!",
            universal_vm.vm_name()
        )
    })
    .unwrap_or_else(|_| {
        panic!(
            "Workload generation at {} did not start on time",
            universal_vm.vm_name()
        )
    })
}

fn await_docker_completion(universal_vm: &DeployedUniversalVm, timeout: Duration) {
    let env = universal_vm.test_env();
    let f = || -> Result<(), anyhow::Error> {
        let _log = env.logger();
        let uvm_name = universal_vm.vm_name();
        let session = universal_vm.get_ssh_session(ADMIN)?;
        let is_docker_running = universal_vm.block_on_bash_script_from_session(
            &session,
            &format!(
                "docker inspect -f '{{.State.Running}}' $(cat {})",
                UVM_CONTAINER_FILE
            ),
        )?;
        if &is_docker_running[..] == "true" {
            bail!("Docker is still running on {}", uvm_name)
        } else {
            Ok(())
        }
    };
    retry(env.logger(), timeout, SSH_SINGLE_COMMAND_BACKOFF, f)
        .map(|_| {
            info!(
                env.logger(),
                "Completed workload generation completed on {}!",
                universal_vm.vm_name()
            )
        })
        .unwrap_or_else(|_| {
            panic!(
                "Workload generation at {} timed out",
                universal_vm.vm_name()
            )
        })
}

fn fetch_docker_log(universal_vm: &DeployedUniversalVm) {
    let env = universal_vm.test_env();
    let f = || -> Result<(), anyhow::Error> {
        let log = env.logger();
        let uvm_name = universal_vm.vm_name();
        let target_path = env.base_path().join(format!("{}.log", &uvm_name));
        let r = {
            let session = universal_vm
                .block_on_ssh_session(ADMIN)
                .unwrap_or_else(|_| panic!("Failed to create session for {}", &uvm_name));

            // Save Docker logs
            universal_vm.block_on_bash_script_from_session(
                &session,
                &format!("docker logs $(cat {UVM_CONTAINER_FILE}) > {}", UVM_LOG_FILE),
            )?;

            // Log file is mapped from docker container to tmp directory.
            let (mut remote_file, _) = session.scp_recv(Path::new(UVM_LOG_FILE))?;

            let mut buf = String::new();
            remote_file.read_to_string(&mut buf)?;
            std::fs::write(target_path.clone(), buf)
        };
        r.map(|_| {
            info!(
                log,
                "Logs from {} written to {:?}",
                universal_vm.vm_name(),
                target_path
            )
        })
        .map_err(|e| e.into())
    };

    retry(
        env.logger(),
        SSH_SINGLE_COMMAND_TIMEOUT,
        SSH_SINGLE_COMMAND_BACKOFF,
        f,
    )
    .unwrap_or_else(|_| panic!("Failed to get logs for {}", universal_vm.vm_name()));
}
