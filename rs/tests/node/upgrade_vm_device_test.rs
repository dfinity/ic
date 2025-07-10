use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{HasTestEnv, SshSession};
use ic_system_test_driver::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_system_test_driver::systest;
use slog::info;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

const UNIVERSAL_VM_NAME: &str = "upgrade_vm_device_test";
fn setup(env: TestEnv) {
    let log = env.logger();

    info!(log, "Starting new universal VM");
    UniversalVm::new(UNIVERSAL_VM_NAME.into())
        .start(&env)
        .expect("failed to setup universal VM");
}

fn upgrade_vm_device_test(env: TestEnv) {
    let deployed_universal_vm = env
        .get_deployed_universal_vm(UNIVERSAL_VM_NAME)
        .expect("unable to get deployed VM.");

    let ssh = deployed_universal_vm
        .block_on_ssh_session()
        .expect("unable to get ssh session.");
    let test_path = PathBuf::from(std::env::var("TEST_PATH").expect("TEST_PATH not set"));

    std::io::copy(
        &mut BufReader::new(File::open(&test_path).expect("Could not open test impl")),
        &mut ssh
            .scp_send(
                Path::new("/tmp/upgrade_vm_device_test"),
                0o755,
                test_path
                    .metadata()
                    .expect("Could not query metadata")
                    .len(),
                None,
            )
            .expect("Unable to open SCP channel"),
    )
    .expect("Could not copy test to VM");

    deployed_universal_vm
        .block_on_bash_script_from_session(
            &ssh,
            "
         set -euo pipefail
        echo listing
         ls /lib64/
         echo end
         sudo \"/tmp/upgrade_vm_device_test\"
        ",
        )
        .expect("Failed to run upgrade_vm_device_test script");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(upgrade_vm_device_test))
        .execute_from_args()?;
    Ok(())
}
