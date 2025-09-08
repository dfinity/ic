use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{SshSession, get_dependency_path};
use ic_system_test_driver::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_system_test_driver::systest;
use slog::info;

const UNIVERSAL_VM_NAME: &str = "systest-runner";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/replicable_mock_test_uvm_config_image.zst",
        ))
        .start(&env)
        .expect("failed to setup universal VM");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let session = universal_vm
        .block_on_ssh_session()
        .expect("Failed to ssh into VM.");

    info!(
        logger,
        "Starting: docker run bazel/rs/tests:replicable_mock_test_image"
    );
    universal_vm
        .block_on_bash_script_from_session(
            &session,
            "docker run bazel/rs/tests:replicable_mock_test_image",
        )
        .unwrap();
    info!(
        logger,
        "Finished: docker run bazel/rs/tests:replicable_mock_test_image"
    );
}
