#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::farm::HostFeature;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::driver::test_env_api::{HasDependencies, HasGroupSetup, SshSession, ADMIN};
use ic_tests::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_tests::systest;
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
    env.ensure_group_setup_created();
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(
            env.get_dependency_path("rs/tests/replicable_mock_test_uvm_config_image.zst"),
        )
        .disable_ipv4()
        .with_required_host_features(vec![HostFeature::Host(
            "fr1-dll07.fr1.dfinity.network".to_string(),
        )])
        .start(&env)
        .expect("failed to setup universal VM");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let session = universal_vm.block_on_ssh_session(ADMIN).unwrap();

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
