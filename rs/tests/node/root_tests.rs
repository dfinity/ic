use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{SshSession, get_dependency_path};
use ic_system_test_driver::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_system_test_driver::systest;
use slog::info;

const UNIVERSAL_VM_NAME: &str = "root_tests";

fn setup(env: TestEnv) {
    let log = env.logger();

    info!(log, "Starting new universal VM");
    UniversalVm::new(UNIVERSAL_VM_NAME.into())
        .with_config_img(get_dependency_path(
            std::env::var("NODE_ROOT_TESTS_UVM_CONFIG_PATH")
                .expect("NODE_ROOT_TESTS_UVM_CONFIG_PATH not set"),
        ))
        .start(&env)
        .expect("failed to setup universal VM");
}

fn root_test(env: TestEnv, test: &str) {
    let deployed_universal_vm = env
        .get_deployed_universal_vm(UNIVERSAL_VM_NAME)
        .expect("unable to get deployed VM.");
    deployed_universal_vm
        .block_on_bash_script(&indoc::formatdoc!(
            r#"
                set -euo pipefail
                docker load -i /config/ubuntu_test_runtime.tar

                TMPDIR=$(mktemp -d)
                trap "rm -rf ${{TMPDIR}}" exit
                cd "${{TMPDIR}}"

                cp /config/{test} .
                cat <<EOF > Dockerfile
                    FROM ubuntu_test_runtime:image
                    COPY --chmod=755 {test} /{test}
                EOF

                docker build --tag final -f Dockerfile .
                docker run --privileged -v /dev:/dev --rm final /usr/bin/bash -c "
                    # The udev daemon is necessary so that the devices created in the test are properly
                    # picked up. dmsetup must be available in the container image for this to work.
                    /usr/lib/systemd/systemd-udevd --daemon
                    RUST_BACKTRACE=1 /{test}
                "
            "#
        ))
        .expect("Failed to run {test}");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(root_test; "upgrade_device_mapper_test"))
        .add_test(systest!(root_test; "guest_disk_test"))
        .add_test(systest!(root_test; "device_test"))
        .execute_from_args()?;
    Ok(())
}
