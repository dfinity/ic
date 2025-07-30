use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{get_dependency_path, SshSession};
use ic_system_test_driver::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_system_test_driver::systest;
use slog::info;
use std::path::Path;

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

fn upgrade_vm_device_test(env: TestEnv) {
    let deployed_universal_vm = env
        .get_deployed_universal_vm(UNIVERSAL_VM_NAME)
        .expect("unable to get deployed VM.");
    deployed_universal_vm
        .block_on_bash_script(
            r#"
        set -euo pipefail
        docker load -i /config/ubuntu_test_runtime.tar

        cp /config/upgrade_device_mapper_test .
        cat <<EOF > /tmp/Dockerfile
            FROM ubuntu_test_runtime:image
            COPY --chmod=755 upgrade_device_mapper_test /upgrade_device_mapper_test
EOF

        docker build --tag final -f /tmp/Dockerfile .
        docker run --privileged -v /dev:/dev --rm final /usr/bin/bash -c "
            # The udev daemon is necessary so that the devices created in the test are properly
            # picked up. dmsetup must be available in the container image for this to work.
            /usr/lib/systemd/systemd-udevd --daemon
            RUST_BACKTRACE=1 /upgrade_device_mapper_test
        "
    "#,
        )
        .expect("Failed to run upgrade_vm_device_test");
}

fn guest_disk_test(env: TestEnv) {
    let deployed_universal_vm = env
        .get_deployed_universal_vm(UNIVERSAL_VM_NAME)
        .expect("unable to get deployed VM.");
    deployed_universal_vm
        .block_on_bash_script(
            r#"
        set -euo pipefail
        docker load -i /config/ubuntu_test_runtime.tar

        cp /config/guest_disk_test .
        cat <<EOF > /tmp/Dockerfile
            FROM ubuntu_test_runtime:image
            COPY --chmod=755 guest_disk_test /guest_disk_test
EOF

        docker build --tag final -f /tmp/Dockerfile .
        mkdir /tmp/out
        docker run --privileged -v /tmp/out:/tmp/out -v /dev:/dev --rm final /usr/bin/bash -c "
            RUST_BACKTRACE=1 /guest_disk_test
            ls
            cp *.profraw /tmp/out
        "
        echo DONE
    "#,
        )
        .expect("Failed to run guest_disk_test");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        // .add_test(systest!(upgrade_vm_device_test))
        .add_test(systest!(guest_disk_test))
        .execute_from_args()?;
    Ok(())
}
