// The `nested` testnet is meant to interactively test the HostOS. In particular to test NNS subnet recovery by interacting with the host grub menu during boot.
//
// The driver will print how to reboot the host-1 VM and how to get to its console such that you can interact with its grub:
//
// ```
// $ ict testnet create nested --lifetime-mins 10 --verbose
// ...
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:16:0] To reboot the host VM run the following command:
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:17:0] curl -X PUT 'https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/reboot'
// ...
//     {
//       "url": "https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/console/",
//       "vm_name": "host-1"
//     }
// ```

use anyhow::Result;
use ic_system_test_driver::driver::test_env::{TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::test_setup::GroupSetup;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use slog::info;

fn log_instructions(env: TestEnv) {
    let logger = env.logger();

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;
    let host_vm_name = nested::HOST_VM_NAME;

    info!(logger, "To reboot the host VM run the following command:");
    info!(
        logger,
        "curl -X PUT '{farm_url}group/{group_name}/vm/{host_vm_name}/reboot'"
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| nested::config(env, 1, None))
        .add_test(systest!(nested::registration))
        .add_test(systest!(log_instructions))
        .execute_from_args()?;
    Ok(())
}
