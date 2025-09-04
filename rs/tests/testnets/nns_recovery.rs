// The `nested` testnet is meant to interactively test the HostOS. In particular to test NNS subnet recovery by interacting with the host grub menu during boot.
//
// The testnet will consist of a single system subnet with a single node running the NNS.
//
// Then NUM_HOST VMs are deployed and started booting SetupOS which will install HostOS to their virtual disks
// and eventually boot the GuestOS in a VM nested inside the host VM.
// These GuestOSes will then register with the NNS as unassigned nodes.
//
// The driver will print how to reboot the host-1 VM and how to get to its console such that you can interact with its grub:
//
// ```
// $ ict testnet create nns_recovery --lifetime-mins 10 --verbose -- --test_env=NUM_HOSTS=4
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
use std::time::Duration;

fn log_instructions(env: TestEnv) {
    nested::registration(env.clone());

    let logger = env.logger();

    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.infra_group_name;

    let topology = env.topology_snapshot();
    let num_hosts = topology.unassigned_nodes().count();

    info!(
        logger,
        "To reboot host VMs run any, or some of the following commands:"
    );
    for i in 1..=num_hosts {
        info!(
            logger,
            "curl -X PUT '{farm_url}group/{group_name}/vm/host-{i}/reboot'"
        );
    }
}

fn main() -> Result<()> {
    let num_hosts = std::env::var("NUM_HOSTS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    SystemTestGroup::new()
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_setup(move |env| nested::config(env, num_hosts, None))
        .add_test(systest!(log_instructions))
        .execute_from_args()?;
    Ok(())
}
