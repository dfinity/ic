use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, ic::InternetComputer, test_env::TestEnv, test_env_api::*},
    systest,
};

use anyhow::Result;
use slog::info;

use std::time::Instant;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let node = topology.root_subnet().nodes().next().unwrap();

    let s = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

    // Add a ton of state files to the node
    let script = r#"set -e
        cat >/tmp/script.sh << EOT
#!/bin/bash
mkdir -p /var/lib/ic/data/ic_state/garbage/
cd /var/lib/ic/data/ic_state/garbage/
for i in {1..1000}; do
    mkdir -p \$i
    pushd \$i
    for j in {1..1000}; do
        echo "data" > \$j
    done
    popd
done
EOT
        sudo chmod +x /tmp/script.sh
        sudo su -c '/tmp/script.sh'
        "#
    .to_string();

    info!(logger, "Adding state files to node",);
    if let Err(e) = execute_bash_command(&s, script) {
        panic!("Script execution failed: {e:?}");
    }

    // Reboot once to get things fully initialized
    node.vm().reboot();
    node.await_status_is_unavailable().unwrap();
    node.await_status_is_healthy().unwrap();

    // Reboot again to measure timing
    let reboot_start = Instant::now();

    node.vm().reboot();
    node.await_status_is_unavailable().unwrap();
    node.await_status_is_healthy().unwrap();

    let reboot_time = reboot_start.elapsed();

    info!(logger, "Reboot took: {}s", reboot_time.as_secs());
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
