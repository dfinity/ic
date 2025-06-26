/* tag::catalog[]

Title:: NNS recovery engine

Goal::
The test ensures that a subnet can be recovered via recovery artifacts using the recovery image.

Runbook:: ...

Success:: ...

end::catalog[] */

use anyhow::Result;
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, SshSession},
    },
    systest,
};
use slog::info;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .use_recovery_image()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Running recovery engine test...");

    let expected_cup_proto = std::env::var("RECOVERY_CUP_CONTENT")
        .expect("RECOVERY_CUP_CONTENT environment variable not found");
    let expected_local_store_1 = std::env::var("RECOVERY_STORE_CONTENT1")
        .expect("RECOVERY_STORE_CONTENT1 environment variable not found");
    let expected_local_store_2 = std::env::var("RECOVERY_STORE_CONTENT2")
        .expect("RECOVERY_STORE_CONTENT2 environment variable not found");

    let node = env.get_first_healthy_node_snapshot();
    info!(log, "Node {} is available.", node.node_id);

    let ssh_session = node.block_on_ssh_session().unwrap();

    let cup_proto = execute_bash_command(
        &ssh_session,
        String::from("cat /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb"),
    )
    .unwrap();
    assert!(
        cup_proto == expected_cup_proto,
        "Unexpected content in cup.types.v1.CatchUpPackage.pb: {}",
        cup_proto
    );

    let local_store_1 = execute_bash_command(
        &ssh_session,
        String::from("cat ic_registry_local_store/0001020304/05/06/07.pb"),
    )
    .expect("ic_registry_local_store has the wrong structure");
    assert!(
        local_store_1 == expected_local_store_1,
        "Unexpected content in local store files: {}. Expected: {}",
        local_store_1,
        expected_local_store_1
    );

    let local_store_2 = execute_bash_command(
        &ssh_session,
        String::from("cat ic_registry_local_store/08090a0b0c/0d/0e/0f.pb"),
    )
    .expect("ic_registry_local_store has the wrong structure");
    assert!(
        local_store_2 == expected_local_store_2,
        "Unexpected content in local store files: {}. Expected: {}",
        local_store_2,
        expected_local_store_2
    );
}

pub fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
