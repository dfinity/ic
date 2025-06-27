/* tag::catalog[]

TODO:
Title:: NNS recovery engine

Goal::
The test ensures that a subnet can be recovered via recovery artifacts using the recovery image.

Runbook:: ...

Success:: ...

end::catalog[] */

use anyhow::{anyhow, Result};
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{secs, HasTopologySnapshot, IcNodeContainer, SshSession},
    },
    retry_with_msg, systest,
};
use slog::info;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Protobuf files are binary files, and since we deserialize them into UTF-8 strings,
/// we read their hex encoding and compare those.
fn hex_eq_utf8(actual: &str, expected: &str, error_message: &str) -> Result<()> {
    if actual == to_hex(expected.as_bytes()) {
        Ok(())
    } else {
        Err(anyhow!("{}. Expected: {}", error_message, expected))
    }
}

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

    let node = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .next()
        .unwrap();

    let ssh_session = node.block_on_ssh_session().unwrap();

    // We retry multiple times because the CUP being overwritten and this read
    // are racing against each other.
    retry_with_msg!("verify CUP", log.clone(), secs(30), secs(5), || {
        // Protobuf files are binary files, and since we deserialize them into UTF-8 strings,
        // we read their hex encoding and compare those.
        let cup_proto = execute_bash_command(
            &ssh_session,
            String::from(
                "od -An -tx1 -v /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb | tr -d ' \\n'",
            ),
        )
        .unwrap();

        hex_eq_utf8(
            &cup_proto,
            &expected_cup_proto,
            "Unexpected content in CUP file",
        )
    }).unwrap();

    retry_with_msg!(
        "verify local store 1",
        log.clone(),
        secs(30),
        secs(5),
        || {
            let local_store_1 = execute_bash_command(
            &ssh_session,
            String::from("od -An -tx1 -v  /var/lib/ic/data/ic_registry_local_store/0001020304/05/06/07.pb | tr -d ' \\n'"),
        )
        .expect("ic_registry_local_store has the wrong structure");

            hex_eq_utf8(
                &local_store_1,
                &expected_local_store_1,
                "Unexpected content in local store files",
            )
        }
    ).unwrap();

    retry_with_msg!(
        "verify local store 2",
        log.clone(),
        secs(30),
        secs(5),
        || {
            let local_store_2 = execute_bash_command(
            &ssh_session,
            String::from("od -An -tx1 -v  /var/lib/ic/data/ic_registry_local_store/08090a0b0c/0d/0e/0f.pb | tr -d ' \\n'"),
        )
        .expect("ic_registry_local_store has the wrong structure");

            hex_eq_utf8(
                &local_store_2,
                &expected_local_store_2,
                "Unexpected content in local store files",
            )
        }
    ).unwrap();
}

pub fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
