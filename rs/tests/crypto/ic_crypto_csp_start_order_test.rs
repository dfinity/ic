/* tag::catalog[]
Title:: IC replica and crypto CSP service start ordering test

Goal:: Ensure that ic-replica.service is correctly configured to start after ic-crypto-csp.service.
Note that in systemd, the start order is implicitly the reverse of the stop order: if ic-replica.service has After=ic-crypto-csp.service,
then ic-crypto-csp.service will start before ic-replica.service, and ic-crypto-csp.service will stop after ic-replica.service.

Runbook::
. Set up a subnet with a single node
. Verify that ic-crypto-csp.service is listed in the After property of ic-replica.service using
  systemctl show ic-replica.service -p After

Success:: The start ordering configuration is correct, ensuring proper start ordering (and implicitly,
proper stop ordering as the reverse).

Coverage::
. systemctl show -p After shows ic-crypto-csp.service in the After property of ic-replica.service
. This ensures ic-crypto-csp.service starts before ic-replica.service
. This implicitly ensures ic-replica.service stops before ic-crypto-csp.service (reverse order)

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SshSession,
};
use ic_system_test_driver::systest;
use slog::{Logger, debug, info};
use std::time::Duration;

const TEN_MINUTES: Duration = Duration::from_secs(10 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(ic_crypto_csp_start_order_test))
        .with_overall_timeout(TEN_MINUTES)
        .with_timeout_per_test(TEN_MINUTES)
        .execute_from_args()?;
    Ok(())
}

pub fn setup_with_single_node(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

pub fn ic_crypto_csp_start_order_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();

    verify_crypto_vault_is_configured_to_start_after_ic_replica(&node, &logger);
}

fn verify_crypto_vault_is_configured_to_start_after_ic_replica(
    node: &IcNodeSnapshot,
    logger: &Logger,
) {
    let service = "ic-replica.service";
    let dependency = "ic-crypto-csp.service";

    info!(
        logger,
        "Verifying that {dependency} is listed in the After property of {service}"
    );

    let cmd = format!("systemctl show {service} -p After");
    debug!(logger, "Executing via SSH: '{cmd}'");

    let output = node
        .block_on_bash_script(&cmd)
        .expect("run systemctl show command");
    debug!(logger, "Output: '{output}'");

    // Parse the output which is in format: "After=service1.service service2.service ..."
    let after_value = match output.strip_prefix("After=") {
        Some(value) => value,
        None => panic!("Unexpected output format: {output}"),
    };

    let after_services: Vec<&str> = after_value.split_whitespace().collect();
    debug!(logger, "After services: {after_services:?}");

    if !after_services.contains(&dependency) {
        panic!(
            "{dependency} is not listed in the After property of {service}. After services found: {after_services:?}",
        );
    }

    info!(
        logger,
        "Successfully verified that {dependency} is listed in the After property of {service}"
    );
}
