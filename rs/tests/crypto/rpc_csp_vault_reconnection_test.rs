/* tag::catalog[]
Title:: RPC crypto CSP vault reconnection test

Goal:: Ensure that a crypto CSP vault client connected via RPC to the crypto CSP vault server
can automatically reconnect in case of an RPC connection problem and function as before once
the connection was re-established.

Runbook::
. Set up a subnet with a single node
. Ensure that usual crypto operations work: install a message canister and query it (a query response is always
  signed, so it uses the crypto CSP vault)
. Simulate an RPC connection problem by shutting down (SIGTERM) the crypto CSP vault server via SSH
. Ensure disconnection was noticed by CSP vault client (like the one managed by the replica process).
. (Reconnection should be handled transparently, the CSP vault server will be automatically restarted
  by systemd upon the next connection to the socket.)
. Ensure that crypto operations work as usual: try to query the message canister.
. Simulate a panic in the server by killing the server (SIGKILL).
. Ensure that crypto operations work as usual: try to query the message canister.

Success:: The shutdown of the crypto CSP vault server is handled transparently for the node
which function as usual and process query calls.

Coverage::
. RPC crypto CSP vault client can automatically reconnect
. RPC crypto CSP vault client works as usual after reconnection


end::catalog[] */

use anyhow::{Result, bail};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot, SshSession,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{MessageCanister, assert_create_agent, block_on};
use slog::{Logger, debug, info};
use std::time::Duration;

const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(rpc_csp_vault_reconnection_test))
        .with_overall_timeout(FIFTEEN_MINUTES)
        .with_timeout_per_test(FIFTEEN_MINUTES)
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

pub fn rpc_csp_vault_reconnection_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let crypto_csp_service = SystemdCli {
        service: "ic-crypto-csp.service".to_string(),
        logger: logger.clone(),
        node: &node,
    };
    let replica_service = SystemdCli {
        service: "ic-replica.service".to_string(),
        logger: logger.clone(),
        node: &node,
    };

    assert_eq!("active".to_string(), crypto_csp_service.state());

    let agent = block_on(assert_create_agent(node.get_public_url().as_str()));
    let message_canister = block_on(MessageCanister::new(&agent, node.effective_canister_id()));

    info!(logger, "Making sure replica processes queries");
    ensure_replica_is_not_stuck(&message_canister, &logger);
    info!(logger, "Making sure replica processes queries: success!");

    crypto_csp_service.stop();
    replica_service.wait_until_log_entry_contains("Detected disconnection from socket");

    info!(
        logger,
        "Making sure replica processes queries after stopping the vault with `systemd`"
    );
    ensure_replica_is_not_stuck(&message_canister, &logger);
    assert_eq!("active".to_string(), crypto_csp_service.state());
    info!(
        logger,
        "Making sure replica processes queries after stopping the vault with `systemd`: success!"
    );

    crypto_csp_service.kill();
    crypto_csp_service.wait_until_log_entry_contains(
        "ic-crypto-csp.service: Main process exited, code=killed, status=9/KILL",
    );

    info!(
        logger,
        "Making sure replica processes queries after killing the vault with `kill`"
    );
    ensure_replica_is_not_stuck(&message_canister, &logger);
    assert_eq!("active".to_string(), crypto_csp_service.state());
    info!(
        logger,
        "Making sure replica processes queries after killing the vault with `kill`: success!"
    );
}

struct SystemdCli<'a> {
    service: String,
    logger: Logger,
    node: &'a IcNodeSnapshot,
}

impl SystemdCli<'_> {
    fn state(&self) -> String {
        let cmd = format!(
            "systemctl show --property ActiveState --value {}",
            &self.service
        );
        self.log_ssh_command(&cmd);
        self.node
            .block_on_bash_script(&cmd)
            .expect("run command")
            .trim()
            .to_string()
    }

    fn kill(&self) {
        info!(self.logger, "Killing {}", self.service);
        let cmd = format!(
            "sudo kill -9 $(systemctl show --property MainPID --value {})",
            &self.service
        );
        self.log_ssh_command(&cmd);
        self.node.block_on_bash_script(&cmd).expect("run command");
    }

    fn stop(&self) {
        info!(self.logger, "Stopping {}", self.service);
        let cmd = format!("sudo systemctl stop {}", &self.service);
        self.log_ssh_command(&cmd);
        self.node.block_on_bash_script(&cmd).expect("run command");
    }

    fn wait_until_log_entry_contains(&self, msg: &str) {
        let ssh_session = self
            .node
            .block_on_ssh_session()
            .expect("establish SSH session");
        let cmd = format!("journalctl -u {} | grep --count '{}'", self.service, msg);
        self.log_ssh_command(&cmd);
        ic_system_test_driver::retry_with_msg!(
            "check if log entry contains expected message",
            self.logger.clone(),
            Duration::from_secs(20),
            Duration::from_secs(1),
            || {
                let occurrences = self
                    .node
                    .block_on_bash_script_from_session(&ssh_session, &cmd)
                    .expect("run command")
                    .trim()
                    .parse::<u32>()
                    .expect("valid integer");
                if occurrences > 0 {
                    Ok(())
                } else {
                    bail!(
                        "Waiting for {} to appear in logs of service {}",
                        msg,
                        self.service
                    )
                }
            }
        )
        .expect("message in service logs");
    }

    fn log_ssh_command(&self, cmd: &str) {
        debug!(self.logger, "Executing via SSH: '{}'", cmd);
    }
}

fn ensure_replica_is_not_stuck(message_canister: &MessageCanister, logger: &Logger) {
    debug!(
        logger,
        "Ensure replica can process query calls by reading message from message canister '{}'",
        message_canister.canister_id()
    );

    let _msg = block_on(async {
        tokio::time::timeout(Duration::from_secs(30), message_canister.read_msg()).await
    })
    .expect("failed to run read message future");
}
