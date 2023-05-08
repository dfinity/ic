use std::time::Duration;

/* tag::catalog[]
Title:: RPC crypto CSP vault reconnection test

Goal:: Ensure that a crypto CSP vault client connected via RPC to the crypto CSP vault server
can automatically reconnect in case of an RPC connection problem and function as before once
the connection was re-established.

Runbook::
. Set up a subnet with a single node
. Ensure that usual crypto operations work: install a message canister and store message
  (uses update calls that need crypto to go through consensus)
. Simulate an RPC connection problem by shutting down (SIGTERM) the crypto CSP vault server via SSH
. Ensure disconnection was noticed by CSP vault client (like the one managed by the replica process).
. (Reconnection should be handled transparently, the CSP vault server will be automatically restarted
  by systemd upon the next connection to the socket.)
. Ensure that crypto operations work as usual: try to store a message in the message canister (uses an update call).
. Simulate a panic in the server by killing the server (SIGKILL).
. Ensure that crypto operations work as usual: try to store a message in the message canister (uses an update call).

Success:: The shutdown of the crypto CSP vault server is handled transparently for the node
which function as usual and process update calls.

Coverage::
. RPC crypto CSP vault client can automatically reconnect
. RPC crypto CSP vault client works as usual after reconnection


end::catalog[] */
use crate::driver::ic::InternetComputer;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    retry, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot, SshSession,
};
use crate::orchestrator::utils::rw_message::{can_read_msg, can_store_msg, store_message};
use anyhow::bail;
use candid::Principal;
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info, Logger};

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
    let canister_id = create_message_canister_and_store_message(&node, &logger);

    crypto_csp_service.stop();
    replica_service.wait_until_log_entry_contains("Detected disconnection from socket");

    ensure_replica_is_not_stuck(&node, canister_id, &logger);
    assert_eq!("active".to_string(), crypto_csp_service.state());

    crypto_csp_service.kill();
    crypto_csp_service.wait_until_log_entry_contains(
        "ic-crypto-csp.service: Main process exited, code=killed, status=9/KILL",
    );

    ensure_replica_is_not_stuck(&node, canister_id, &logger);
    assert_eq!("active".to_string(), crypto_csp_service.state());
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
        retry(
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
            },
        )
        .expect("message in service logs");
    }

    fn log_ssh_command(&self, cmd: &str) {
        debug!(self.logger, "Executing via SSH: '{}'", cmd);
    }
}

fn create_message_canister_and_store_message(node: &IcNodeSnapshot, logger: &Logger) -> Principal {
    const MSG: &str = "RPC CSP vault reconnection";
    let canister_id = store_message(&node.get_public_url(), node.effective_canister_id(), MSG);
    info!(logger, "Stored message to canister ID {}", canister_id);
    assert!(can_read_msg(
        logger,
        &node.get_public_url(),
        canister_id,
        MSG
    ));
    canister_id
}

fn ensure_replica_is_not_stuck(node: &IcNodeSnapshot, canister_id: Principal, logger: &Logger) {
    info!(logger, "Ensure update calls can be processed");
    assert!(can_store_msg(
        logger,
        &node.get_public_url(),
        canister_id,
        "alive"
    ));
}
