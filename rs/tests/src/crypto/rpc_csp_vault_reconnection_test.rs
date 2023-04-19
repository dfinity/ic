/* tag::catalog[]
Title:: RPC crypto CSP vault reconnection test

Goal:: Ensure that a crypto CSP vault client connected via RPC to the crypto CSP vault server
can automatically reconnect in case of an RPC connection problem and function as before once
the connection was re-established.

Runbook::
. Set up a subnet with a single node
. Ensure that usual crypto operations work: install a message canister and store message
  (uses update calls that need crypto to go through consensus)
. Simulates an RPC connection problem by shutting down the crypto CSP vault server via SSH
. TODO CRP-1822: update run book. Currently, client is dead at this point and restarting
                 server does not help. No update call can be processed.

Success:: The shutdown of the crypto CSP vault server is handled transparently for the node
which function as usual and process update calls.

Coverage::
. RPC crypto CSP vault client can automatically reconnect
. RPC crypto CSP vault client works as usual after reconnection


end::catalog[] */
use crate::driver::ic::InternetComputer;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot, SshSession,
};
use crate::orchestrator::utils::rw_message::{can_read_msg, cannot_store_msg, store_message};
use candid::Principal;
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info, Logger};

pub fn setup_with_single_node(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

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

    assert_eq!("active".to_string(), crypto_csp_service.state());
    let canister_id = create_message_canister_and_store_message(&node, &logger);

    crypto_csp_service.stop();
    ensure_replica_is_stuck(&node, canister_id, &logger);

    crypto_csp_service.start();
    assert_eq!("active".to_string(), crypto_csp_service.state());
    info!(logger, "TODO CRP-1822: CSP vault client should no longer be dead after server being restarted. Replace calling `cannot_store_msg` with `can_store_msg`");
    ensure_replica_is_stuck(&node, canister_id, &logger);
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
            .expect("could not run command")
            .trim()
            .to_string()
    }

    fn stop(&self) {
        info!(self.logger, "Stopping {}", self.service);
        let cmd = format!("sudo systemctl stop {}", &self.service);
        self.log_ssh_command(&cmd);
        self.node
            .block_on_bash_script(&cmd)
            .expect("could not run command");
    }

    fn start(&self) {
        info!(self.logger, "Starting {}", self.service);
        let cmd = format!("sudo systemctl start {}", &self.service);
        self.log_ssh_command(&cmd);
        self.node
            .block_on_bash_script(&cmd)
            .expect("could not run command");
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

fn ensure_replica_is_stuck(node: &IcNodeSnapshot, canister_id: Principal, logger: &Logger) {
    info!(logger, "Ensure update calls can no longer be processed");
    assert!(cannot_store_msg(
        logger.clone(),
        &node.get_public_url(),
        canister_id,
        "dead"
    ));
}
