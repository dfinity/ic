/* tag::catalog[]

Goal:: Ensure that an upgrade with a wrong hash can be fixed by downloading the correct update file

Runbook::
. Setup an IC with 4-node NNS.
. Initiate upgrade on the replicas with a wrong hash.
. Prove subnet is stuck - "wrong SHA" log message and inability to create a canister.
. On 3/4 of nodes download the proper image via done providers admin SSH access.
. Restart the orchestrator on those nodes.

Success:: The subnet is unstuck as we can write a message to it.

end::catalog[] */

use super::utils::upgrade::{bless_replica_version, update_subnet_replica_version};
use crate::orchestrator::node_reassignment_test::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::{can_install_canister, UpdateImageType};
use crate::util::block_on;
use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    orchestrator::utils::upgrade::get_assigned_replica_version,
};
use anyhow::bail;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use ssh2::Session;
use std::convert::TryFrom;
use std::io::{Read, Write};

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test")
}

pub fn test(test_env: TestEnv) {
    let logger = test_env.logger();
    let mut all_nodes = test_env.topology_snapshot().root_subnet().nodes();

    let nns_node = all_nodes.next().unwrap();
    nns_node.await_status_is_healthy().unwrap();
    info!(logger, "node0: {:?}", nns_node.get_ip_addr());
    let nodes = all_nodes.collect::<Vec<IcNodeSnapshot>>();
    for n in &nodes {
        n.await_status_is_healthy().unwrap();
    }
    info!(logger, "node1: {:?}", nodes[0].get_ip_addr());
    info!(logger, "node2: {:?}", nodes[1].get_ip_addr());
    info!(logger, "node3: {:?}", nodes[2].get_ip_addr());

    info!(logger, "Installing NNS canisters...");
    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(logger, "NNS canisters are installed.");

    let target_version = get_assigned_replica_version(&nns_node).unwrap();
    info!(logger, "Target version: {}", target_version);

    block_on(bless_replica_version(
        &nns_node,
        &target_version,
        UpdateImageType::ImageTest,
        UpdateImageType::Image,
        &logger,
    ));

    let subnet_id = test_env.topology_snapshot().root_subnet_id();
    block_on(update_subnet_replica_version(
        &nns_node,
        &ReplicaVersion::try_from(format!("{}-test", target_version))
            .expect("Wrong format of the version"),
        subnet_id,
    ));
    info!(logger, "Upgrade started");

    let sess = nns_node.get_ssh_session(ADMIN).unwrap();

    info!(logger, "Wait for 'hash mismatch' in the replica's log.");
    retry(test_env.logger(), secs(600), secs(20), || {
        if have_sha_errors(&sess) {
            Ok(())
        } else {
            bail!("Waiting for hash mismatch!")
        }
    })
    .expect("No hash missmatch in the logs");

    info!(logger, "Check that creation of canisters is impossible...");
    retry(test_env.logger(), secs(60), secs(5), || {
        if can_install_canister(&nns_node.get_public_url()) {
            bail!("Waiting for a failure creating a canister!")
        } else {
            Ok(())
        }
    })
    .expect("Error: a canister can still be created");

    info!(logger, "Stopping orchestrator...");
    for n in &nodes {
        let s = n.get_ssh_session(ADMIN).unwrap();
        execute_bash_command(&s, "sudo systemctl stop ic-replica".to_string());
    }

    info!(logger, "Download and save the proper image file...");
    let command = format!(
        r#"sudo chmod 777 /var/lib/ic/data/images
        cd /var/lib/ic/data/images/
        sudo mv guest-os.tar.gz old-guest-os.tar.gz
        sudo curl https://download.dfinity.systems/ic/{}/guest-os/update-img/update-img-test.tar.gz -o guest-os.tar.gz
        sudo chmod --reference=old-guest-os.tar.gz guest-os.tar.gz
        sudo chown --reference=old-guest-os.tar.gz guest-os.tar.gz
        sudo rm old-guest-os.tar.gz
        "#,
        target_version,
    );
    for n in &nodes {
        let s = n.get_ssh_session(ADMIN).unwrap();
        execute_bash_command(&s, command.clone());
    }

    info!(logger, "Starting orchestrator...");
    for n in &nodes {
        let s = n.get_ssh_session(ADMIN).unwrap();
        execute_bash_command(&s, "sudo systemctl start ic-replica".to_string());
    }

    info!(logger, "Waiting for update to finish on all 3 nodes...");
    let updated_version = format!("{}-test", target_version);
    for n in &nodes {
        retry(
            test_env.logger(),
            secs(1800),
            secs(60),
            || match get_assigned_replica_version(n) {
                Ok(current_version) => {
                    info!(
                        logger,
                        "Versions: cur: {} upd: {}", current_version, updated_version
                    );
                    if current_version == updated_version {
                        Ok(())
                    } else {
                        bail!("Expect new version...");
                    }
                }
                Err(err) => bail!("Can't read version: {}", err),
            },
        )
        .expect("Node hasn't upgraded");
    }

    info!(logger, "Write a message to a canister");
    let msg = "Hello world!";
    let can_id = block_on(store_message(&nodes[0].get_public_url(), msg));
    // read it on all other nodes
    for n in &nodes {
        assert!(block_on(can_read_msg(
            &logger,
            &n.get_public_url(),
            can_id,
            msg
        )));
    }
    info!(logger, "Could store and read message!");
}

fn have_sha_errors(sess: &Session) -> bool {
    let search_str = "FileHashMismatchError";
    let check_log_script = format!("journalctl | grep \"{}\"", search_str);
    execute_bash_command(sess, check_log_script).lines().count() != 0
}

fn execute_bash_command(sess: &Session, command: String) -> String {
    let mut channel = sess.channel_session().unwrap();
    channel.exec("bash").unwrap();
    channel.write_all(command.as_bytes()).unwrap();
    channel.flush().unwrap();
    channel.send_eof().unwrap();
    let mut out = String::new();
    channel.read_to_string(&mut out).unwrap();
    out
}
