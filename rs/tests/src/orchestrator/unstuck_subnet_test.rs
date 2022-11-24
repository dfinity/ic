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

use super::utils::rw_message::install_nns_and_message_canisters;
use super::utils::ssh_access::execute_bash_command;
use super::utils::upgrade::{bless_public_replica_version, update_subnet_replica_version};
use crate::orchestrator::utils::rw_message::{
    can_read_msg_with_retries, cert_state_makes_no_progress_with_retries,
    store_message_with_retries,
};
use crate::orchestrator::utils::upgrade::UpdateImageType;
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

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;
const NUM_READ_RETRIES: usize = 10;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_message_canisters(env.topology_snapshot());
}

pub fn test(test_env: TestEnv) {
    let logger = test_env.logger();
    let mut all_nodes = test_env.topology_snapshot().root_subnet().nodes();

    let nns_node = all_nodes.next().unwrap();
    info!(logger, "node0: {:?}", nns_node.get_ip_addr());
    let nodes = all_nodes.collect::<Vec<IcNodeSnapshot>>();
    info!(logger, "node1: {:?}", nodes[0].get_ip_addr());
    info!(logger, "node2: {:?}", nodes[1].get_ip_addr());
    info!(logger, "node3: {:?}", nodes[2].get_ip_addr());

    let target_version =
        get_assigned_replica_version(&nns_node).expect("Failed to get assigned replica version");
    info!(logger, "Target version: {}", target_version);

    block_on(bless_public_replica_version(
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

    let sess = nns_node
        .block_on_ssh_session(ADMIN)
        .expect("Failed to establish SSH session");

    info!(logger, "Wait for 'hash mismatch' in the replica's log.");
    retry(test_env.logger(), secs(600), secs(20), || {
        if have_sha_errors(&sess) {
            Ok(())
        } else {
            bail!("Waiting for hash mismatch!")
        }
    })
    .expect("No hash missmatch in the logs");

    info!(logger, "Check that system does not make progress");
    cert_state_makes_no_progress_with_retries(
        &nns_node.get_public_url(),
        nns_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    info!(logger, "Stopping orchestrator...");
    for n in &nodes {
        let s = n
            .block_on_ssh_session(ADMIN)
            .expect("Failed to establish SSH session");
        execute_bash_command(&s, "sudo systemctl stop ic-replica".to_string()).unwrap();
    }

    info!(logger, "Download and save the proper image file...");
    let command = format!(
        r#"set -e
        sudo chmod 777 /var/lib/ic/data/images
        cd /var/lib/ic/data/images/
        sudo mv image.bin old-image.bin
        sudo curl http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/update-img-test.tar.zst -o image.bin --retry 10 --retry-connrefused --retry-delay 10 --retry-max-time 500
        sudo chmod --reference=old-image.bin image.bin
        sudo chown --reference=old-image.bin image.bin
        sudo rm old-image.bin
        "#,
        target_version,
    );
    for n in &nodes {
        let s = n
            .block_on_ssh_session(ADMIN)
            .expect("Failed to establish SSH session");
        if let Err(err) = execute_bash_command(&s, command.clone()) {
            panic!("{}", err)
        }
    }

    info!(logger, "Starting orchestrator...");
    for n in &nodes {
        let s = n
            .block_on_ssh_session(ADMIN)
            .expect("Failed to establish SSH session");
        execute_bash_command(&s, "sudo systemctl start ic-replica".to_string()).unwrap();
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
    let can_id = store_message_with_retries(
        &nodes[0].get_public_url(),
        nodes[0].effective_canister_id(),
        msg,
        &logger,
    );
    info!(logger, "Read it on all other nodes");
    for n in &nodes {
        assert!(
            can_read_msg_with_retries(&logger, &n.get_public_url(), can_id, msg, NUM_READ_RETRIES),
            "Failed to read message on {}",
            n.get_ip_addr()
        );
    }
    info!(logger, "Could store and read message!");
}

fn have_sha_errors(sess: &Session) -> bool {
    let cmd = "journalctl | grep -c 'FileHashMismatchError'".to_string();
    execute_bash_command(sess, cmd).map_or(false, |res| res.trim().parse::<i32>().unwrap() > 0)
}
