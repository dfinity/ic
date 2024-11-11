/* tag::catalog[]
Title:: ic-crypto-csp umask test

Goal:: Ensure that the umask file permissions set for the `ic-crypto-csp` systemd service are
respected, such that new files created by the process have the expected permissions. In particular,
ensure that updated `sks_data.pb` secret key store files in the `/var/lib/ic/crypto/` directory
have read and write permissions for the `ic-csp-vault` (the owner), and no permissions for anyone
else (not the group, nor others), and has the `ic-csp-vault` owner and `ic-csp-vault` group.

Runbook::
. Set up a subnet with a single node
. Wait for the node to start up correctly and be healthy
. Retrieve the file metadata (permissions, timestamp, inode number) of the current secret key
  store file
. Wait for a DKG interval to pass, so that keys are updated
. Wait for an updated version of the secret key store to be written
. Verify that a new secret key store has been written by comparing the inode number and timestamp
  of the current secret key store against the metadata of the initial secret key store
. Verify that the permissions, owner, and group of the new secret key store file are correct

Success:: A new secret key store file has been written to disk, and it has the correct permissions,
owner, and group.

Coverage::
. The secret key store is updated when a DKG interval has passed
. The permissions, owner, and group, of new files are set correctly for the `ic-crypto-csp` process


end::catalog[] */

use anyhow::bail;
use ic_consensus_system_test_utils::node::await_node_certified_height;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SshSession,
    READY_WAIT_TIMEOUT, RETRY_BACKOFF,
};
use ic_types::Height;
use slog::{info, Logger};

const SHORT_DKG_INTERVAL: u64 = 3;

pub fn setup_with_single_node_and_short_dkg_interval(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(SHORT_DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

pub fn ic_crypto_csp_umask_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();

    let current_sks_metadata = retrieve_secret_key_store_metadata(&node, &logger);
    info!(logger, "current sks metadata: {:?}", current_sks_metadata);
    assert_is_correct(&current_sks_metadata);

    info!(logger, "waiting for a DKG interval to pass");
    await_node_certified_height(&node, Height::from(SHORT_DKG_INTERVAL), logger.clone());

    info!(logger, "waiting for the secret key store to be updated");
    let updated_sks_metadata =
        await_updated_secret_key_store_metadata(&node, &current_sks_metadata, env.logger());
    info!(logger, "updated sks metadata: {:?}", updated_sks_metadata);
    info!(logger, "checking metadata of new secret key store file");
    assert_is_correct(&updated_sks_metadata);
}

#[derive(Debug)]
struct SecretKeyStoreMetadata {
    permissions: u16,
    timestamp: u64,
    inode: u64,
    owner: String,
    group: String,
}

impl From<String> for SecretKeyStoreMetadata {
    fn from(value: String) -> Self {
        // Example output from "stat -c '%a %Y %i %U %G' /var/lib/ic/crypto/sks_data.pb".
        // Columns are:
        //  - file permissions in octal
        //  - timestamp in seconds since the UNIX epoch
        //  - inode number
        //  - owner
        //  - group
        // 600 1681978151 14 ic-csp-vault ic-csp-vault
        let mut field_iter = value.split_whitespace();
        let permissions = field_iter.next().expect("no permissions field");
        let timestamp = field_iter.next().expect("no timestamp field");
        let inode = field_iter.next().expect("no inode field");
        let owner = field_iter.next().expect("no owner field");
        let group = field_iter.next().expect("no group field");
        let no_more_fields = field_iter.next();
        assert!(
            no_more_fields.is_none(),
            "unexpected field: {:?}",
            no_more_fields
        );

        SecretKeyStoreMetadata {
            permissions: permissions.parse().expect("error parsing permissions"),
            timestamp: timestamp.parse().expect("error parsing timestamp"),
            inode: inode.parse().expect("error parsing inode number"),
            owner: String::from(owner),
            group: String::from(group),
        }
    }
}

impl SecretKeyStoreMetadata {
    fn has_been_updated(&self, previous: &SecretKeyStoreMetadata) -> bool {
        self.timestamp > previous.timestamp && self.inode != previous.inode
    }

    fn has_correct_permissions(&self) -> bool {
        // The secret key store shall have permissions '600'.
        // This corresponds to '-rw-------', i.e., read & write for the owner, but no permissions
        // for anyone else (not group, nor others).
        self.permissions == 600
    }

    fn has_group(&self, group: &str) -> bool {
        self.group == group
    }

    fn has_owner(&self, owner: &str) -> bool {
        self.owner == owner
    }
}

fn retrieve_secret_key_store_metadata(
    node: &IcNodeSnapshot,
    logger: &Logger,
) -> SecretKeyStoreMetadata {
    const STAT_CMD: &str = "sudo stat -c '%a %Y %i %U %G' /var/lib/ic/crypto/sks_data.pb";
    info!(
        logger,
        "retrieving secret key store metadata using command: {}", STAT_CMD
    );
    let stat_output = node
        .block_on_bash_script(STAT_CMD)
        .expect("unable to get secret key store metadata using SSH")
        .trim()
        .to_string();
    SecretKeyStoreMetadata::from(stat_output)
}

fn await_updated_secret_key_store_metadata(
    node: &IcNodeSnapshot,
    current_sks_metadata: &SecretKeyStoreMetadata,
    logger: Logger,
) -> SecretKeyStoreMetadata {
    ic_system_test_driver::retry_with_msg!(
        "check if secret key store metadata has been updated",
        logger.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            let sks_metadata = retrieve_secret_key_store_metadata(node, &logger);
            match sks_metadata.has_been_updated(current_sks_metadata) {
                true => Ok(sks_metadata),
                false => {
                    bail!("secret key store has not been updated yet")
                }
            }
        }
    )
    .expect("The secret key store was not updated in time")
}

fn assert_is_correct(sks_metadata: &SecretKeyStoreMetadata) {
    assert!(sks_metadata.has_correct_permissions());
    assert!(sks_metadata.has_owner("ic-csp-vault"));
    assert!(sks_metadata.has_group("ic-csp-vault"));
}
