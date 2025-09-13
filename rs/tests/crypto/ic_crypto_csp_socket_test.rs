/* tag::catalog[]
Title:: ic-crypto-csp socket test

Goal:: Ensure that the Unix domain sockets for the crypto csp are created and have the correct
permissions. In particular, ensure that `socket` and `metrics` sockets in the
`/run/ic-node/crypto-csp/` directory have read and write permissions for the `ic-csp-vault` user
(the owner) and the `ic-csp-vault-socket` group, and no permissions for others, and has the
`ic-csp-vault` owner and `ic-csp-vault-socket` group (which contains the `ic-replica` user).

Runbook::
. Set up a subnet with a single node
. Wait for the node to start up correctly and be healthy
. Retrieve the file metadata (permissions, timestamp, inode number) of the sockets
. Verify that the permissions, owner, and group of the sockets are correct

Success:: Both sockets for the crypto csp exist, and that they have the correct permissions, owner,
and group.

Coverage::
. The sockets for the crypto csp are created
. The permissions, owner, and group, of the sockets are set correctly for the `ic-crypto-csp` process


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
use slog::{Logger, info};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(ic_crypto_csp_socket_test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup_with_single_node(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

const SOCKET_DIR: &str = "/run/ic-node/crypto-csp";
const SOCKET_NAMES: [&str; 2] = ["socket", "metrics"];

pub fn ic_crypto_csp_socket_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();

    for socket_name in &SOCKET_NAMES {
        let socket_metadata = SocketMetadata::retrieve(socket_name, SOCKET_DIR, &node, &logger);
        info!(
            logger,
            "{}/{} socket metadata: {:?}", SOCKET_DIR, socket_name, socket_metadata
        );

        // The socket shall have permissions '660'.
        // This corresponds to '-rw-rw----', i.e., read & write for the owner and the group, but
        // no permissions for others.
        assert!(socket_metadata.has_permissions(660));
        assert!(socket_metadata.has_owner("ic-csp-vault"));
        assert!(socket_metadata.has_group("ic-csp-vault-socket"));
        assert!(socket_metadata.has_type("socket"));
    }
}

#[derive(Debug)]
struct SocketMetadata {
    permissions: u16,
    owner: String,
    group: String,
    file_type: String,
}

impl From<String> for SocketMetadata {
    fn from(value: String) -> Self {
        // Example output from "stat -c '%a %U %G %F' /var/lib/ic/crypto/sks_data.pb".
        // Columns are:
        //  - file permissions in octal
        //  - owner
        //  - group
        //  - file type
        // 660 ic-csp-vault ic-csp-vault-socket socket
        let mut field_iter = value.split_whitespace();
        let permissions = field_iter.next().expect("no permissions field");
        let owner = field_iter.next().expect("no owner field");
        let group = field_iter.next().expect("no group field");
        let file_type = field_iter.next().expect("no file type field");
        let no_more_fields = field_iter.next();
        assert!(
            no_more_fields.is_none(),
            "unexpected field: {no_more_fields:?}"
        );

        SocketMetadata {
            permissions: permissions.parse().expect("error parsing permissions"),
            owner: String::from(owner),
            group: String::from(group),
            file_type: String::from(file_type),
        }
    }
}

impl SocketMetadata {
    fn retrieve(socket: &str, path: &str, node: &IcNodeSnapshot, logger: &Logger) -> Self {
        let stat_cmd = format!("sudo stat -c '%a %U %G %F' {path}/{socket}");
        info!(
            logger,
            "retrieving socket metadata using command: {}", stat_cmd
        );
        let stat_output = node
            .block_on_bash_script(stat_cmd.as_str())
            .expect("unable to get socket metadata using SSH")
            .trim()
            .to_string();
        SocketMetadata::from(stat_output)
    }

    fn has_permissions(&self, permissions: u16) -> bool {
        self.permissions == permissions
    }

    fn has_group(&self, group: &str) -> bool {
        self.group == group
    }

    fn has_owner(&self, owner: &str) -> bool {
        self.owner == owner
    }

    fn has_type(&self, file_type: &str) -> bool {
        self.file_type == file_type
    }
}
