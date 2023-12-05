/* tag::catalog[]

Title:: Node IPv4 Configuration

Goal:: Ensure that the node correctly applies its IPv4 configuration

Description::

Runbook::
. Step 1
. Step 2
.

Success::
. Backup tool is able to restore the state from pulled artifacts, including those after the upgrade. The state is also archived.

end::catalog[] */

use crate::driver::{
    ic::{InternetComputer, Ipv4Config, Subnet},
    test_env::TestEnv,
    test_env_api::*,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;

use ic_base_types::PrincipalId;

use registry_canister::mutations::node_management::{
    do_remove_node_directly::RemoveNodeDirectlyPayload,
    do_update_node_ipv4_config_directly::UpdateNodeIPv4ConfigDirectlyPayload,
};

use slog::info;
use std::net::Ipv4Addr;
use tokio::runtime::Runtime;

use candid::Encode;

use ic_agent::identity::Secp256k1Identity;
use k256::elliptic_curve::SecretKey;
use std::str::FromStr;

const TEST_PRINCIPAL: &str = "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";
const TEST_PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIBzyyJ32Kdjixx+ZJvNeUWsqAzSQZfLsOyXKgxc7aH9oAcGBSuBBAAK
oUQDQgAECWc6ZRn9bBP96RM1G6h8ZAtbryO65dKg6cw0Oij2XbnAlb6zSPhU+4hh
gc2Q0JiGrqKks1AVi+8wzmZ+2PQXXA==
-----END EC PRIVATE KEY-----";

pub fn config(env: TestEnv) {
    let ipv4_config = Ipv4Config {
        ip_addr: Ipv4Addr::new(193, 118, 59, 142),
        gateway_ip_addr: Ipv4Addr::new(193, 118, 59, 137),
        prefix_length: 29,
    };

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .with_node_provider(PrincipalId::from_str(TEST_PRINCIPAL).unwrap())
        .with_node_operator(PrincipalId::from_str(TEST_PRINCIPAL).unwrap())
        .with_ipv4_enabled_unassigned_node(ipv4_config)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();

    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("could not install NNS canisters");
}

pub fn test(env: TestEnv) {
    let log = env.logger();

    info!(log, "Start of the test");

    info!(log, "creating agent");
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let mut agent = nns_node.build_default_agent();

    info!(log, "set the node provider identity");
    let np_identity =
        Secp256k1Identity::from_private_key(SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap());
    agent.set_identity(np_identity);

    let rt = Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async {
        // configure the node's IPv4 address by directly calling the registry with the node provider's identity
        let app_node = env.get_first_healthy_application_node_snapshot();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: app_node.node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into()],
            prefix_length: 29,
        };

        let _out = agent
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");
        // let data: Result<(), String> = Decode!(&out, Result<(), String>).unwrap();

        let topology = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(2))
            .await
            .unwrap();

        let app_node = env.get_first_healthy_application_node_snapshot();
        let ipv4_config = app_node.get_ipv4_configuration().expect("Failed to apply IPv4 configuration through a direct call to the registry");
        assert_eq!(ipv4_config.ip_addr, "193.118.59.140");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["193.118.59.137"]);
        assert_eq!(ipv4_config.prefix_length, 29);

        // configure the node's IPv4 address at node registration
        // to this end, we first need to remove the unassigned node and let it join again
        info!(log, "Make sure we have 1 unassigned node");
        assert_eq!(topology.unassigned_nodes().count(), 1);

        let unassigned_node = topology.unassigned_nodes().next().unwrap();
        info!(log, "Old Node ID: {:?}", unassigned_node.node_id);
        let payload = RemoveNodeDirectlyPayload {
            node_id: unassigned_node.node_id,
        };
        let _out = agent
            .update(&REGISTRY_CANISTER_ID.into(), "remove_node_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not remove the unassigned node");

        info!(log, "Make sure we have no unassigned nodes anymore");
        let num_unassigned_nodes = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(3))
            .await
            .unwrap()
            .unassigned_nodes()
            .count();
        assert_eq!(num_unassigned_nodes, 0);

        if let Err(e) = unassigned_node.block_on_bash_script(&indoc::formatdoc! {r#"set -e
            sudo systemctl stop ic-crypto-csp
            sudo systemctl stop ic-replica
            sudo rm /var/lib/ic/crypto/public_keys.pb
            sudo rm /var/lib/ic/crypto/sks_data.pb
            cat <<EOT >/tmp/node_operator_private_key.pem
{TEST_PRIVATE_KEY}
EOT
            sudo cp /tmp/node_operator_private_key.pem /var/lib/ic/data/node_operator_private_key.pem
            sudo chmod a+r /var/lib/ic/data/node_operator_private_key.pem
            sudo systemctl start ic-crypto-csp
            sudo systemctl start ic-replica
            "#}) {
            panic!("Script execution failed: {:?}", e);
        }

        // Wait until the node registers itself and updates the registry, then check that we have
        // exactly 1 unassigned node.
        info!(log, "Make sure we have 1 unassigned node again");
        let topology = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(4))
            .await
            .unwrap();
        assert_eq!(topology.unassigned_nodes().count(), 1);

        let unassigned_node: IcNodeSnapshot = topology.unassigned_nodes().next().unwrap();
        let ipv4_config = unassigned_node.get_ipv4_configuration().expect("Failed to apply IPv4 configuration at node registration");
        assert_eq!(ipv4_config.ip_addr, "193.118.59.142");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["193.118.59.137"]);
        assert_eq!(ipv4_config.prefix_length, 29);
    });

    info!(log, "End of the test");
}
