/* tag::catalog[]

Title:: Setting IPv4 Configuration and Domain Name of a Node

Goal:: Ensure that node correctly applies its IPv4 and domain name settings during registration

Runbook::
. IC setup:
  . Two single-node subnets (System and Application)
  . One unassigned node with preset ipv4 and domain name settings. These settings are not yet in the registry.
. Install NNS canisters (most importantly registry canister)
. Select a node from the Application subnet
. Verify that initial ipv4 and domain name settings for this node are empty
. Modify node's ipv4 settings via direct registry canister call (using the agent with node provider identity)
. Assert new ipv4 settings are in place in the registry
. Check node's ipv4 and domain name settings at the node registration level
  . Select unassigned node and remove it from the registry via direct canister call
  . Restart the services of this removed node and let it register itself
  . Assert this node appears as unassigned node in the registry again
  . Assert that node's ipv4 and domain name are set correctly

end::catalog[] */

use crate::driver::{
    ic::{InternetComputer, Ipv4Config, Node, Subnet},
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
    let domain = "api-example.com".to_string();
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
        .with_unassigned_node(
            Node::new()
                .with_ipv4_config(ipv4_config)
                .with_domain(domain),
        )
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
    let topology = env.topology_snapshot();
    let registry_version = topology.get_registry_version().get();
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    info!(log, "Creating an agent with node provider's identity");
    let mut agent_with_identity = nns_node.build_default_agent();
    let np_identity =
        Secp256k1Identity::from_private_key(SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap());
    agent_with_identity.set_identity(np_identity);
    info!(log, "Asserting there is exactly 1 unassigned node");
    assert_eq!(topology.unassigned_nodes().count(), 1);

    let rt = Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async {
        info!(log, "Checking initial IPv4 config and domain name are None for Application Node with id={}", app_node.node_id);
        let ipv4_config = app_node.get_ipv4_configuration();
        assert!(ipv4_config.is_none());
        let domain = app_node.get_domain();
        assert!(domain.is_none());
        info!(log, "Node's IPv4 config and domain name have correct initial settings");

        info!(log, "Configuring node's IPv4 address by directly updating the registry record");
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: app_node.node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into()],
            prefix_length: 29,
        };
        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");
        info!(log, "Waiting for the topology snapshot with the new registry version {} ...", registry_version + 1);
        let _topology = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(registry_version + 1))
            .await
            .unwrap();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let ipv4_config = app_node.get_ipv4_configuration().expect("Failed to get IPv4 configuration");
        assert_eq!(ipv4_config.ip_addr, "193.118.59.140");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["193.118.59.137"]);
        assert_eq!(ipv4_config.prefix_length, 29);
        info!(log, "IPv4 config of node with id={} has been updated successfully", app_node.node_id);
        info!(log, "Checking node's IPv4 and domain name settings at the node registration level");
        let unassigned_node = topology.unassigned_nodes().next().unwrap();
        info!(log, "Removing the unassigned node with id={} and letting it join again", unassigned_node.node_id);
        let payload = RemoveNodeDirectlyPayload {
            node_id: unassigned_node.node_id,
        };
        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "remove_node_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not remove the unassigned node");
        info!(log, "Make sure we have no unassigned nodes anymore");
        let num_unassigned_nodes = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(registry_version + 2))
            .await
            .unwrap()
            .unassigned_nodes()
            .count();
        assert_eq!(num_unassigned_nodes, 0);
        info!(log, "Waiting until the removed node registers itself again and updates the registry ...");
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
        info!(log, "Assert there is 1 unassigned node again");
        let topology = env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(registry_version + 3))
            .await
            .unwrap();
        assert_eq!(topology.unassigned_nodes().count(), 1);

        info!(log, "Checking unassigned node's IPv4 config and domain name after its registration");
        let unassigned_node: IcNodeSnapshot = topology.unassigned_nodes().next().unwrap();
        let ipv4_config = unassigned_node.get_ipv4_configuration().expect("Failed to get IPv4 configuration");
        assert_eq!(ipv4_config.ip_addr, "193.118.59.142");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["193.118.59.137"]);
        assert_eq!(ipv4_config.prefix_length, 29);
        assert_eq!(unassigned_node.get_domain(), Some("api-example.com".to_string()));
    });
}
