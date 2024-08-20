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

use anyhow::Result;

use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Node, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    retry_with_msg, systest,
};

use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;

use ic_base_types::PrincipalId;

use ic_registry_canister_api::{IPv4Config, UpdateNodeIPv4ConfigDirectlyPayload};
use registry_canister::mutations::node_management::do_remove_node_directly::RemoveNodeDirectlyPayload;

use slog::info;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::runtime::Runtime;

use anyhow::{anyhow, format_err, Error};

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

const CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const CONFIG_CHECK_SLEEP: Duration = Duration::from_secs(1);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn config(env: TestEnv) {
    let domain = "api-example.com".to_string();
    let ipv4_config = IPv4Config::try_new(
        "193.118.59.142".to_string(),
        "193.118.59.137".to_string(),
        29,
    )
    .unwrap();
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
            ipv4_config: Some(IPv4Config::try_new(
                "193.118.59.140".into(),
                "193.118.59.137".into(),
                29,
            ).unwrap()),
        };
        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        info!(log, "Check that the IPv4 address is in the node record in the registry ...");
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

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        info!(log, "Make sure we have no unassigned nodes anymore");
        let num_unassigned_nodes = topology.unassigned_nodes().count();
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

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        info!(log, "Assert there is 1 unassigned node again");
        assert_eq!(topology.unassigned_nodes().count(), 1);

        info!(log, "Checking unassigned node's IPv4 config and domain name after its registration");
        let unassigned_node: IcNodeSnapshot = topology.unassigned_nodes().next().unwrap();
        let ipv4_config = unassigned_node.get_ipv4_configuration().expect("Failed to get IPv4 configuration");
        assert_eq!(ipv4_config.ip_addr, "193.118.59.142");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["193.118.59.137"]);
        assert_eq!(ipv4_config.prefix_length, 29);
        assert_eq!(unassigned_node.get_domain(), Some("api-example.com".to_string()));

        info!(log, "SSH into both nodes and check that the IP address is configured on the interface ...");
        info!(log, "Check that the orchestrator applied the IPv4 config on both nodes ...");
        retry_with_msg!(
            "check that the orchestrator applied the IPv4 config on the unassigned node",
            log.clone(),
            CONFIG_CHECK_TIMEOUT,
            CONFIG_CHECK_SLEEP,
            || {
                wait_for_expected_node_ipv4_config(unassigned_node.clone(), Some(IPv4Config::try_new(
                    "193.118.59.142".into(),
                    "193.118.59.137".into(),
                    29,
                ).unwrap()))
            }
        ).expect("Failed to check the applied IPv4 configuration on the unassigned node");

        retry_with_msg!(
            "check that the orchestrator applied the IPv4 config on the app node",
            log.clone(),
            CONFIG_CHECK_TIMEOUT,
            CONFIG_CHECK_SLEEP,
            || {
                wait_for_expected_node_ipv4_config(app_node.clone(), Some(IPv4Config::try_new(
                    "193.118.59.140".into(),
                    "193.118.59.137".into(),
                    29).unwrap()
                ))
            }
        ).expect("Failed to check the applied IPv4 configuration on the app node");

        info!(log, "Modifying the IPv4 configuration on the unassigned node ...");
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: unassigned_node.node_id,
            ipv4_config: Some(IPv4Config::try_new(
                "196.156.107.201".into(),
                "196.156.107.193".into(),
                28,
            ).unwrap()),
        };

        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        info!(log, "Check that the IPv4 address has been updated in the node record in the registry ...");
        let unassigned_node: IcNodeSnapshot = topology.unassigned_nodes().next().unwrap();
        info!(log, "Check that the orchestrator applied the IPv4 config on both nodes ...");
        let ipv4_config = unassigned_node.get_ipv4_configuration().expect("Failed to update IPv4 configuration through a direct call to the registry");
        assert_eq!(ipv4_config.ip_addr, "196.156.107.201", "IPv4 address in the registry is incorrect");
        assert_eq!(ipv4_config.gateway_ip_addr, vec!["196.156.107.193"], "IPv4 gateways in the registry is incorrect");
        assert_eq!(ipv4_config.prefix_length, 28, "prefix length in the registry is incorrect");

        info!(log, "SSH into the node and check that the IP address is configured on the interface ...");
        retry_with_msg!(
            "SSH into the node and check that the IP address is configured on the interface",
            log.clone(),
            CONFIG_CHECK_TIMEOUT,
            CONFIG_CHECK_SLEEP,
            || {
                wait_for_expected_node_ipv4_config(unassigned_node.clone(), Some(IPv4Config::try_new(
                    "196.156.107.201".into(),
                    "196.156.107.193".into(),
                    28,
                ).unwrap()))
            }
        ).expect("Failed to check the applied IPv4 configuration on the unassigned node");

        info!(log, "Removing the IPv4 configuration on both nodes ...");
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: unassigned_node.node_id,
            ipv4_config: None,
        };

        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: app_node.node_id,
            ipv4_config: None,
        };

        let _out = agent_with_identity
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_ipv4_config_directly")
            .with_arg(Encode!(&payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not update the node's IPv4 config");

        info!(log, "Waiting for the registry to update from version {:?} ...", topology.get_registry_version());
        let topology = topology.block_for_newer_registry_version().await.unwrap();

        info!(log, "Check that the IPv4 address is removed in the registry ...");
        let unassigned_node: IcNodeSnapshot = topology.unassigned_nodes().next().unwrap();
        let ipv4_config = unassigned_node.get_ipv4_configuration();
        if let Some(tmp_config) = &ipv4_config {
            info!(log, "Existing config in the registry: {:?}", tmp_config);
        }
        assert!(ipv4_config.is_none(), "Failed to remove the IPv4 configuration of the unassigned node");

        let app_node = env.get_first_healthy_application_node_snapshot();
        let ipv4_config = app_node.get_ipv4_configuration();
        if let Some(tmp_config) = &ipv4_config {
            info!(log, "Existing config in the registry: {:?}", tmp_config);
        }
        assert!(ipv4_config.is_none(), "Failed to remove the IPv4 configuration of the node in the application subnet");

        info!(log, "SSH into both nodes and check that no IPv4 address is configured on the interface ...");
        retry_with_msg!(
            "SSH into the unassigned node and check that no IPv4 address is configured on the interface",
            log.clone(),
            CONFIG_CHECK_TIMEOUT,
            CONFIG_CHECK_SLEEP,
            || {
                wait_for_expected_node_ipv4_config(unassigned_node.clone(), None)
            }
        ).expect("Failed to check the applied IPv4 configuration on the unassigned node");
        retry_with_msg!(
            "SSH into the app node and check that no IPv4 address is configured on the interface",
            log.clone(),
            CONFIG_CHECK_TIMEOUT,
            CONFIG_CHECK_SLEEP,
            || {
                wait_for_expected_node_ipv4_config(app_node.clone(), None, )
            }
        ).expect("Failed to check the applied IPv4 configuration on the app node");
    });
}

// this helper obtains the IPv4 configuration of the specified node by
// SSHing into the node and checking the interface configuration.
// It keeps checking until the node's configuration matches the expected one
// or the timeout occurs.
fn wait_for_expected_node_ipv4_config(
    vm: IcNodeSnapshot,
    expected_ipv4_config: Option<IPv4Config>,
) -> Result<(), Error> {
    // first, get the current IPv4 config on the provided node
    // check if the interface has any IPv4 config
    let actual_interface_config =
        vm.block_on_bash_script(r#"ifconfig enp1s0 | awk '/inet / {print $2":"$4}'"#)?;
    let actual_interface_config = actual_interface_config.trim();

    let actual_ipv4_config = if actual_interface_config.is_empty() {
        None
    } else {
        // extract the IPv4 address
        let config_parts: Vec<&str> = actual_interface_config.split(':').collect();
        let actual_address = config_parts.first().map_or_else(
            || {
                Err(anyhow!(
                    "failed to extract the IPv4 address{:?}",
                    actual_interface_config
                ))
            },
            |&address| Ok(address.to_string()),
        )?;

        // get the prefix length by turning the subnet mask into its integer representation
        // and counting the number of 1s
        let subnet_mask_string = config_parts.get(1).ok_or_else(|| {
            anyhow!(
                "failed to extract the IPv4 address: {:?}",
                actual_interface_config
            )
        })?;
        let subnet_mask = Ipv4Addr::from_str(subnet_mask_string)
            .map_err(|_| anyhow!("invalid IPv4 subnet mask: '{:?}'", subnet_mask_string))?;
        let subnet_mask_u32 = u32::from(subnet_mask);
        let actual_prefix_length = subnet_mask_u32.count_ones();

        // get the default gateway
        let default_gateway =
            vm.block_on_bash_script(r#"ip route | awk '/default/ {print $3}'"#)?;
        let actual_gateway_address = default_gateway.trim().to_string();

        Some(IPv4Config::try_new(
            actual_address,
            actual_gateway_address,
            actual_prefix_length,
        )?)
    };

    // then, compare the expected and actual configuration
    if actual_ipv4_config == expected_ipv4_config {
        Ok(())
    } else {
        Err(format_err!(
            "the actual configuration did not match the expected one",
        ))
    }
}
