use anyhow::Result;
use ic_base_types::PrincipalId;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_protobuf::registry::node_rewards::v2::UpdateNodeRewardsTableProposalPayload;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, ic::InternetComputer, test_env::TestEnv, test_env_api::*},
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    systest,
    util::{block_on, runtime_from_url},
};
use maplit::btreemap;
use registry_canister::mutations::do_update_node_operator_config::UpdateNodeOperatorConfigPayload;
use registry_canister::mutations::node_management::do_remove_nodes::RemoveNodesPayload;
use slog::info;
use std::str::FromStr;

fn setup(env: TestEnv) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_unassigned_nodes(1)
        .with_node_provider(principal)
        .with_node_operator(principal)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    env.topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());
}

fn test(env: TestEnv) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    info!(&logger, "Make sure we have 1 unassigned node");
    assert_eq!(topology.unassigned_nodes().count(), 1);

    let unassigned_node = topology.unassigned_nodes().next().unwrap();
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(&logger, "Remove the unassigned node from the registry");
    block_on(async {
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::RemoveNodes,
            RemoveNodesPayload {
                node_ids: vec![unassigned_node.node_id],
            },
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    });

    info!(&logger, "Make sure we have no unassigned nodes anymore");
    let num_unassigned_nodes = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(2)),
    )
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(num_unassigned_nodes, 0);

    // Add a RewardTable which, if present, will force Registry Canister to look at
    // `max_rewardable_nodes`
    block_on(async {
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::UpdateNodeRewardsTable,
            UpdateNodeRewardsTableProposalPayload {
                // The rates themselves are not important, what is important
                // is that at least some NodeRewardTable exists
                new_entries: btreemap! {
                    "CH".to_string() =>  NodeRewardRates {
                        rates: btreemap!{
                            "default".to_string() => NodeRewardRate {
                                xdr_permyriad_per_node_per_month: 240,
                                reward_coefficient_percent: None,
                            },
                            "small".to_string() => NodeRewardRate {
                                xdr_permyriad_per_node_per_month: 350,
                                reward_coefficient_percent: None,
                            },
                        }
                    }
                },
            },
        )
        .await;

        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    });

    // Update the node operator config to include 1 max rewardable node
    block_on(async {
        let proposal_id = submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::UpdateNodeOperatorConfig,
            UpdateNodeOperatorConfigPayload {
                node_operator_id: Some(principal),
                // Only one node is enough for this test, but the
                // real setup would include all of the nodes that
                // the node operator is linked to.
                max_rewardable_nodes: Some(btreemap! {
                    "type3.1".to_string() => 1,
                }),
                rewardable_nodes: btreemap! {
                    "type3.1".to_string() => 1,
                },
                ..Default::default()
            },
        )
        .await;

        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    });

    // Wait for registry to increase the version.
    block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(4)),
    )
    .unwrap();

    let s = unassigned_node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

    // Stop the replica on the unassigned node, delete crypto keys, deploy the test key PEM, restart everything.
    let script = r#"set -e
        sudo systemctl stop ic-crypto-csp
        sudo systemctl stop ic-replica
        sudo rm /var/lib/ic/crypto/public_keys.pb
        sudo rm /var/lib/ic/crypto/sks_data.pb
        cat <<EOT >/tmp/node_operator_private_key.pem
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJ61mhHntzgHe39PaCg7JY6QJcbe0g3dvS1UnEEbKVzdoAcGBSuBBAAK
oUQDQgAEKSfx/T3gDtkfdGl1fiONzUHs0N7/hcfQ8zwcqIzwuvHK3qqSJ3EhY5OB
WIgAGf+2BAs2ac0RonxQZdQTmZMvrw==
-----END EC PRIVATE KEY-----
EOT

        jq '.icos_settings.node_reward_type = "type3.1"' /run/config/config.json > /tmp/config.json.tmp
        # sudo cp /tmp/config.json.tmp /run/config/config.json

        sudo cp /tmp/node_operator_private_key.pem /var/lib/ic/data/node_operator_private_key.pem
        sudo chmod a+r /var/lib/ic/data/node_operator_private_key.pem
        sudo systemctl start ic-crypto-csp
        sudo systemctl start ic-replica
        "#
    .to_string();

    execute_bash_command(&s, script).unwrap();

    // Wait until the node registers itself and updates the registry, then check that we have
    // exactly 1 unassigned node.
    info!(&logger, "Make sure we have 1 unassigned node again");
    let num_unassigned_nodes = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(5)),
    )
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(num_unassigned_nodes, 1);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
