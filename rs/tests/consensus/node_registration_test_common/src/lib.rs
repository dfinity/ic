use canister_test::Canister;
use ic_base_types::PrincipalId;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_with_customizations_and_check_progress,
    ssh_access::execute_bash_command,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{ic::InternetComputer, test_env::TestEnv, test_env_api::*},
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    util::{block_on, runtime_from_url},
};
use ic_types::RegistryVersion;
use registry_canister::mutations::{
    do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
    node_management::do_remove_nodes::RemoveNodesPayload,
};
use slog::info;
use std::str::FromStr;

const TEST_PRINCIPAL: &str = "7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe";

pub fn setup(env: TestEnv) {
    let principal = PrincipalId::from_str(TEST_PRINCIPAL).unwrap();
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
}

enum TestConfig {
    NodeAllowance,
    MaxRewardableNodes,
}

impl TestConfig {
    fn is_max_rewardable_nodes(&self) -> bool {
        match self {
            TestConfig::NodeAllowance => false,
            TestConfig::MaxRewardableNodes => true,
        }
    }
}

pub fn test_with_node_allowance(env: TestEnv) {
    test(env, TestConfig::NodeAllowance)
}

pub fn test_with_max_rewardable_nodes(env: TestEnv) {
    test(env, TestConfig::MaxRewardableNodes)
}

fn test(env: TestEnv, config: TestConfig) {
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

    if config.is_max_rewardable_nodes() {
        info!(&logger, "Adding reward table and rewardable node");
        block_on(add_node_reward_table_and_rewardable_node(
            &governance_canister,
        ))
    }

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
        sudo cp /tmp/config.json.tmp /run/config/config.json
        sudo cp /tmp/node_operator_private_key.pem /var/lib/ic/data/node_operator_private_key.pem
        sudo chmod a+r /var/lib/ic/data/node_operator_private_key.pem
        sudo systemctl start ic-crypto-csp
        sudo systemctl start ic-replica
        "#
    .to_string();

    info!(logger, "Rotate keys on the unassigned node and restart it",);
    if let Err(e) = execute_bash_command(&s, script) {
        panic!("Script execution failed: {e:?}");
    }

    // Wait until the node registers itself and updates the registry, then check that we have
    // exactly 1 unassigned node.
    info!(&logger, "Make sure we have 1 unassigned node again");
    let num_unassigned_nodes = block_on(env.topology_snapshot().block_for_min_registry_version(
        RegistryVersion::from(if config.is_max_rewardable_nodes() {
            5
        } else {
            3
        }),
    ))
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(num_unassigned_nodes, 1);
}

/// Add a RewardTable which, if present, will force Registry Canister to look at `max_rewardable_nodes`,
/// and update the node operator config to include 1 max rewardable node.
async fn add_node_reward_table_and_rewardable_node(governance_canister: &Canister<'_>) {
    let proposal_id = submit_external_proposal_with_test_id(
        governance_canister,
        NnsFunction::UpdateNodeRewardsTable,
        UpdateNodeRewardsTableProposalPayload {
            // The rates themselves are not important, what is important
            // is that at least some NodeRewardTable exists
            new_entries: [(
                "CH".to_string(),
                NodeRewardRates {
                    rates: [(
                        "default".to_string(),
                        NodeRewardRate {
                            xdr_permyriad_per_node_per_month: 240,
                            reward_coefficient_percent: None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    )
    .await;
    vote_execute_proposal_assert_executed(governance_canister, proposal_id).await;

    let principal = PrincipalId::from_str(TEST_PRINCIPAL).unwrap();
    let proposal_id = submit_external_proposal_with_test_id(
        governance_canister,
        NnsFunction::UpdateNodeOperatorConfig,
        UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(principal),
            // Only one node is enough for this test, but the
            // real setup would include all of the nodes that
            // the node operator is linked to.
            max_rewardable_nodes: Some([("type3.1".to_string(), 1)].into_iter().collect()),
            ..Default::default()
        },
    )
    .await;
    vote_execute_proposal_assert_executed(governance_canister, proposal_id).await;
}
