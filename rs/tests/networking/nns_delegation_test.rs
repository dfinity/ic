use std::time::SystemTime;

use anyhow::Result;
use ic_agent::Agent;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress,
    upgrade::{
        assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
    },
};
use ic_crypto_tree_hash::{lookup_path, LabeledTree};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_guestos_img_version, get_guestos_update_img_sha256, get_guestos_update_img_url,
            get_guestos_update_img_version, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            IcNodeSnapshot, SubnetSnapshot,
        },
    },
    systest,
    util::{block_on, get_nns_node},
};
use ic_types::{messages::Certificate, Height, PrincipalId};
use slog::info;

/// How long to wait between subsequent nns delegation fetch requests.
const RETRY_DELAY: tokio::time::Duration = tokio::time::Duration::from_secs(60);

const DKG_LENGTH: Height = Height::new(9);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System).with_dkg_interval_length(DKG_LENGTH),
        )
        .add_subnet(
            Subnet::fast_single_node(SubnetType::Application).with_dkg_interval_length(DKG_LENGTH),
        )
        .setup_and_start(&env)
        .expect("Should be able to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    // Upgrade the application subnet to test protocol compatibility between subnets running
    // replica different versions.
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    upgrade_subnet_if_necessary(&env, &subnet, &node);
}

fn nns_delegation_on_nns_test(env: TestEnv) {
    block_on(nns_delegation_test(env, SubnetType::System))
}

fn nns_delegation_on_app_subnet_test(env: TestEnv) {
    block_on(nns_delegation_test(env, SubnetType::Application))
}

async fn nns_delegation_test(env: TestEnv, subnet_type: SubnetType) {
    let (_subnet, node) = get_subnet_and_node(&env, subnet_type);

    let agent = node.build_default_agent_async().await;
    info!(env.logger(), "Fetching an initial NNS delegation");
    let maybe_initial_delegation_timestamp =
        get_nns_delegation_timestamp(&agent, node.effective_canister_id()).await;

    if subnet_type == SubnetType::System {
        assert!(
            maybe_initial_delegation_timestamp.is_none(),
            "There shouldn't be delegation on the NNS subnet"
        );

        // We can return, there is nothing more to be checked.
        return;
    }

    let initial_delegation_timestamp = maybe_initial_delegation_timestamp
        .expect("Non-NNS subnet should return an NNS delegation with the response");
    let initial_delegation_time = SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_nanos(
            initial_delegation_timestamp,
        ))
        .unwrap();

    info!(
        env.logger(),
        "Waiting for a new NNS delegation. Note: it could take up to 10 minutes."
    );
    loop {
        let new_delegation_timestamp =
            get_nns_delegation_timestamp(&agent, node.effective_canister_id())
                .await
                .expect("Non-NNS subnet should return an NNS delegation with the response");
        assert!(
            new_delegation_timestamp >= initial_delegation_timestamp,
            "Timestamps should be (not necessarily strictly) increasing. \
            New delegation timestamp: {}, \
            initial delegation timestamp: {}",
            new_delegation_timestamp,
            initial_delegation_timestamp,
        );

        if new_delegation_timestamp == initial_delegation_timestamp {
            info!(
                env.logger(),
                "The subnet is still using the old nns delegation, which is roughly {}s old. \
                Retrying in {} seconds.",
                SystemTime::now()
                    .duration_since(initial_delegation_time)
                    .unwrap()
                    .as_secs(),
                RETRY_DELAY.as_secs(),
            );
            tokio::time::sleep(RETRY_DELAY).await;
        } else {
            info!(
                env.logger(),
                "The subnet is using a new nns delegation. Success.",
            );

            break;
        }
    }
}

fn get_subnet_and_node(env: &TestEnv, subnet_type: SubnetType) -> (SubnetSnapshot, IcNodeSnapshot) {
    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == subnet_type)
        .expect("There is at least one subnet of each type");

    let node = subnet
        .nodes()
        .next()
        .expect("There is at least one node in the subnet");

    (subnet, node)
}

async fn get_nns_delegation_timestamp(
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> Option<u64> {
    let delegation = agent
        .read_state_raw(vec![vec!["time".into()]], effective_canister_id.into())
        .await
        .expect("The node is up and running and should respond to the request")
        .delegation?;

    let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
        .expect("Should return a certificate which can be deserialized");
    let tree = LabeledTree::try_from(parsed_delegation.tree)
        .expect("Should return a state tree which can be parsed");

    let timestamp: Vec<u8> =
        match lookup_path(&tree, &[b"time"]).expect("Every delegation has a '/time' path") {
            LabeledTree::Leaf(value) => value.clone(),
            LabeledTree::SubTree(_) => panic!("Not a leaf"),
        };

    Some(leb128::read::unsigned(&mut std::io::Cursor::new(&timestamp)).unwrap())
}

fn upgrade_subnet_if_necessary(env: &TestEnv, subnet: &SubnetSnapshot, node: &IcNodeSnapshot) {
    let nns_node = get_nns_node(&env.topology_snapshot());

    let initial_version = get_guestos_img_version().expect("initial version");
    let target_version = get_guestos_update_img_version().expect("target IC version");

    if initial_version == target_version {
        // No upgrade needed
        return;
    }

    let sha256 = get_guestos_update_img_sha256().unwrap();
    let upgrade_url = get_guestos_update_img_url().unwrap();

    block_on(bless_replica_version(
        &nns_node,
        &target_version,
        &env.logger(),
        sha256,
        /*guest_launch_measurements=*/ None,
        vec![upgrade_url.to_string()],
    ));

    block_on(deploy_guestos_to_all_subnet_nodes(
        &nns_node,
        &target_version,
        subnet.subnet_id,
    ));

    assert_assigned_replica_version(&node, &target_version, env.logger());
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(std::time::Duration::from_secs(15 * 60))
        .add_test(systest!(nns_delegation_on_nns_test))
        .add_test(systest!(nns_delegation_on_app_subnet_test))
        .execute_from_args()
}
