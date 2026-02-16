use std::time::Duration;

use anyhow::Result;

use ic_consensus_system_test_upgrade_common::{
    bless_target_version, get_chain_key_canister_and_public_key, upgrade,
};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::make_key_ids_for_all_schemes;
use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
};
use ic_system_test_driver::systest;
use ic_types::Height;

const DKG_INTERVAL: u64 = 9;
const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes
const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

fn setup(env: TestEnv) {
    let subnet_under_test = Subnet::new(SubnetType::Application)
        .add_nodes(SUBNET_SIZE)
        .with_dkg_interval_length(Height::from(DKG_INTERVAL))
        .with_chain_key_config(ChainKeyConfig {
            key_configs: make_key_ids_for_all_schemes()
                .into_iter()
                .map(|key_id| KeyConfig {
                    max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                    pre_signatures_to_create_in_advance: key_id
                        .requires_pre_signatures()
                        .then_some(5),
                    key_id,
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(subnet_under_test)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the app subnet to the target version
fn upgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let target_version = bless_target_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let ecdsa_state = get_chain_key_canister_and_public_key(
        &env,
        &nns_node,
        &agent,
        SubnetType::Application,
        make_key_ids_for_all_schemes(),
    );

    upgrade(
        &env,
        &nns_node,
        &target_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(upgrade_app_subnet))
        .execute_from_args()?;
    Ok(())
}
