use std::time::Duration;

use anyhow::Result;

use canister_test::Canister;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing_with_timeout_and_rotation_period, get_public_key_with_logger,
    make_key_ids_for_all_idkg_schemes, setup_without_ecdsa_on_nns,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
    util::{MessageCanister, MetricsFetcher, block_on, runtime_from_url},
};
use slog::info;

const MASTER_KEY_TRANSCRIPTS_CREATED: &str = "consensus_master_key_transcripts_created";

/// Tests whether chain key transcripts are correctly reshared when crypto keys are rotated
/// using the test settings below:
/// - DKG interval is set to 19, which roughly takes 20 or so seconds.
/// - Keys are rotated every 50 seconds, which should take more than 2 DKG intervals.
fn test(test_env: TestEnv) {
    let log = test_env.logger();
    let topology = test_env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();

    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        let key_ids = make_key_ids_for_all_idkg_schemes();
        enable_chain_key_signing_with_timeout_and_rotation_period(
            &governance,
            app_subnet.subnet_id,
            key_ids.clone(),
            None,
            Some(Duration::from_secs(50)),
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        // Get the public key first to make sure feature is working
        for key_id in &key_ids {
            let _public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();

            let mut count = 0;
            let mut created = 0;
            let metric_with_label =
                format!("{MASTER_KEY_TRANSCRIPTS_CREATED}{{key_id=\"{key_id}\"}}");
            let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
            loop {
                match metrics.fetch::<u64>().await {
                    Ok(val) => {
                        created = val[&metric_with_label][0];
                        if created > 1 {
                            break;
                        }
                    }
                    Err(err) => {
                        info!(log, "Could not connect to metrics yet {:?}", err);
                    }
                }
                count += 1;
                // Break after 200 tries
                if count > 200 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
            if created <= 1 {
                panic!("Failed to observe key transcript being reshared more than once");
            }
        }
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_without_ecdsa_on_nns)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
