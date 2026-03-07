use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, bail};

use canister_test::Canister;
use ic_consensus_threshold_sig_system_test_utils::{
    await_pre_signature_stash_size, enable_chain_key_signing_with_timeout_and_rotation_period,
    get_public_key_with_logger, make_key_ids_for_all_idkg_schemes, set_pre_signature_stash_size,
    setup_without_ecdsa_on_nns,
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
use ic_types::Height;
use slog::info;

const MASTER_KEY_TRANSCRIPTS_CREATED: &str = "consensus_master_key_transcripts_created";

/// Fetches the minimum `consensus_master_key_transcripts_created` metric value
/// across all nodes in the subnet for the given key, retrying until all nodes
/// report the metric or the timeout expires.
async fn fetch_min_transcript_count(
    metrics: &MetricsFetcher,
    key_id: &impl std::fmt::Display,
    metric_with_label: &str,
    node_count: usize,
) -> Result<u64> {
    let val = metrics.fetch::<u64>().await?;
    let counts = val.get(metric_with_label).ok_or_else(|| {
        anyhow::anyhow!("Metric {} not found for key {}", metric_with_label, key_id)
    })?;
    if counts.len() != node_count {
        bail!(
            "Metric {} reported by {} out of {} nodes",
            metric_with_label,
            counts.len(),
            node_count
        );
    }
    counts
        .iter()
        .copied()
        .min()
        .ok_or_else(|| anyhow::anyhow!("No sample yet for key {}", key_id))
}

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
        let key_rotation_period = Some(Duration::from_secs(50));
        enable_chain_key_signing_with_timeout_and_rotation_period(
            &governance,
            app_subnet.subnet_id,
            key_ids.clone(),
            None,
            key_rotation_period,
            &log,
        )
        .await;
        // Stash size should be 5 before the rotation
        await_pre_signature_stash_size(&app_subnet, 5, key_ids.as_slice(), &log);
        // Turn off pre-signature creation to verify that the stash is purged correctly
        set_pre_signature_stash_size(
            &governance,
            app_subnet.subnet_id,
            key_ids.as_slice(),
            /* max_parallel_pre_signatures */ 0,
            /* max_stash_size */ 5,
            key_rotation_period,
            &log,
        )
        .await;

        // Capture current transcript counts immediately after disabling
        // pre-signature creation so we can detect NEW rotations that happen
        // after the config change. Without this, the check can be satisfied
        // by rotations that happened before, causing the stash to never reach 0.
        let node_count = app_subnet.nodes().count();
        let mut initial_counts = BTreeMap::new();
        for key_id in &key_ids {
            let metric_with_label =
                format!("{MASTER_KEY_TRANSCRIPTS_CREATED}{{key_id=\"{key_id}\"}}");
            let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
            let initial = ic_system_test_driver::retry_with_msg_async!(
                format!("Fetching initial transcript count for key {key_id}"),
                &log,
                Duration::from_secs(60),
                Duration::from_secs(1),
                || async {
                    fetch_min_transcript_count(&metrics, key_id, &metric_with_label, node_count)
                        .await
                }
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to obtain initial transcript count for key {}: {e}",
                    key_id
                )
            });
            initial_counts.insert(key_id, initial);
        }

        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        // Get the public key first to make sure feature is working
        let mut pub_keys = BTreeMap::new();
        for key_id in &key_ids {
            let public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();
            pub_keys.insert(key_id, public_key);
        }

        for key_id in &key_ids {
            let metric_with_label =
                format!("{MASTER_KEY_TRANSCRIPTS_CREATED}{{key_id=\"{key_id}\"}}");
            let initial = initial_counts[key_id];
            let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
            let created = ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "Waiting for key transcript rotation for key {key_id} \
                     (initial count: {initial})"
                ),
                &log,
                Duration::from_secs(200),
                Duration::from_secs(1),
                || async {
                    let created = fetch_min_transcript_count(
                        &metrics,
                        key_id,
                        &metric_with_label,
                        node_count,
                    )
                    .await?;
                    if created > initial {
                        Ok(created)
                    } else {
                        bail!(
                            "Key transcript for key {} not yet reshared \
                             (initial: {}, current min: {})",
                            key_id,
                            initial,
                            created
                        )
                    }
                }
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to observe key transcript for key {} being reshared \
                     (initial: {}): {:?}",
                    key_id, initial, e
                )
            });
            info!(
                log,
                "Observed key transcript for key {} being reshared \
                 (initial min: {}, current min: {})",
                key_id,
                initial,
                created
            );
        }

        // Stash size should be 0 after the rotation
        await_pre_signature_stash_size(&app_subnet, 0, key_ids.as_slice(), &log);

        // Ensure that public keys are the same after the rotation
        for key_id in &key_ids {
            let public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();
            assert_eq!(
                public_key, pub_keys[key_id],
                "Public key changed after rotation"
            );
        }
    });
}

fn setup(test_env: TestEnv) {
    setup_without_ecdsa_on_nns(test_env, Height::from(19));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
