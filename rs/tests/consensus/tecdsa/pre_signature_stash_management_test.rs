/* tag::catalog[]
Title:: Pre-signature stash management test

Goal:: Test that increasing and decreasing the pre-signature stash size works as expected

Runbook::
. Setup:
    . App subnet comprising N nodes, with all supported chain keys enabled.
. Initially, the stash size is set to 20.
. Decrease the stash size to 1 via proposal.
. Assert that the stash size is 1 on all nodes.
. Stop pre-signature generation and increase the stash size to 15 via proposal.
. Assert that the stash size is still 1.
. Send a signature request for each key and assert that the signatures succeed.
. Assert that the stash size is now 0.
. Start pre-signature generation again.
. Assert that the stash size is now 15.

Success::
. Pre-signature stash size can be increased and decreased via proposal.
. Chain key signatures succeed.

end::catalog[] */

use anyhow::{bail, Result};
use canister_test::Canister;
use ic_consensus_system_test_utils::node::{
    await_node_certified_height, get_node_certified_height,
};
use ic_consensus_threshold_sig_system_test_utils::{
    empty_subnet_update, execute_update_subnet_proposal, get_master_public_key,
    make_key_ids_for_all_idkg_schemes, run_chain_key_signature_test,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            SubnetSnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    systest,
    util::{block_on, runtime_from_url, MessageCanister, MetricsFetcher},
};
use ic_types::{Height, SubnetId};
use registry_canister::mutations::do_update_subnet::{
    ChainKeyConfig as ChainKeyConfigUpdate, KeyConfig as KeyConfigUpdate, UpdateSubnetPayload,
};
use slog::{info, Logger};

const MAX_PARALLEL_PRE_SIGNATURES: u32 = 10;
const DKG_INTERVAL_LENGTH: u64 = 19;

fn setup(test_env: TestEnv) {
    let key_ids = make_key_ids_for_all_idkg_schemes();
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
                .add_nodes(4)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: key_ids
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            key_id,
                            pre_signatures_to_create_in_advance: 20,
                            max_queue_size: 20,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: Some(
                        MAX_PARALLEL_PRE_SIGNATURES,
                    ),
                }),
        )
        .setup_and_start(&test_env)
        .expect("Could not start IC!");

    test_env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    let nns_node = test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &test_env)
        .expect("Failed to install NNS canisters");
}

fn await_pre_signature_stash_size(
    subnet: &SubnetSnapshot,
    expected_size: usize,
    key_ids: &[MasterPublicKeyId],
    log: &Logger,
) {
    let metric_vec = key_ids
        .iter()
        .map(|key_id| format!("execution_pre_signature_stash_size{{key_id=\"{key_id}\"}}"))
        .collect::<Vec<_>>();
    let metrics = MetricsFetcher::new(subnet.nodes(), metric_vec.clone());
    ic_system_test_driver::retry_with_msg!(
        format!(
            "Waiting until pre-signature stashes for key_ids {key_ids:?} are of size {expected_size}",
        ),
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match block_on(metrics.fetch::<usize>()) {
            Ok(val) => {
                for metric in &metric_vec {
                    let sizes = &val[metric];
                    assert_eq!(sizes.len(), subnet.nodes().count());
                    for size in sizes {
                        if *size != expected_size {
                            bail!(
                                "Pre-signature stash for key_id {} is of size {}, but expected {}",
                                metric, size, expected_size
                            );
                        }
                    }
                }
                Ok(())
            }
            Err(err) => {
                bail!("Could not connect to metrics yet {:?}", err);
            }
        }
    )
    .expect("The subnet did not reach the required pre-signature stash size in time");
}

async fn set_pre_signature_stash_size(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: &[MasterPublicKeyId],
    max_parallel_pre_signature_transcripts_in_creation: u32,
    pre_signatures_to_create_in_advance: u32,
    log: &Logger,
) {
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        chain_key_config: Some(ChainKeyConfigUpdate {
            key_configs: key_ids
                .into_iter()
                .map(|key_id| KeyConfigUpdate {
                    key_id: Some(key_id.clone()),
                    pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
                    max_queue_size: Some(20),
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: Some(
                max_parallel_pre_signature_transcripts_in_creation,
            ),
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload, "Update Chain key config", log)
        .await;
}

fn test(test_env: TestEnv) {
    let log = test_env.logger();
    let topology = test_env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

    let key_ids = make_key_ids_for_all_idkg_schemes();
    await_pre_signature_stash_size(&app_subnet, 20, key_ids.as_slice(), &log);

    info!(log, "Reducing pre-signature stash size to 1");
    block_on(set_pre_signature_stash_size(
        &governance,
        app_subnet.subnet_id,
        key_ids.as_slice(),
        MAX_PARALLEL_PRE_SIGNATURES,
        /* max_stash_size */ 1,
        &log,
    ));
    await_pre_signature_stash_size(&app_subnet, 1, key_ids.as_slice(), &log);

    info!(
        log,
        "Stopping pre-signature generation, and increasing max stash size to 15"
    );
    block_on(set_pre_signature_stash_size(
        &governance,
        app_subnet.subnet_id,
        key_ids.as_slice(),
        /* max_parallel_pre_signatures */ 0,
        /* max_stash_size */ 15,
        &log,
    ));
    // Sleep for two DKG intervals
    let app_node = app_subnet.nodes().next().unwrap();
    let height = get_node_certified_height(&app_node, log.clone());
    let target_height = height + Height::from(2 * DKG_INTERVAL_LENGTH);
    await_node_certified_height(&app_node, target_height, log.clone());
    // Pre-signature stash size should still be 1
    await_pre_signature_stash_size(&app_subnet, 1, key_ids.as_slice(), &log);

    info!(log, "Sending a signature request for each key");
    let agent = app_node.build_default_agent();
    let msg_canister = block_on(MessageCanister::new(
        &agent,
        app_node.effective_canister_id(),
    ));
    for key_id in &key_ids {
        let public_key = get_master_public_key(&msg_canister, key_id, &log);
        run_chain_key_signature_test(&msg_canister, &log, key_id, public_key);
    }

    // Stash size should be 0
    await_pre_signature_stash_size(&app_subnet, 0, key_ids.as_slice(), &log);

    info!(log, "Starting pre-signature generation again");
    block_on(set_pre_signature_stash_size(
        &governance,
        app_subnet.subnet_id,
        key_ids.as_slice(),
        MAX_PARALLEL_PRE_SIGNATURES,
        /* max_stash_size */ 15,
        &log,
    ));
    await_pre_signature_stash_size(&app_subnet, 15, key_ids.as_slice(), &log);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
