/* tag::catalog[]
Title:: Enabling tECDSA signing on two separate subnets at the same time

Goal:: Test whether enabling tECDSA signing on two separate subnets at the same time and
       generating signatures works as expected.

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with ecdsa feature enabled.
    . N unassigned nodes.
. Reshare the key by creating a new subnet using the N unassigned nodes.
. Enable signing on the NNS.
. Get public key, and ensure signing works.
. Enable signing on the App subnet.
. Ensure signing works and public key hasn't changed.
. Disable signing on the NNS
. Ensure signing works and public key hasn't changed.

Success::
. ECDSA signature creation succeeds with the same public key as before.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    retry, HasIcDependencies, HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot,
    IcNodeContainer, SubnetSnapshot, TopologySnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
};
use crate::orchestrator::utils::rw_message::install_nns_and_check_progress;
use crate::orchestrator::utils::subnet_recovery::{get_ecdsa_pub_key, run_ecdsa_signature_test};
use crate::tecdsa::{create_new_subnet_with_keys, make_key};
use crate::{retry_with_msg, tecdsa::KEY_ID1, util::*};
use anyhow::bail;
use canister_test::Canister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, SubnetId};
use registry_canister::mutations::do_create_subnet::EcdsaKeyRequest;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{info, Logger};

use super::{empty_subnet_update, execute_update_subnet_proposal};

const NODES_COUNT: usize = 4;
const DKG_INTERVAL: u64 = 9;
const MR_REGISTRY_VERSION: &str = "mr_registry_version";

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT)
                .with_ecdsa_config(EcdsaConfig {
                    quadruples_to_create_in_advance: 5,
                    key_ids: vec![make_key(KEY_ID1)],
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                }),
        )
        .with_unassigned_nodes(NODES_COUNT)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn enable_signing(governance: &Canister<'_>, subnet_id: SubnetId, logger: &Logger) {
    let enable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![make_key(KEY_ID1)]),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        governance,
        enable_signing_payload,
        "Enable ECDSA signing",
        logger,
    ));
}

fn disable_signing(governance: &Canister<'_>, subnet_id: SubnetId, logger: &Logger) {
    let disable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_disable: Some(vec![make_key(KEY_ID1)]),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        governance,
        disable_signing_payload,
        "Disable ECDSA signing",
        logger,
    ));
}

fn wait_until_ic_mr_version(
    snapshot: &TopologySnapshot,
    target_registry_version: u64,
    logger: &Logger,
) {
    snapshot
        .subnets()
        .for_each(|subnet| wait_until_subnet_mr_version(&subnet, target_registry_version, logger));
}

fn wait_until_subnet_mr_version(
    subnet: &SubnetSnapshot,
    target_registry_version: u64,
    logger: &Logger,
) {
    info!(
        logger,
        "Waiting until message routing registry version {} on subnet {}",
        target_registry_version,
        subnet.subnet_id,
    );
    let metrics = MetricsFetcher::new(subnet.nodes().take(1), vec![MR_REGISTRY_VERSION.into()]);
    retry_with_msg!(
        format!(
            "check if message routing registry version {} on subnet {}",
            target_registry_version, subnet.subnet_id,
        ),
        logger.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match block_on(metrics.fetch::<u64>()) {
            Ok(val) => {
                let current_registry_version = val[MR_REGISTRY_VERSION][0];
                if current_registry_version >= target_registry_version {
                    Ok(())
                } else {
                    bail!(
                        "Target registry version not yet reached, current: {}, target: {}",
                        current_registry_version,
                        target_registry_version,
                    )
                }
            }
            Err(err) => {
                bail!("Could not connect to metrics yet {:?}", err);
            }
        }
    )
    .expect("The subnet did not reach the specified registry version in time")
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();

    let nns_node = get_nns_node(&snapshot);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let replica_version = env.get_initial_replica_version().unwrap();
    let mut registry_version = snapshot.get_registry_version();
    let root_subnet_id = snapshot.root_subnet_id();

    let unassigned_node_ids = snapshot.unassigned_nodes().map(|n| n.node_id).collect();

    info!(logger, "Creating new subnet with keys.");
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        vec![EcdsaKeyRequest {
            key_id: make_key(KEY_ID1),
            subnet_id: Some(root_subnet_id.get()),
        }],
        replica_version,
        &logger,
    ));
    registry_version.inc_assign();
    let snapshot = block_on(snapshot.block_for_min_registry_version(registry_version)).unwrap();

    let app_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");

    app_subnet.nodes().for_each(|n| {
        n.await_status_is_healthy()
            .expect("Timeout while waiting for all nodes to be healthy");
    });

    info!(logger, "Enabling signing on NNS.");
    enable_signing(&governance, root_subnet_id, &logger);
    registry_version.inc_assign();
    let pub_key = get_ecdsa_pub_key(&nns_canister, &logger);
    run_ecdsa_signature_test(&nns_canister, &logger, pub_key);

    info!(logger, "Enabling signing on App subnet.");
    enable_signing(&governance, app_subnet.subnet_id, &logger);
    registry_version.inc_assign();
    wait_until_ic_mr_version(&snapshot, registry_version.get(), &logger);
    run_ecdsa_signature_test(&nns_canister, &logger, pub_key);

    info!(logger, "Disabling signing on NNS.");
    disable_signing(&governance, root_subnet_id, &logger);
    registry_version.inc_assign();
    wait_until_ic_mr_version(&snapshot, registry_version.get(), &logger);
    run_ecdsa_signature_test(&nns_canister, &logger, pub_key);
}
