/* tag::catalog[]
Title:: Create Subnet

Goal:: Ensure that subnets can be created from unassigned nodes and that the
`SetupInitialDKG` management canister call is routed according to the
`default_initial_dkg_subnet_id` registry key and the optional explicit
`initial_dkg_subnet_id` field of the `CreateSubnet` payload.

Runbook::
. set up the IC with three original system subnets and a pool of unassigned nodes
. submit two create-subnet proposals without explicit `initial_dkg_subnet_id` set,
  while no default initial DKG subnet is configured
. submit a proposal to set the default initial DKG subnet to the second
  original subnet
. submit two create-subnet proposals without `initial_dkg_subnet_id`; these
  should be routed to the configured default
. submit two create-subnet proposals with `initial_dkg_subnet_id` set to the
  third original subnet
. validate that all create-subnet proposals were executed and the subnets are
  operational
. validate that the `consensus_dkg_remote_transcripts_delivered_total` metric
  on each of the three original subnets were incremented correctly

Success::
. all create-subnet proposals are adopted and executed
. registry subnet list contains the original subnets plus the newly created
  ones
. universal canisters can be installed onto all new subnets and are
  responsive
. each of the three original subnets has handled exactly two
  `SetupInitialDKG` calls

end::catalog[] */

use anyhow::{Result, bail};
use canister_test::Canister;
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::wait_for_final_state;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder, SshSession,
    SubnetSnapshot,
};
use ic_system_test_driver::nns::get_subnet_list_from_registry;
use ic_system_test_driver::nns::{
    self, get_software_version_from_snapshot,
    submit_create_application_subnet_proposal_with_initial_dkg_subnet,
    submit_external_proposal_with_test_id,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MetricsFetcher, UniversalCanister, assert_create_agent, block_on, runtime_from_url,
};
use ic_types::{Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use registry_canister::mutations::do_create_subnet::CanisterCyclesCostSchedule;
use registry_canister::mutations::do_set_default_initial_dkg_subnet::SetDefaultInitialDkgSubnetPayload;
use slog::{Logger, info};
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::Duration;

const METRIC_TIMEOUT: Duration = Duration::from_secs(120);
const METRIC_BACKOFF: Duration = Duration::from_secs(5);
const MR_REGISTRY_VERSION_METRIC: &str = "mr_registry_version";
const REMOTE_TRANSCRIPTS_METRIC: &str = "consensus_dkg_remote_transcripts_delivered_total";

const NODES_PER_SUBNET: usize = 4;
const ORIGINAL_SUBNETS: usize = 3;
const NEW_SUBNETS: usize = 6;
const PROPOSALS_PER_BATCH: usize = NEW_SUBNETS / ORIGINAL_SUBNETS;
/// Expected per-tag value of `REMOTE_TRANSCRIPTS_METRIC` on each original
/// subnet at the end of the test (one transcript per `SetupInitialDKG` call
/// per tag).
const EXPECTED_TRANSCRIPTS_PER_TAG: u64 = PROPOSALS_PER_BATCH as u64;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new();
    // First System subnet becomes the NNS / root subnet.
    for _ in 0..ORIGINAL_SUBNETS {
        ic = ic.add_subnet(Subnet::fast(SubnetType::System, NODES_PER_SUBNET));
    }
    ic.with_unassigned_nodes(NODES_PER_SUBNET * NEW_SUBNETS)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    env.topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());
}

pub fn test(env: TestEnv) {
    let log = &env.logger();

    // [Phase I] Prepare NNS
    install_nns_canisters(&env);
    let topology_snapshot = &env.topology_snapshot();
    let nns_subnet = topology_snapshot.root_subnet();
    let other_original_subnets: Vec<SubnetSnapshot> = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_id != nns_subnet.subnet_id)
        .collect();
    assert_eq!(other_original_subnets.len(), ORIGINAL_SUBNETS - 1);
    let default_initial_dkg_subnet_id = other_original_subnets[0].subnet_id;
    let third_subnet_id = other_original_subnets[1].subnet_id;
    let original_subnet_ids = [
        nns_subnet.subnet_id,
        default_initial_dkg_subnet_id,
        third_subnet_id,
    ];
    let nns_endpoint = nns_subnet.nodes().next().unwrap();
    let mut unassigned_nodes = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id);

    // [Phase II] Submit proposals in three batches and verify execution.
    let client = RegistryCanister::new_with_query_timeout(
        vec![nns_endpoint.get_public_url()],
        Duration::from_secs(10),
    );

    let topology_snapshot_after_proposals = block_on(async move {
        let original_subnets = get_subnet_list_from_registry(&client).await;
        assert_eq!(original_subnets.len(), ORIGINAL_SUBNETS);
        info!(log, "original subnets: {:?}", original_subnets);

        let version = get_software_version_from_snapshot(&nns_endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(
            nns_endpoint.get_public_url(),
            nns_endpoint.effective_canister_id(),
        );
        let governance = nns::get_governance_canister(&nns);

        // Batch 1: explicit `initial_dkg_subnet_id = None`, no default
        // configured yet. Routed to the NNS subnet.
        info!(
            log,
            "Batch 1: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit initial_dkg_subnet_id = None",
        );
        submit_and_wait_for_create_subnet_proposals(
            log,
            &governance,
            &mut unassigned_nodes,
            version.clone(),
            None,
            PROPOSALS_PER_BATCH,
        )
        .await;

        info!(
            log,
            "Setting default_initial_dkg_subnet_id to {default_initial_dkg_subnet_id}"
        );
        let proposal_id = submit_external_proposal_with_test_id(
            &governance,
            NnsFunction::SetDefaultInitialDkgSubnet,
            SetDefaultInitialDkgSubnetPayload {
                subnet_id: Some(default_initial_dkg_subnet_id.get()),
            },
        )
        .await;
        let proposal_info = wait_for_final_state(&governance, proposal_id).await;
        assert_eq!(proposal_info.status, ProposalStatus::Executed as i32);

        // Make sure NNS message routing has observed the new default before
        // submitting batch 2; otherwise its `SetupInitialDKG` calls could
        // still be routed based on the pre-SetDefault network topology.
        let target_version = client
            .get_latest_version()
            .await
            .expect("failed to read latest registry version");
        wait_until_subnet_mr_version(log, &nns_subnet, target_version).await;

        // Batch 2: no explicit `initial_dkg_subnet_id`. Routed to the configured default.
        info!(
            log,
            "Batch 2: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit \
             initial_dkg_subnet_id = None (routed to default {default_initial_dkg_subnet_id})"
        );
        submit_and_wait_for_create_subnet_proposals(
            log,
            &governance,
            &mut unassigned_nodes,
            version.clone(),
            None,
            PROPOSALS_PER_BATCH,
        )
        .await;

        // Batch 3: explicit `initial_dkg_subnet_id` overrides the default.
        info!(
            log,
            "Batch 3: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit \
             initial_dkg_subnet_id = {third_subnet_id} (third original subnet)"
        );
        submit_and_wait_for_create_subnet_proposals(
            log,
            &governance,
            &mut unassigned_nodes,
            version,
            Some(third_subnet_id),
            PROPOSALS_PER_BATCH,
        )
        .await;

        // One initial version plus one registry mutation per CreateSubnet plus one for SetDefaultInitialDkgSubnet.
        let min_version = 1 + NEW_SUBNETS as u64 + 1;
        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(min_version))
            .await
            .expect("Could not obtain updated registry.");

        // Check that the registry indeed contains the data
        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);

        let original_subnet_set = set(&original_subnets);
        let final_subnet_set = set(&final_subnets);
        // check that there are exactly APP_SUBNETS added subnets
        assert_eq!(
            original_subnet_set.len() + NEW_SUBNETS,
            final_subnet_set.len(),
        );
        assert!(original_subnet_set.is_subset(&final_subnet_set));

        new_topology_snapshot
    });

    // [Phase III] Install a universal canister on every new subnet to verify
    // they are operational.
    let new_subnet_ids: Vec<SubnetId> = topology_snapshot_after_proposals
        .subnets()
        .map(|s| s.subnet_id)
        .filter(|id| !original_subnet_ids.contains(id))
        .collect();
    assert_eq!(new_subnet_ids.len(), NEW_SUBNETS);

    for subnet_id in &new_subnet_ids {
        info!(log, "Asserting healthy status of subnet {subnet_id}");
        let subnet = topology_snapshot_after_proposals
            .subnets()
            .find(|subnet| subnet.subnet_id == *subnet_id)
            .expect("Could not find newly created subnet.");
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap());
        let endpoint = subnet
            .nodes()
            .next()
            .expect("Could not find any node in newly created subnet.");

        block_on(async move {
            let agent = assert_create_agent(endpoint.get_public_url().as_str()).await;
            info!(
                log,
                "successfully created agent for endpoint of subnet node"
            );

            let universal_canister =
                UniversalCanister::new_with_retries(&agent, endpoint.effective_canister_id(), log)
                    .await;
            info!(log, "successfully created a universal canister instance");

            const UPDATE_MSG_1: &[u8] =
                b"This beautiful prose should be persisted for future generations";

            universal_canister.store_to_stable(0, UPDATE_MSG_1).await;
            info!(log, "successfully saved message in the universal canister");

            assert_eq!(
                universal_canister
                    .try_read_stable(0, UPDATE_MSG_1.len() as u32)
                    .await,
                UPDATE_MSG_1.to_vec(),
                "could not validate that subnet is healthy: universal canister is broken"
            );
        });
    }

    // [Phase IV] Verify each original subnet handled the expected number of
    // SetupInitialDKG calls.
    for subnet in topology_snapshot_after_proposals.subnets() {
        if !original_subnet_ids.contains(&subnet.subnet_id) {
            continue;
        }
        block_on(assert_remote_transcripts_delivered_per_tag(
            log,
            &subnet,
            EXPECTED_TRANSCRIPTS_PER_TAG,
        ));
    }
}

/// Submits `count` create-application-subnet proposals (each consuming
/// `NODES_PER_SUBNET` unassigned nodes) and waits for all of them to execute.
async fn submit_and_wait_for_create_subnet_proposals(
    log: &Logger,
    governance: &Canister<'_>,
    unassigned_nodes: &mut impl Iterator<Item = NodeId>,
    version: ReplicaVersion,
    initial_dkg_subnet_id: Option<SubnetId>,
    count: usize,
) {
    let mut proposal_ids = Vec::with_capacity(count);
    for _ in 0..count {
        let nodes = unassigned_nodes.by_ref().take(NODES_PER_SUBNET).collect();
        info!(
            log,
            "Submitting proposal to create subnet with nodes: {nodes:?}, \
             initial_dkg_subnet_id: {initial_dkg_subnet_id:?}"
        );
        let proposal_id = submit_create_application_subnet_proposal_with_initial_dkg_subnet(
            governance,
            nodes,
            version.clone(),
            Some(CanisterCyclesCostSchedule::Normal),
            Some(0),
            initial_dkg_subnet_id,
        )
        .await;
        proposal_ids.push(proposal_id);
    }
    for proposal_id in proposal_ids {
        info!(log, "Waiting on proposal {proposal_id}");
        let proposal_info = wait_for_final_state(governance, proposal_id).await;
        assert_eq!(
            proposal_info.status,
            ProposalStatus::Executed as i32,
            "proposal {proposal_id} did not execute: {proposal_info:?}"
        );
    }
}

/// Retries until every node of `subnet` reports `expected_per_tag` for
/// `REMOTE_TRANSCRIPTS_METRIC` on both the `LowThreshold` and
/// `HighThreshold` tags.
async fn assert_remote_transcripts_delivered_per_tag(
    log: &Logger,
    subnet: &SubnetSnapshot,
    expected_per_tag: u64,
) {
    let metric_keys: Vec<String> = ["LowThreshold", "HighThreshold"]
        .iter()
        .map(|tag| format!("{REMOTE_TRANSCRIPTS_METRIC}{{tag=\"{tag}\"}}"))
        .collect();
    let expected_node_count = subnet.nodes().count();
    let metrics = MetricsFetcher::new(subnet.nodes(), metric_keys.clone());
    let subnet_id = subnet.subnet_id;

    retry_with_msg_async!(
        format!(
            "Waiting until subnet {subnet_id} reports {expected_per_tag} delivered remote DKG \
             transcripts per tag on all {expected_node_count} nodes"
        ),
        log,
        METRIC_TIMEOUT,
        METRIC_BACKOFF,
        || async {
            let values = match metrics.fetch::<u64>().await {
                Ok(values) => values,
                Err(err) => bail!("Failed to fetch metrics from subnet {subnet_id}: {err}"),
            };
            for key in &metric_keys {
                let Some(per_node) = values.get(key) else {
                    bail!("Metric {key} not yet exposed on subnet {subnet_id}");
                };
                if per_node.len() != expected_node_count {
                    bail!(
                        "Subnet {subnet_id}: metric {key} reported by {} out of {} nodes",
                        per_node.len(),
                        expected_node_count,
                    );
                }
                if per_node.iter().any(|v| *v != expected_per_tag) {
                    bail!(
                        "Subnet {subnet_id}: metric {key} reports {per_node:?}, \
                         expected all values to be {expected_per_tag}"
                    );
                }
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|err| {
        panic!(
            "Subnet {subnet_id} did not deliver the expected number of remote DKG transcripts: \
             {err}"
        )
    });
}

/// Retries until every node of `subnet` reports an `mr_registry_version` of
/// at least `target_version`.
async fn wait_until_subnet_mr_version(log: &Logger, subnet: &SubnetSnapshot, target_version: u64) {
    let expected_node_count = subnet.nodes().count();
    let metrics = MetricsFetcher::new(subnet.nodes(), vec![MR_REGISTRY_VERSION_METRIC.into()]);
    let subnet_id = subnet.subnet_id;

    retry_with_msg_async!(
        format!(
            "Waiting until subnet {subnet_id} message routing has reached registry version \
             {target_version}"
        ),
        log,
        METRIC_TIMEOUT,
        METRIC_BACKOFF,
        || async {
            let values = match metrics.fetch::<u64>().await {
                Ok(values) => values,
                Err(err) => bail!("Failed to fetch metrics from subnet {subnet_id}: {err}"),
            };
            let Some(per_node) = values.get(MR_REGISTRY_VERSION_METRIC) else {
                bail!("Metric {MR_REGISTRY_VERSION_METRIC} not yet exposed on subnet {subnet_id}");
            };
            if per_node.len() != expected_node_count {
                bail!(
                    "Subnet {subnet_id}: metric {MR_REGISTRY_VERSION_METRIC} reported by {} out \
                     of {} nodes",
                    per_node.len(),
                    expected_node_count,
                );
            }
            if let Some(behind) = per_node.iter().find(|v| **v < target_version) {
                bail!(
                    "Subnet {subnet_id}: a node is still at MR registry version {behind} \
                     (target: {target_version})"
                );
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|err| {
        panic!("Subnet {subnet_id} did not reach MR registry version {target_version}: {err}")
    });
}

fn set<H: Clone + std::cmp::Eq + std::hash::Hash>(data: &[H]) -> HashSet<H> {
    HashSet::from_iter(data.iter().cloned())
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}
