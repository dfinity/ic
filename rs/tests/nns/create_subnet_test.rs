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
. starting from a zero baseline, after each proposal verify that the
  `consensus_dkg_remote_transcripts_delivered_total` metric incremented by
  exactly one (per tag) on the expected dealing subnet and on no other, so
  each increment is attributed to a single `SetupInitialDKG` call
. validate that all create-subnet proposals were executed and the subnets are
  operational

Success::
. all create-subnet proposals are adopted and executed
. registry subnet list contains the original subnets plus the newly created
  ones
. universal canisters can be installed onto all new subnets and are
  responsive
. each `SetupInitialDKG` call is dealt by the expected subnet, so each of the
  three original subnets ends up having handled exactly two such calls

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
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use registry_canister::mutations::do_create_subnet::CanisterCyclesCostSchedule;
use registry_canister::mutations::do_set_default_initial_dkg_subnet::SetDefaultInitialDkgSubnetPayload;
use slog::{Logger, info};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::time::Duration;

const METRIC_TIMEOUT: Duration = Duration::from_secs(120);
const METRIC_BACKOFF: Duration = Duration::from_secs(5);

const NODES_PER_SUBNET: usize = 4;
const ORIGINAL_SUBNETS: usize = 3;
const NEW_SUBNETS: usize = 6;
const PROPOSALS_PER_BATCH: usize = NEW_SUBNETS / ORIGINAL_SUBNETS;

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
    let nns_subnet_id = nns_subnet.subnet_id;
    let mut other_original_subnets = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_id != nns_subnet_id);
    let default_subnet = other_original_subnets
        .next()
        .expect("missing second original subnet for setup_initial_dkg");
    let third_subnet = other_original_subnets
        .next()
        .expect("missing third original subnet for setup_initial_dkg");
    assert!(
        other_original_subnets.next().is_none(),
        "expected exactly {ORIGINAL_SUBNETS} original subnets"
    );
    let default_initial_dkg_subnet_id = default_subnet.subnet_id;
    let third_subnet_id = third_subnet.subnet_id;
    let nns_endpoint = nns_subnet.nodes().next().unwrap();

    // The three original subnets, each of which acts as the DKG dealing subnet
    // for exactly one of the three proposal batches below.
    let original_subnets = vec![nns_subnet, default_subnet, third_subnet];
    let original_subnet_ids: Vec<SubnetId> = original_subnets.iter().map(|s| s.subnet_id).collect();
    // Per-subnet count of delivered remote DKG transcripts (per tag), starting
    // from zero and updated after every proposal so that each increment can be
    // attributed to a single `SetupInitialDKG` call.
    let mut expected_transcripts: HashMap<SubnetId, u64> =
        original_subnet_ids.iter().map(|id| (*id, 0)).collect();

    let mut unassigned_nodes = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id);

    // [Phase II] Submit proposals in three batches and verify execution.
    let client = RegistryCanister::new_with_query_timeout(
        vec![nns_endpoint.get_public_url()],
        Duration::from_secs(10),
    );

    let topology_snapshot_after_proposals = block_on(async move {
        let original_subnet_list = get_subnet_list_from_registry(&client).await;
        assert_eq!(original_subnet_list.len(), ORIGINAL_SUBNETS);
        info!(log, "original subnets: {:?}", original_subnet_list);

        let version = get_software_version_from_snapshot(&nns_endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(
            nns_endpoint.get_public_url(),
            nns_endpoint.effective_canister_id(),
        );
        let governance = nns::get_governance_canister(&nns);

        // Baseline: before any proposal, no remote DKG transcripts have been
        // delivered on any original subnet.
        wait_for_expected_transcripts(log, &original_subnets, &expected_transcripts).await;

        // Batch 1: explicit `initial_dkg_subnet_id = None`, no default
        // configured yet. Routed to the NNS subnet.
        info!(
            log,
            "Batch 1: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit initial_dkg_subnet_id = None",
        );
        submit_create_subnet_proposals_and_check(
            log,
            &governance,
            &mut unassigned_nodes,
            version.clone(),
            None,
            nns_subnet_id,
            PROPOSALS_PER_BATCH,
            &original_subnets,
            &mut expected_transcripts,
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
        wait_until_subnet_mr_version(log, &original_subnets[0], target_version).await;

        // Batch 2: no explicit `initial_dkg_subnet_id`. Routed to the configured default.
        info!(
            log,
            "Batch 2: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit \
             initial_dkg_subnet_id = None (routed to default {default_initial_dkg_subnet_id})"
        );
        submit_create_subnet_proposals_and_check(
            log,
            &governance,
            &mut unassigned_nodes,
            version.clone(),
            None,
            default_initial_dkg_subnet_id,
            PROPOSALS_PER_BATCH,
            &original_subnets,
            &mut expected_transcripts,
        )
        .await;

        // Batch 3: explicit `initial_dkg_subnet_id` overrides the default.
        info!(
            log,
            "Batch 3: {PROPOSALS_PER_BATCH} create-subnet proposals, explicit \
             initial_dkg_subnet_id = {third_subnet_id} (third original subnet)"
        );
        submit_create_subnet_proposals_and_check(
            log,
            &governance,
            &mut unassigned_nodes,
            version,
            Some(third_subnet_id),
            third_subnet_id,
            PROPOSALS_PER_BATCH,
            &original_subnets,
            &mut expected_transcripts,
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

        let original_subnet_set = set(&original_subnet_list);
        let final_subnet_set = set(&final_subnets);
        // check that there are exactly NEW_SUBNETS added subnets
        assert_eq!(
            final_subnet_set.len(),
            original_subnet_set.len() + NEW_SUBNETS,
            "Expected {} new subnets in addition to the original {:?} subnets, but found {:?}",
            NEW_SUBNETS,
            original_subnet_set,
            final_subnet_set
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
}

/// Submits `count` create-application-subnet proposals one at a time (each
/// consuming `NODES_PER_SUBNET` unassigned nodes). After each proposal has
/// executed, verifies that the delivered-remote-transcripts counter on
/// `target_subnet_id` increased by exactly one per tag while all other
/// original subnets stayed unchanged.
#[allow(clippy::too_many_arguments)]
async fn submit_create_subnet_proposals_and_check(
    log: &Logger,
    governance: &Canister<'_>,
    unassigned_nodes: &mut impl Iterator<Item = NodeId>,
    version: ReplicaVersion,
    initial_dkg_subnet_id: Option<SubnetId>,
    target_subnet_id: SubnetId,
    count: usize,
    original_subnets: &[SubnetSnapshot],
    expected_transcripts: &mut HashMap<SubnetId, u64>,
) {
    for _ in 0..count {
        let nodes = unassigned_nodes.by_ref().take(NODES_PER_SUBNET).collect();
        info!(
            log,
            "Submitting proposal to create subnet with nodes: {nodes:?}, \
             initial_dkg_subnet_id: {initial_dkg_subnet_id:?} \
             (expecting transcripts to be dealt by {target_subnet_id})"
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
        info!(log, "Waiting on proposal {proposal_id}");
        let proposal_info = wait_for_final_state(governance, proposal_id).await;
        assert_eq!(
            proposal_info.status,
            ProposalStatus::Executed as i32,
            "proposal {proposal_id} did not execute: {proposal_info:?}"
        );

        // This proposal triggers a single `SetupInitialDKG` call, dealt by
        // `target_subnet_id`, which delivers one remote transcript per tag
        // there and none on any other subnet.
        *expected_transcripts.entry(target_subnet_id).or_insert(0) += 1;
        wait_for_expected_transcripts(log, original_subnets, expected_transcripts).await;
    }
}

/// Retries until, for every subnet in `subnets`, all of its nodes report the
/// per-tag delivered-remote-transcripts count given in `expected` (keyed by
/// subnet id, defaulting to zero) on both the `LowThreshold` and
/// `HighThreshold` tags. A subnet expected to be at zero must not expose the
/// counter series yet.
async fn wait_for_expected_transcripts(
    log: &Logger,
    subnets: &[SubnetSnapshot],
    expected: &HashMap<SubnetId, u64>,
) {
    let tag_keys: Vec<String> = ["LowThreshold", "HighThreshold"]
        .iter()
        .map(|tag| format!("consensus_dkg_remote_transcripts_delivered_total{{tag=\"{tag}\"}}"))
        .collect();
    let fetchers: Vec<(SubnetId, usize, MetricsFetcher)> = subnets
        .iter()
        .map(|s| {
            (
                s.subnet_id,
                s.nodes().count(),
                MetricsFetcher::new(s.nodes(), tag_keys.clone()),
            )
        })
        .collect();

    retry_with_msg_async!(
        format!("Waiting until delivered remote DKG transcript counters reach {expected:?}"),
        log,
        METRIC_TIMEOUT,
        METRIC_BACKOFF,
        || async {
            for (subnet_id, node_count, fetcher) in &fetchers {
                let want = expected.get(subnet_id).copied().unwrap_or(0);
                let values = match fetcher.fetch::<u64>().await {
                    Ok(values) => values,
                    Err(err) => bail!("Failed to fetch metrics from subnet {subnet_id}: {err}"),
                };
                for key in &tag_keys {
                    let node_metric_values = values.get(key).map(Vec::as_slice).unwrap_or(&[]);
                    if want == 0 {
                        // No delivery expected yet: the series must be absent or zero.
                        if node_metric_values.iter().any(|v| *v != 0) {
                            bail!(
                                "Subnet {subnet_id}: metric {key} reports {node_metric_values:?}, \
                                 expected no deliveries yet"
                            );
                        }
                    } else {
                        if node_metric_values.len() != *node_count {
                            bail!(
                                "Subnet {subnet_id}: metric {key} reported by {} out of {} nodes",
                                node_metric_values.len(),
                                node_count,
                            );
                        }
                        if node_metric_values.iter().any(|v| *v != want) {
                            bail!(
                                "Subnet {subnet_id}: metric {key} reports {node_metric_values:?}, \
                                 expected all values to be {want}"
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|err| {
        panic!("Delivered remote DKG transcript counters did not reach {expected:?}: {err}")
    });
}

/// Retries until every node of `subnet` reports an `mr_registry_version` of
/// at least `target_version`.
async fn wait_until_subnet_mr_version(log: &Logger, subnet: &SubnetSnapshot, target_version: u64) {
    let expected_node_count = subnet.nodes().count();
    let metrics = MetricsFetcher::new(subnet.nodes(), vec!["mr_registry_version".into()]);
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
            let Some(node_metric_values) = values.get("mr_registry_version") else {
                bail!("Metric mr_registry_version not yet exposed on subnet {subnet_id}");
            };
            if node_metric_values.len() != expected_node_count {
                bail!(
                    "Subnet {subnet_id}: metric mr_registry_version reported by {} out \
                     of {} nodes",
                    node_metric_values.len(),
                    expected_node_count,
                );
            }
            if let Some(subnet_version) = node_metric_values.iter().find(|v| **v < target_version) {
                bail!(
                    "Subnet {subnet_id}: a node is still at MR registry version {subnet_version} \
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
