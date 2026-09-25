//! The "merge readiness" condition of the `Subnet merging` dashboard, evaluated
//! from the metrics of the replicas rather than from a Grafana panel.
//!
//! A subnet that is cooling down is ready to be merged once it has come to a
//! complete rest: every subnet has observed that it is cooling down, nothing is
//! in flight to or from it, and it holds no state that only it could act upon.
//! The terms below spell that out, in the order the dashboard states them.

use crate::metrics_helper::{self, Metrics};

use ic_base_types::SubnetId;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    get_member_node_ids_and_ips,
    registry_helper::RegistryHelper,
};
use ic_registry_client_helpers::subnet::SubnetListRegistry;
use slog::{Logger, info, warn};

use std::{
    collections::BTreeMap,
    net::IpAddr,
    thread::sleep,
    time::{Duration, Instant},
};

/// The nodes of every subnet the conditions below range over.
pub type SubnetNodeIps = BTreeMap<SubnetId, Vec<IpAddr>>;

/// The registry version every subnet has to have observed.
const METRIC_REGISTRY_VERSION: &str = "mr_registry_version";
/// The messages held in the streams of a subnet, by remote subnet (the subnet
/// itself included, i.e. its loopback stream).
const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
/// The entries of the ingress history, by status.
const METRIC_INGRESS_HISTORY_BY_STATE: &str = "replicated_state_ingress_history_length_by_state";
/// The messages held in the input and output queues of the subnet itself, i.e.
/// the management canister's.
const METRIC_SUBNET_INPUT_QUEUE_MESSAGES: &str = "execution_subnet_input_queue_messages";
const METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES: &str = "execution_subnet_output_queue_messages";
/// The call contexts of the subnet call context manager, e.g. the `install_code`
/// calls that are still running.
const METRIC_SUBNET_CALL_CONTEXTS: &str = "replicated_state_subnet_call_contexts";
/// The number of pending anonymous refunds, i.e. the size of the refund pool.
const METRIC_PENDING_REFUNDS: &str = "replicated_state_pending_refunds";
/// The total value of those refunds, which is logged next to the term above
/// when the refund pool is not empty, but is not itself a condition.
const METRIC_PENDING_REFUNDS_CYCLES: &str = "replicated_state_pending_refunds_cycles";

/// A term of the readiness condition: what has to hold, and whether it does.
pub struct Term {
    pub description: String,
    pub satisfied: bool,
}

/// Evaluates the terms of the "merge readiness" condition of the `Subnet
/// merging` dashboard for the subnet that is cooling down and the registry
/// version `V` at which it was labeled as such.
///
/// As in the dashboard, every term is evaluated on the median across the
/// replicas reporting the respective series, and missing data reads as zero
/// (the dashboard's `or vector(0)` fallback). The first term is the one that
/// keeps an unreachable subnet from reading as ready: a subnet whose metrics
/// cannot be scraped reports no registry version, i.e. zero, which is below
/// `V`.
pub fn evaluate_merge_readiness(
    subnets: &SubnetNodeIps,
    source_subnet_id: SubnetId,
    registry_version: u64,
    logger: &Logger,
) -> Vec<Term> {
    let own_metrics = subnet_metrics(
        subnets,
        source_subnet_id,
        &[
            METRIC_REGISTRY_VERSION,
            METRIC_STREAM_MESSAGES,
            METRIC_INGRESS_HISTORY_BY_STATE,
            METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
            METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
            METRIC_SUBNET_CALL_CONTEXTS,
            METRIC_PENDING_REFUNDS,
            METRIC_PENDING_REFUNDS_CYCLES,
        ],
        logger,
    );

    // Terms 1 and 2 range over all subnets: the registry version of every
    // subnet and the streams of all remote subnets towards this one.
    let remote_label = format!("remote=\"{source_subnet_id}\"");
    let mut min_registry_version = None;
    let mut incoming_stream_messages = 0.0;
    for &subnet_id in subnets.keys() {
        let metrics = if subnet_id == source_subnet_id {
            own_metrics.clone()
        } else {
            subnet_metrics(
                subnets,
                subnet_id,
                &[METRIC_REGISTRY_VERSION, METRIC_STREAM_MESSAGES],
                logger,
            )
        };
        let version =
            metrics_helper::median_across_replicas(&metrics, METRIC_REGISTRY_VERSION, |_| true)
                .unwrap_or(0.0);
        min_registry_version = Some(min_registry_version.map_or(version, |v: f64| v.min(version)));
        if subnet_id != source_subnet_id {
            incoming_stream_messages +=
                metrics_helper::sum_of_medians(&metrics, METRIC_STREAM_MESSAGES, |labels| {
                    labels.contains(&remote_label)
                });
        }
    }
    let min_registry_version = min_registry_version.unwrap_or(0.0);

    let outgoing_stream_messages =
        metrics_helper::sum_of_medians(&own_metrics, METRIC_STREAM_MESSAGES, |_| true);
    let ingress_history_messages =
        metrics_helper::sum_of_medians(&own_metrics, METRIC_INGRESS_HISTORY_BY_STATE, |labels| {
            !labels.contains("state=\"processing\"")
        });
    let subnet_input_queue_messages =
        metrics_helper::sum_of_medians(&own_metrics, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, |_| true);
    let subnet_output_queue_messages = metrics_helper::median_across_replicas(
        &own_metrics,
        METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
        |_| true,
    )
    .unwrap_or(0.0);
    let subnet_call_contexts =
        metrics_helper::sum_of_medians(&own_metrics, METRIC_SUBNET_CALL_CONTEXTS, |_| true);
    let pending_refunds =
        metrics_helper::median_across_replicas(&own_metrics, METRIC_PENDING_REFUNDS, |_| true)
            .unwrap_or(0.0);
    let pending_refunds_cycles =
        metrics_helper::median_across_replicas(&own_metrics, METRIC_PENDING_REFUNDS_CYCLES, |_| {
            true
        })
        .unwrap_or(0.0);

    let term = |description: String, satisfied: bool| Term {
        description,
        satisfied,
    };
    vec![
        term(
            format!(
                "every subnet has reached registry version {registry_version} (the lowest one is \
                 at {min_registry_version})"
            ),
            min_registry_version >= registry_version as f64,
        ),
        term(
            format!(
                "no remote subnet holds a message in its stream to subnet {source_subnet_id} \
                 ({incoming_stream_messages} messages)"
            ),
            incoming_stream_messages == 0.0,
        ),
        term(
            format!(
                "subnet {source_subnet_id} holds no message in any of its streams, loopback \
                 included ({outgoing_stream_messages} messages)"
            ),
            outgoing_stream_messages == 0.0,
        ),
        term(
            format!(
                "the ingress history holds nothing but `processing` entries \
                 ({ingress_history_messages} other entries)"
            ),
            ingress_history_messages == 0.0,
        ),
        term(
            format!("the subnet input queues are empty ({subnet_input_queue_messages} messages)"),
            subnet_input_queue_messages == 0.0,
        ),
        term(
            format!("the subnet output queues are empty ({subnet_output_queue_messages} messages)"),
            subnet_output_queue_messages == 0.0,
        ),
        term(
            format!(
                "the subnet call context manager holds no call context ({subnet_call_contexts} \
                 call contexts)"
            ),
            subnet_call_contexts == 0.0,
        ),
        term(
            // A cooling down subnet routes no refunds either (see `route_refunds`
            // in `rs/messaging/src/routing/stream_builder.rs`), so a refund that
            // is in the pool stays pending until the subnet is merged, and is
            // then lost: the merged state takes the refunds of the destination
            // subnet, not those of the subnet that is merged away.
            format!(
                "the refund pool holds no pending anonymous refund ({pending_refunds} refunds, \
                 worth {pending_refunds_cycles} cycles)"
            ),
            pending_refunds == 0.0,
        ),
    ]
}

/// Waits until every term of the readiness condition holds, logging the ones
/// that do not after every round.
pub fn await_merge_readiness(
    registry_helper: &RegistryHelper,
    source_subnet_id: SubnetId,
    registry_version: u64,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
) -> RecoveryResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let terms = evaluate_merge_readiness(
            &subnet_node_ips(registry_helper)?,
            source_subnet_id,
            registry_version,
            logger,
        );
        let unsatisfied: Vec<&Term> = terms.iter().filter(|term| !term.satisfied).collect();

        if unsatisfied.is_empty() {
            info!(
                logger,
                "Subnet {source_subnet_id} is ready to be merged; every term holds:"
            );
            for term in &terms {
                info!(logger, "  [x] {}", term.description);
            }
            return Ok(());
        }

        info!(
            logger,
            "Subnet {source_subnet_id} is not ready to be merged yet, {} of {} terms do not hold:",
            unsatisfied.len(),
            terms.len(),
        );
        for term in &terms {
            let mark = if term.satisfied { "x" } else { " " };
            info!(logger, "  [{mark}] {}", term.description);
        }

        if Instant::now() >= deadline {
            return Err(RecoveryError::UnexpectedError(format!(
                "Subnet {source_subnet_id} did not become ready to be merged within {timeout:?}; \
                 the terms that do not hold: {}",
                unsatisfied
                    .iter()
                    .map(|term| term.description.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            )));
        }
        sleep(poll_interval);
    }
}

/// Waits until every subnet other than `skipped` has reached `registry_version`.
///
/// `skipped` is the subnet that was merged away: its replicas are stopped by
/// the time this runs, so it reports no metrics anymore, and it is about to be
/// deleted. What matters is that every *other* subnet already routes its
/// canisters to the destination subnet.
pub fn await_registry_version_on_all_subnets(
    registry_helper: &RegistryHelper,
    skipped: SubnetId,
    registry_version: u64,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
) -> RecoveryResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut behind = Vec::new();
        let subnets = subnet_node_ips(registry_helper)?;
        for &subnet_id in subnets.keys() {
            if subnet_id == skipped {
                continue;
            }
            let metrics = subnet_metrics(&subnets, subnet_id, &[METRIC_REGISTRY_VERSION], logger);
            let version =
                metrics_helper::median_across_replicas(&metrics, METRIC_REGISTRY_VERSION, |_| true)
                    .unwrap_or(0.0);
            if version < registry_version as f64 {
                behind.push(format!("{subnet_id} is at registry version {version}"));
            }
        }

        if behind.is_empty() {
            info!(
                logger,
                "All subnets other than {skipped} have reached registry version {registry_version}"
            );
            return Ok(());
        }

        info!(
            logger,
            "Waiting until all subnets reached registry version {registry_version}: {}",
            behind.join("; "),
        );

        if Instant::now() >= deadline {
            return Err(RecoveryError::UnexpectedError(format!(
                "Not all subnets reached registry version {registry_version} within {timeout:?}: \
                 {}",
                behind.join("; "),
            )));
        }
        sleep(poll_interval);
    }
}

/// The nodes of every subnet in the registry.
pub fn subnet_node_ips(registry_helper: &RegistryHelper) -> RecoveryResult<SubnetNodeIps> {
    let registry_version = registry_helper.latest_registry_version()?;
    let subnet_ids = registry_helper
        .registry_client()
        .get_subnet_ids(registry_version)
        .map_err(|err| {
            RecoveryError::RegistryError(format!(
                "Failed to get the subnet ids at registry version {registry_version}: {err}"
            ))
        })?
        .ok_or_else(|| {
            RecoveryError::RegistryError(format!(
                "No subnet ids at registry version {registry_version}"
            ))
        })?;

    subnet_ids
        .into_iter()
        .map(|subnet_id| {
            let node_ips = get_member_node_ids_and_ips(registry_helper, subnet_id)?
                .into_values()
                .collect();
            Ok((subnet_id, node_ips))
        })
        .collect()
}

/// Fetches the given metrics from all nodes of `subnet_id`.
fn subnet_metrics(
    subnets: &SubnetNodeIps,
    subnet_id: SubnetId,
    metrics: &[&str],
    logger: &Logger,
) -> Metrics {
    let node_ips = match subnets.get(&subnet_id) {
        Some(node_ips) if !node_ips.is_empty() => node_ips.as_slice(),
        _ => {
            warn!(logger, "Subnet {subnet_id} has no node to scrape");
            &[]
        }
    };

    metrics_helper::fetch_metrics(logger, node_ips, metrics)
}
