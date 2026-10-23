//! The "merge readiness" condition, evaluated from the metrics of the
//! replicas.
//!
//! For the subnet `S` that is cooling down and a registry version `V` at which
//! it is labeled as such, the condition holds iff all of the following
//! terms hold. A term holds on a subnet iff a quorum of its replicas (see
//! `quorum`) satisfies it. A replica that cannot be scraped satisfies no term.
//!
//! 1. `RegistryVersion`: a replica of any subnet satisfies it iff it reports
//!    `mr_registry_version >= V`.
//! 2. `IncomingStreams`: a replica of any other subnet satisfies it iff it
//!    reports no `mr_stream_messages{remote="S"} > 0`.
//! 3. `OutgoingStreams`: a replica of `S` satisfies it iff it reports no
//!    `mr_stream_messages > 0` for any remote subnet, `S` itself included.
//! 4. `IngressHistory`: a replica of `S` satisfies it iff it reports no
//!    `replicated_state_ingress_history_length_by_state > 0` for any state
//!    other than `processing`.
//! 5. `SubnetInputQueues`: a replica of `S` satisfies it iff it reports no
//!    `execution_subnet_input_queue_messages > 0` for any kind.
//! 6. `SubnetOutputQueues`: a replica of `S` satisfies it iff it reports no
//!    `execution_subnet_output_queue_messages > 0`.
//! 7. `SubnetCallContexts`: a replica of `S` satisfies it iff it reports no
//!    `replicated_state_subnet_call_contexts > 0` for any type.
//! 8. `RefundPool`: a replica of `S` satisfies it iff it reports no
//!    `replicated_state_pending_refunds > 0`.
//! 9. `CommonQuorum`: a replica of any subnet satisfies it iff it satisfies
//!    all of the above terms that apply to its subnet. Hence, it holds iff on
//!    every subnet a single quorum of the replicas satisfies all of these terms
//!    at once, as opposed to each term holding on a possibly different quorum.

use crate::metrics_helper::{self, Labels, MetricsByReplica, ReplicaMetrics, ScrapeError};

use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
    util::block_on,
};
use ic_registry_client_helpers::{
    node::NodeRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_types::consensus::get_faults_tolerated;
use slog::{Logger, info, warn};
use strum_macros::EnumIter;

use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    thread::sleep,
    time::{Duration, Instant},
};

/// The nodes of every subnet the conditions below range over.
pub type SubnetNodeIps = BTreeMap<SubnetId, Vec<IpAddr>>;

/// The registry version every subnet has to have observed.
pub const METRIC_REGISTRY_VERSION: &str = "mr_registry_version";
/// The messages held in the streams of a subnet, by remote subnet (the subnet
/// itself included, i.e. its loopback stream).
pub const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
/// The entries of the ingress history, by status.
pub const METRIC_INGRESS_HISTORY_BY_STATE: &str =
    "replicated_state_ingress_history_length_by_state";
/// The messages held in the input and output queues of the subnet itself, i.e.
/// the management canister's.
pub const METRIC_SUBNET_INPUT_QUEUE_MESSAGES: &str = "execution_subnet_input_queue_messages";
pub const METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES: &str = "execution_subnet_output_queue_messages";
/// The call contexts of the subnet call context manager, e.g. the `install_code`
/// calls that are still running.
pub const METRIC_SUBNET_CALL_CONTEXTS: &str = "replicated_state_subnet_call_contexts";
/// The number of pending anonymous refunds, i.e. the size of the refund pool.
pub const METRIC_PENDING_REFUNDS: &str = "replicated_state_pending_refunds";

/// The individual conditions the "merge readiness" condition is made of.
#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq)]
pub enum Condition {
    RegistryVersion,
    IncomingStreams,
    OutgoingStreams,
    IngressHistory,
    SubnetInputQueues,
    SubnetOutputQueues,
    SubnetCallContexts,
    RefundPool,
    CommonQuorum,
}

/// A term of the readiness condition: which condition it states, what has to
/// hold for it, and whether that does hold.
pub struct Term {
    pub condition: Condition,
    pub description: String,
    pub satisfied: bool,
}

/// The number of the `n` replicas of a subnet that have to satisfy a term for
/// it to hold on that subnet: all but the faulty ones that a subnet of `n`
/// replicas tolerates.
pub fn quorum(n: usize) -> usize {
    n - get_faults_tolerated(n)
}

/// The evaluated terms of the readiness condition, along with the nodes that
/// could not be scraped, by subnet.
pub struct Readiness {
    pub terms: Vec<Term>,
    pub scrape_failures: Vec<(SubnetId, ScrapeError)>,
}

/// Why the readiness condition could not be evaluated.
#[derive(Debug)]
pub enum ReadinessError {
    /// `subnets` does not list the subnet that is cooling down.
    UnknownSubnet(SubnetId),
    /// `subnets` lists no node for the subnet.
    NoNodes(SubnetId),
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSubnet(subnet_id) => write!(f, "subnet {subnet_id} is not listed"),
            Self::NoNodes(subnet_id) => write!(f, "subnet {subnet_id} has no node to scrape"),
        }
    }
}

impl std::error::Error for ReadinessError {}

/// Evaluates the terms of the "merge readiness" condition for the subnet that
/// is cooling down and a registry version `V` at which it is labeled as such.
/// Returns one term per condition: readiness holds iff every term is satisfied.
/// Nodes that cannot be scraped do not fail the evaluation, but are returned
/// along with the terms.
pub async fn evaluate_merge_readiness(
    subnets: &SubnetNodeIps,
    source_subnet_id: SubnetId,
    registry_version: u64,
) -> Result<Readiness, ReadinessError> {
    let (metrics, scrape_failures) = fetch_readiness_metrics(subnets, source_subnet_id).await?;
    Ok(Readiness {
        terms: evaluate(subnets, &metrics, source_subnet_id, registry_version),
        scrape_failures,
    })
}

/// The metrics of the replicas that could be scraped, by subnet, along with the
/// nodes that could not be scraped, by subnet.
type FetchedMetrics = (
    BTreeMap<SubnetId, MetricsByReplica>,
    Vec<(SubnetId, ScrapeError)>,
);

/// Fetches the metrics the terms are evaluated on: all of them from the subnet
/// that is cooling down, and those of terms 1 and 2 from every other subnet.
/// Fails if `subnets` does not list the cooling down subnet, or lists no node
/// for a subnet.
async fn fetch_readiness_metrics(
    subnets: &SubnetNodeIps,
    source_subnet_id: SubnetId,
) -> Result<FetchedMetrics, ReadinessError> {
    if !subnets.contains_key(&source_subnet_id) {
        return Err(ReadinessError::UnknownSubnet(source_subnet_id));
    }
    if let Some((&subnet_id, _)) = subnets.iter().find(|(_, node_ips)| node_ips.is_empty()) {
        return Err(ReadinessError::NoNodes(subnet_id));
    }
    let mut result = BTreeMap::new();
    let mut scrape_failures = Vec::new();
    for (&subnet_id, node_ips) in subnets {
        let metrics: &[&str] = if subnet_id == source_subnet_id {
            &[
                METRIC_REGISTRY_VERSION,
                METRIC_STREAM_MESSAGES,
                METRIC_INGRESS_HISTORY_BY_STATE,
                METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
                METRIC_SUBNET_CALL_CONTEXTS,
                METRIC_PENDING_REFUNDS,
            ]
        } else {
            &[METRIC_REGISTRY_VERSION, METRIC_STREAM_MESSAGES]
        };
        let (metrics, failures) = metrics_helper::fetch_available_metrics(node_ips, metrics).await;
        result.insert(subnet_id, metrics);
        scrape_failures.extend(failures.map(|err| (subnet_id, err)));
    }
    Ok((result, scrape_failures))
}

/// Whether a quorum of the replicas of a subnet, i.e. of `node_ips`, could be
/// scraped and satisfy `satisfies`.
fn holds_on_quorum(
    node_ips: &[IpAddr],
    metrics: &MetricsByReplica,
    satisfies: impl Fn(&ReplicaMetrics) -> bool,
) -> bool {
    let satisfied = node_ips
        .iter()
        .filter_map(|ip| metrics.get(ip))
        .filter(|replica_metrics| satisfies(replica_metrics))
        .count();
    satisfied >= quorum(node_ips.len())
}

/// Whether a replica reports no value above zero for any series of `metric`
/// whose labels match `labels_match`. A replica that does not export any such
/// series, e.g. a counter it never touched, reports no such value.
fn reports_nothing(
    metric: &'static str,
    labels_match: impl Fn(&Labels) -> bool,
) -> impl Fn(&ReplicaMetrics) -> bool {
    move |metrics| {
        metrics_helper::replica_values(metrics, metric, &labels_match).all(|value| value <= 0.0)
    }
}

/// Evaluates the terms on the metrics that `fetch_readiness_metrics` fetched,
/// which hold an entry for every subnet of `subnets`, the cooling down one
/// included.
fn evaluate(
    subnets: &SubnetNodeIps,
    metrics: &BTreeMap<SubnetId, MetricsByReplica>,
    source_subnet_id: SubnetId,
    registry_version: u64,
) -> Vec<Term> {
    let holds_on = |subnet_id: &SubnetId, satisfies: &dyn Fn(&ReplicaMetrics) -> bool| {
        holds_on_quorum(&subnets[subnet_id], &metrics[subnet_id], satisfies)
    };
    let holds_on_source =
        |satisfies: &dyn Fn(&ReplicaMetrics) -> bool| holds_on(&source_subnet_id, satisfies);

    let source_subnet = source_subnet_id.to_string();
    // A replica that reports no registry version has not reached `V`.
    let registry_version_reached_on = |metrics: &ReplicaMetrics| {
        metrics_helper::replica_values(metrics, METRIC_REGISTRY_VERSION, |_| true)
            .reduce(f64::min)
            .is_some_and(|version| version >= registry_version as f64)
    };
    let incoming_streams_empty_on = reports_nothing(METRIC_STREAM_MESSAGES, |labels| {
        labels.get("remote") == Some(&source_subnet)
    });
    let outgoing_streams_empty_on = reports_nothing(METRIC_STREAM_MESSAGES, |_| true);
    let ingress_history_processing_only_on =
        reports_nothing(METRIC_INGRESS_HISTORY_BY_STATE, |labels| {
            labels
                .get("state")
                .is_some_and(|state| state != "processing")
        });
    let subnet_input_queues_empty_on =
        reports_nothing(METRIC_SUBNET_INPUT_QUEUE_MESSAGES, |_| true);
    let subnet_output_queues_empty_on =
        reports_nothing(METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES, |_| true);
    let subnet_call_contexts_empty_on = reports_nothing(METRIC_SUBNET_CALL_CONTEXTS, |_| true);
    let refund_pool_empty_on = reports_nothing(METRIC_PENDING_REFUNDS, |_| true);

    // Keep the individual quorum results for diagnostics. They cannot establish
    // readiness alone: different replicas may satisfy different conditions as
    // a call moves from a subnet queue to a call context and then to a stream.
    let registry_version_reached = subnets
        .keys()
        .all(|subnet_id| holds_on(subnet_id, &registry_version_reached_on));
    let incoming_streams_empty = subnets
        .keys()
        .filter(|&&subnet_id| subnet_id != source_subnet_id)
        .all(|subnet_id| holds_on(subnet_id, &incoming_streams_empty_on));
    let outgoing_streams_empty = holds_on_source(&outgoing_streams_empty_on);
    let ingress_history_processing_only = holds_on_source(&ingress_history_processing_only_on);
    let subnet_input_queues_empty = holds_on_source(&subnet_input_queues_empty_on);
    let subnet_output_queues_empty = holds_on_source(&subnet_output_queues_empty_on);
    let subnet_call_contexts_empty = holds_on_source(&subnet_call_contexts_empty_on);
    let refund_pool_empty = holds_on_source(&refund_pool_empty_on);

    let common_quorum = subnets.keys().all(|subnet_id| {
        holds_on(subnet_id, &|metrics| {
            registry_version_reached_on(metrics)
                && if *subnet_id == source_subnet_id {
                    outgoing_streams_empty_on(metrics)
                        && ingress_history_processing_only_on(metrics)
                        && subnet_input_queues_empty_on(metrics)
                        && subnet_output_queues_empty_on(metrics)
                        && subnet_call_contexts_empty_on(metrics)
                        && refund_pool_empty_on(metrics)
                } else {
                    incoming_streams_empty_on(metrics)
                }
        })
    });

    let term = |condition, description: String, satisfied: bool| Term {
        condition,
        description,
        satisfied,
    };
    vec![
        term(
            Condition::RegistryVersion,
            format!(
                "a quorum of the replicas of every subnet has reached registry version \
                 {registry_version}"
            ),
            registry_version_reached,
        ),
        term(
            Condition::IncomingStreams,
            format!(
                "a quorum of the replicas of every remote subnet holds no message in its stream \
                 to subnet {source_subnet_id}"
            ),
            incoming_streams_empty,
        ),
        term(
            Condition::OutgoingStreams,
            format!(
                "a quorum of the replicas of subnet {source_subnet_id} holds no message in any \
                 of its streams, loopback included"
            ),
            outgoing_streams_empty,
        ),
        term(
            Condition::IngressHistory,
            "the ingress history holds nothing but `processing` entries on a quorum of the \
             replicas"
                .to_string(),
            ingress_history_processing_only,
        ),
        term(
            Condition::SubnetInputQueues,
            "the subnet input queues are empty on a quorum of the replicas".to_string(),
            subnet_input_queues_empty,
        ),
        term(
            Condition::SubnetOutputQueues,
            "the subnet output queues are empty on a quorum of the replicas".to_string(),
            subnet_output_queues_empty,
        ),
        term(
            Condition::SubnetCallContexts,
            "the subnet call context manager holds no call context on a quorum of the replicas"
                .to_string(),
            subnet_call_contexts_empty,
        ),
        term(
            Condition::RefundPool,
            "the refund pool holds no pending anonymous refund on a quorum of the replicas"
                .to_string(),
            refund_pool_empty,
        ),
        term(
            Condition::CommonQuorum,
            "on every subnet, the same quorum of the replicas satisfies all applicable \
             conditions together"
                .to_string(),
            common_quorum,
        ),
    ]
}

/// Waits until every term of the readiness condition holds, logging the ones
/// that do not after every round, along with the nodes that could not be
/// scraped. A round in which the condition cannot be evaluated (e.g. because
/// the registry cannot be read) counts as not ready.
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
        let terms = subnet_node_ips(registry_helper).and_then(|subnets| {
            block_on(evaluate_merge_readiness(
                &subnets,
                source_subnet_id,
                registry_version,
            ))
            .map_err(|err| RecoveryError::UnexpectedError(err.to_string()))
        });
        let not_ready = match terms {
            Ok(Readiness {
                terms,
                scrape_failures,
            }) => {
                for (subnet_id, err) in &scrape_failures {
                    warn!(logger, "Subnet {subnet_id}: {err}");
                }
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
                    "Subnet {source_subnet_id} is not ready to be merged yet, {} of {} terms do \
                     not hold:",
                    unsatisfied.len(),
                    terms.len(),
                );
                for term in &terms {
                    let mark = if term.satisfied { "x" } else { " " };
                    info!(logger, "  [{mark}] {}", term.description);
                }
                format!(
                    "the terms that do not hold: {}",
                    unsatisfied
                        .iter()
                        .map(|term| term.description.clone())
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
            Err(err) => {
                warn!(
                    logger,
                    "Failed to evaluate whether subnet {source_subnet_id} is ready to be merged: \
                     {err}"
                );
                format!("the readiness condition could not be evaluated: {err}")
            }
        };

        if Instant::now() >= deadline {
            return Err(RecoveryError::UnexpectedError(format!(
                "Subnet {source_subnet_id} did not become ready to be merged within {timeout:?}; \
                 {not_ready}"
            )));
        }
        sleep(poll_interval);
    }
}

/// The nodes of every subnet in the registry, all read at the same registry
/// version: the registry is polled once, for the latest version, and every
/// read after that is a local one at that version.
pub fn subnet_node_ips(registry_helper: &RegistryHelper) -> RecoveryResult<SubnetNodeIps> {
    let registry_version = registry_helper.latest_registry_version()?;
    let registry_client = registry_helper.registry_client();
    let registry_error = |what: String| {
        move |err| {
            RecoveryError::RegistryError(format!(
                "Failed to get {what} at registry version {registry_version}: {err}"
            ))
        }
    };
    let missing = |what: String| {
        RecoveryError::RegistryError(format!("No {what} at registry version {registry_version}"))
    };

    let subnet_ids = registry_client
        .get_subnet_ids(registry_version)
        .map_err(registry_error("the subnet ids".to_string()))?
        .ok_or_else(|| missing("subnet ids".to_string()))?;

    subnet_ids
        .into_iter()
        .map(|subnet_id| {
            let node_ids = registry_client
                .get_node_ids_on_subnet(subnet_id, registry_version)
                .map_err(registry_error(format!("the nodes of subnet {subnet_id}")))?
                .ok_or_else(|| missing(format!("nodes of subnet {subnet_id}")))?;
            let node_ips = node_ids
                .into_iter()
                .map(|node_id| node_ip(registry_helper, node_id, registry_version))
                .collect::<RecoveryResult<_>>()?;
            Ok((subnet_id, node_ips))
        })
        .collect()
}

/// The IP address of `node_id` as of `registry_version`.
fn node_ip(
    registry_helper: &RegistryHelper,
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> RecoveryResult<IpAddr> {
    let node_record = registry_helper
        .registry_client()
        .get_node_record(node_id, registry_version)
        .map_err(|err| {
            RecoveryError::RegistryError(format!(
                "Failed to get the record of node {node_id} at registry version \
                 {registry_version}: {err}"
            ))
        })?
        .ok_or_else(|| {
            RecoveryError::RegistryError(format!(
                "No record of node {node_id} at registry version {registry_version}"
            ))
        })?;
    let ip_addr = node_record
        .http
        .ok_or_else(|| {
            RecoveryError::RegistryError(format!(
                "The record of node {node_id} at registry version {registry_version} has no \
                 http endpoint"
            ))
        })?
        .ip_addr;
    ip_addr.parse().map_err(|err| {
        RecoveryError::UnexpectedError(format!(
            "Failed to parse the IP address {ip_addr} of node {node_id}: {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_base_types::PrincipalId;
    use strum::IntoEnumIterator;

    const V: u64 = 10;

    fn subnet(n: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(n))
    }

    fn ip(node: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, node])
    }

    /// The cooling down subnet `S` with nodes 1 to 4, and the remote subnet `R`
    /// with nodes 5 to 8.
    fn s() -> SubnetId {
        subnet(1)
    }
    fn r() -> SubnetId {
        subnet(2)
    }
    const S_NODES: [u8; 4] = [1, 2, 3, 4];
    const R_NODES: [u8; 4] = [5, 6, 7, 8];
    fn subnets() -> SubnetNodeIps {
        SubnetNodeIps::from([
            (s(), S_NODES.map(ip).to_vec()),
            (r(), R_NODES.map(ip).to_vec()),
        ])
    }

    /// Sets the value that `node` of `subnet_id` reports for the series of
    /// `metric` with the given labels.
    fn set(
        metrics: &mut BTreeMap<SubnetId, MetricsByReplica>,
        subnet_id: SubnetId,
        node: u8,
        metric: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) {
        let labels: Labels = labels
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        metrics
            .entry(subnet_id)
            .or_default()
            .entry(ip(node))
            .or_default()
            .insert((metric.to_string(), labels), value);
    }

    /// Makes `node` of `subnet_id` one that could not be scraped.
    fn unscrape(metrics: &mut BTreeMap<SubnetId, MetricsByReplica>, subnet_id: SubnetId, node: u8) {
        metrics.get_mut(&subnet_id).unwrap().remove(&ip(node));
    }

    /// Metrics on which the condition holds: every replica reports registry
    /// version `V`, and empty streams, queues etc.
    fn ready_metrics() -> BTreeMap<SubnetId, MetricsByReplica> {
        let mut metrics = BTreeMap::new();
        let (s_id, r_id) = (s().to_string(), r().to_string());
        for node in S_NODES {
            set(
                &mut metrics,
                s(),
                node,
                METRIC_REGISTRY_VERSION,
                &[],
                V as f64,
            );
            for remote in [&s_id, &r_id] {
                set(
                    &mut metrics,
                    s(),
                    node,
                    METRIC_STREAM_MESSAGES,
                    &[("remote", remote.as_str())],
                    0.0,
                );
            }
            set(
                &mut metrics,
                s(),
                node,
                METRIC_INGRESS_HISTORY_BY_STATE,
                &[("state", "processing")],
                3.0,
            );
            set(
                &mut metrics,
                s(),
                node,
                METRIC_INGRESS_HISTORY_BY_STATE,
                &[("state", "completed")],
                0.0,
            );
            set(
                &mut metrics,
                s(),
                node,
                METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                &[("kind", "request")],
                0.0,
            );
            set(
                &mut metrics,
                s(),
                node,
                METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
                &[],
                0.0,
            );
            set(
                &mut metrics,
                s(),
                node,
                METRIC_SUBNET_CALL_CONTEXTS,
                &[("type", "install_code")],
                0.0,
            );
            set(&mut metrics, s(), node, METRIC_PENDING_REFUNDS, &[], 0.0);
        }
        for node in R_NODES {
            set(
                &mut metrics,
                r(),
                node,
                METRIC_REGISTRY_VERSION,
                &[],
                V as f64 + 1.0,
            );
            for remote in [&s_id, &r_id] {
                set(
                    &mut metrics,
                    r(),
                    node,
                    METRIC_STREAM_MESSAGES,
                    &[("remote", remote.as_str())],
                    0.0,
                );
            }
        }
        metrics
    }

    /// The conditions that do not hold on `metrics`.
    fn violated(metrics: &BTreeMap<SubnetId, MetricsByReplica>) -> Vec<Condition> {
        evaluate(&subnets(), metrics, s(), V)
            .into_iter()
            .filter(|term| !term.satisfied)
            .map(|term| term.condition)
            .collect()
    }

    #[test]
    fn quorum_is_all_but_the_tolerated_faults() {
        assert_eq!(
            (1..=13).map(quorum).collect::<Vec<_>>(),
            vec![1, 2, 3, 3, 4, 5, 5, 6, 7, 7, 8, 9, 9]
        );
        assert_eq!(quorum(15), 11);
    }

    #[test]
    fn holds_when_ready() {
        let terms = evaluate(&subnets(), &ready_metrics(), s(), V);
        assert_eq!(
            terms.iter().map(|term| term.condition).collect::<Vec<_>>(),
            Condition::iter().collect::<Vec<_>>()
        );
        assert!(terms.iter().all(|term| term.satisfied));
    }

    /// A condition, and the value of a series on a subnet that violates that
    /// condition alone on every replica it is set on.
    struct Violation {
        condition: Condition,
        subnet_id: SubnetId,
        metric: &'static str,
        labels: Vec<(&'static str, String)>,
        value: f64,
    }

    impl Violation {
        fn set_on(&self, metrics: &mut BTreeMap<SubnetId, MetricsByReplica>, node: u8) {
            let labels: Vec<(&str, &str)> = self
                .labels
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            set(
                metrics,
                self.subnet_id,
                node,
                self.metric,
                &labels,
                self.value,
            );
        }
    }

    fn violations() -> Vec<Violation> {
        let violation =
            |condition, subnet_id, metric, labels: &[(&'static str, String)], value| Violation {
                condition,
                subnet_id,
                metric,
                labels: labels.to_vec(),
                value,
            };
        let remote_s = [("remote", s().to_string())];
        let remote_r = [("remote", r().to_string())];
        vec![
            violation(
                Condition::RegistryVersion,
                r(),
                METRIC_REGISTRY_VERSION,
                &[],
                V as f64 - 1.0,
            ),
            violation(
                Condition::IncomingStreams,
                r(),
                METRIC_STREAM_MESSAGES,
                &remote_s,
                1.0,
            ),
            violation(
                Condition::OutgoingStreams,
                s(),
                METRIC_STREAM_MESSAGES,
                &remote_r,
                1.0,
            ),
            // The loopback stream of `S` is an outgoing stream, not an incoming one.
            violation(
                Condition::OutgoingStreams,
                s(),
                METRIC_STREAM_MESSAGES,
                &remote_s,
                1.0,
            ),
            violation(
                Condition::IngressHistory,
                s(),
                METRIC_INGRESS_HISTORY_BY_STATE,
                &[("state", "completed".to_string())],
                1.0,
            ),
            violation(
                Condition::SubnetInputQueues,
                s(),
                METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                &[("kind", "response".to_string())],
                1.0,
            ),
            violation(
                Condition::SubnetOutputQueues,
                s(),
                METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
                &[],
                1.0,
            ),
            violation(
                Condition::SubnetCallContexts,
                s(),
                METRIC_SUBNET_CALL_CONTEXTS,
                &[("type", "install_code".to_string())],
                1.0,
            ),
            violation(Condition::RefundPool, s(), METRIC_PENDING_REFUNDS, &[], 1.0),
        ]
    }

    /// The nodes of `subnet_id`.
    fn nodes(subnet_id: SubnetId) -> [u8; 4] {
        if subnet_id == s() { S_NODES } else { R_NODES }
    }

    #[test]
    fn each_condition_is_violated_on_its_own_without_a_quorum() {
        for violation in violations() {
            let Violation {
                condition,
                subnet_id,
                metric,
                labels,
                value,
            } = &violation;
            // Two of four replicas, i.e. more than the one faulty replica tolerated.
            for violating in [[0, 1], [1, 3], [2, 3]] {
                let mut metrics = ready_metrics();
                for i in violating {
                    violation.set_on(&mut metrics, nodes(*subnet_id)[i]);
                }
                assert_eq!(
                    violated(&metrics),
                    vec![*condition, Condition::CommonQuorum],
                    "{metric}{labels:?} = {value} on replicas {violating:?} of {subnet_id}"
                );
            }
        }
    }

    #[test]
    fn a_faulty_replica_does_not_violate_a_condition() {
        for violation in violations() {
            let Violation {
                subnet_id,
                metric,
                labels,
                value,
                ..
            } = &violation;
            // One of four replicas, i.e. as many as the faulty replicas tolerated.
            for node in nodes(*subnet_id) {
                let mut metrics = ready_metrics();
                violation.set_on(&mut metrics, node);
                assert_eq!(
                    violated(&metrics),
                    vec![],
                    "{metric}{labels:?} = {value} on node {node} of {subnet_id}"
                );
            }
        }
    }

    #[test]
    fn replicas_violating_different_conditions_do_not_form_a_common_quorum() {
        // Each individual condition has a quorum, but only two replicas of
        // `S` satisfy every applicable condition together.
        let mut metrics = ready_metrics();
        set(&mut metrics, s(), 1, METRIC_PENDING_REFUNDS, &[], 1.0);
        set(
            &mut metrics,
            s(),
            2,
            METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
            &[],
            1.0,
        );
        assert_eq!(violated(&metrics), vec![Condition::CommonQuorum]);
    }

    #[test]
    fn successive_call_stages_do_not_establish_readiness() {
        let mut metrics = ready_metrics();
        // Three honest replicas observe successive stages: before cooling,
        // executing a management call, and holding its undelivered response.
        // The fourth replica falsely reports that every condition holds.
        set(
            &mut metrics,
            s(),
            1,
            METRIC_REGISTRY_VERSION,
            &[],
            V as f64 - 1.0,
        );
        set(
            &mut metrics,
            s(),
            2,
            METRIC_SUBNET_CALL_CONTEXTS,
            &[("type", "install_code")],
            1.0,
        );
        set(
            &mut metrics,
            s(),
            3,
            METRIC_STREAM_MESSAGES,
            &[("remote", r().to_string().as_str())],
            1.0,
        );
        assert_eq!(violated(&metrics), vec![Condition::CommonQuorum]);
    }

    #[test]
    fn remote_registry_and_stream_conditions_need_the_same_quorum() {
        let mut metrics = ready_metrics();
        set(
            &mut metrics,
            r(),
            5,
            METRIC_REGISTRY_VERSION,
            &[],
            V as f64 - 1.0,
        );
        set(
            &mut metrics,
            r(),
            6,
            METRIC_STREAM_MESSAGES,
            &[("remote", s().to_string().as_str())],
            1.0,
        );
        assert_eq!(violated(&metrics), vec![Condition::CommonQuorum]);
    }

    #[test]
    fn one_replica_per_subnet_may_violate_all_applicable_conditions() {
        let mut metrics = ready_metrics();
        for violation in violations() {
            violation.set_on(&mut metrics, nodes(violation.subnet_id)[0]);
        }
        // The quorum is shared within each subnet, independently of which
        // replica fails on another subnet.
        set(
            &mut metrics,
            s(),
            1,
            METRIC_REGISTRY_VERSION,
            &[],
            V as f64 - 1.0,
        );
        assert_eq!(violated(&metrics), vec![]);
    }

    #[test]
    fn unscraped_replicas_satisfy_no_condition() {
        // One unscraped replica per subnet is tolerated.
        let mut metrics = ready_metrics();
        unscrape(&mut metrics, s(), 1);
        unscrape(&mut metrics, r(), 5);
        assert_eq!(violated(&metrics), vec![]);

        // Together with a second replica that violates a condition, it is not.
        set(&mut metrics, s(), 2, METRIC_PENDING_REFUNDS, &[], 1.0);
        assert_eq!(
            violated(&metrics),
            vec![Condition::RefundPool, Condition::CommonQuorum]
        );

        // Two unscraped replicas of `S` violate every condition on `S`, even
        // though they report nothing that would violate them.
        let mut metrics = ready_metrics();
        unscrape(&mut metrics, s(), 1);
        unscrape(&mut metrics, s(), 4);
        assert_eq!(
            violated(&metrics),
            vec![
                Condition::RegistryVersion,
                Condition::OutgoingStreams,
                Condition::IngressHistory,
                Condition::SubnetInputQueues,
                Condition::SubnetOutputQueues,
                Condition::SubnetCallContexts,
                Condition::RefundPool,
                Condition::CommonQuorum,
            ]
        );

        // Two unscraped replicas of `R` violate the conditions on `R`.
        let mut metrics = ready_metrics();
        unscrape(&mut metrics, r(), 6);
        unscrape(&mut metrics, r(), 7);
        assert_eq!(
            violated(&metrics),
            vec![
                Condition::RegistryVersion,
                Condition::IncomingStreams,
                Condition::CommonQuorum
            ]
        );
    }

    #[test]
    fn irrelevant_series_do_not_violate_the_condition() {
        let mut metrics = ready_metrics();
        for node in R_NODES {
            // Streams of `R` to subnets other than `S`.
            set(
                &mut metrics,
                r(),
                node,
                METRIC_STREAM_MESSAGES,
                &[("remote", r().to_string().as_str())],
                5.0,
            );
            set(
                &mut metrics,
                r(),
                node,
                METRIC_STREAM_MESSAGES,
                &[("remote", subnet(3).to_string().as_str())],
                5.0,
            );
            // Replicas of `R` that report a higher registry version.
            set(
                &mut metrics,
                r(),
                node,
                METRIC_REGISTRY_VERSION,
                &[],
                V as f64 + 5.0,
            );
        }
        for node in S_NODES {
            // `processing` entries of the ingress history.
            set(
                &mut metrics,
                s(),
                node,
                METRIC_INGRESS_HISTORY_BY_STATE,
                &[("state", "processing")],
                7.0,
            );
        }
        assert_eq!(violated(&metrics), vec![]);
    }

    #[test]
    fn registry_version_requires_replicas_to_report() {
        for subnet_id in [s(), r()] {
            let mut metrics = ready_metrics();
            // Two of the replicas of the subnet report no registry version,
            // the other two still do.
            for node in &nodes(subnet_id)[..2] {
                metrics
                    .get_mut(&subnet_id)
                    .unwrap()
                    .get_mut(&ip(*node))
                    .unwrap()
                    .retain(|(name, _), _| name != METRIC_REGISTRY_VERSION);
            }
            assert_eq!(
                violated(&metrics),
                vec![Condition::RegistryVersion, Condition::CommonQuorum],
                "two replicas of {subnet_id} report no registry version"
            );
        }
    }

    #[test]
    fn fails_if_a_subnet_is_unknown_or_has_no_nodes() {
        let evaluate = |subnets: SubnetNodeIps| {
            futures::executor::block_on(evaluate_merge_readiness(&subnets, s(), V))
        };

        let mut without_s = subnets();
        without_s.remove(&s());
        assert!(matches!(evaluate(without_s), Err(ReadinessError::UnknownSubnet(id)) if id == s()));

        let mut s_without_nodes = subnets();
        s_without_nodes.insert(s(), vec![]);
        assert!(matches!(evaluate(s_without_nodes), Err(ReadinessError::NoNodes(id)) if id == s()));

        let mut r_without_nodes = subnets();
        r_without_nodes.insert(r(), vec![]);
        assert!(matches!(evaluate(r_without_nodes), Err(ReadinessError::NoNodes(id)) if id == r()));
    }
}
