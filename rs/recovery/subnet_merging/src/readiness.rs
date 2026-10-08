//! The "merge readiness" condition, evaluated from the metrics of the
//! replicas.
//!
//! For the subnet `S` that is cooling down and the registry version `V` at
//! which it was labeled as such, the condition holds iff all of the following
//! terms, one per `Condition`, hold:
//!
//! 1. `RegistryVersion`: every replica of every subnet reports
//!    `mr_registry_version >= V`.
//! 2. `IncomingStreams`: no replica of any other subnet reports
//!    `mr_stream_messages{remote="S"} > 0`.
//! 3. `OutgoingStreams`: no replica of `S` reports `mr_stream_messages > 0`
//!    for any remote subnet, `S` itself included.
//! 4. `IngressHistory`: no replica of `S` reports
//!    `replicated_state_ingress_history_length_by_state > 0` for any state
//!    other than `processing`.
//! 5. `SubnetInputQueues`: no replica of `S` reports
//!    `execution_subnet_input_queue_messages > 0` for any kind.
//! 6. `SubnetOutputQueues`: no replica of `S` reports
//!    `execution_subnet_output_queue_messages > 0`.
//! 7. `SubnetCallContexts`: no replica of `S` reports
//!    `replicated_state_subnet_call_contexts > 0` for any type.
//! 8. `RefundPool`: no replica of `S` reports
//!    `replicated_state_pending_refunds > 0`.

use crate::metrics_helper::{self, Metrics, ScrapeError};

use ic_base_types::SubnetId;

use std::{collections::BTreeMap, fmt, net::IpAddr};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    RegistryVersion,
    IncomingStreams,
    OutgoingStreams,
    IngressHistory,
    SubnetInputQueues,
    SubnetOutputQueues,
    SubnetCallContexts,
    RefundPool,
}

/// A term of the readiness condition: which condition it states, what has to
/// hold for it, and whether that does hold.
pub struct Term {
    pub condition: Condition,
    pub description: String,
    pub satisfied: bool,
}

/// Why the readiness condition could not be evaluated.
#[derive(Debug)]
pub enum ReadinessError {
    /// `subnets` lists no node for the subnet.
    NoNodes(SubnetId),
    /// A node of the subnet could not be scraped.
    Scrape(SubnetId, ScrapeError),
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNodes(subnet_id) => write!(f, "subnet {subnet_id} has no node to scrape"),
            Self::Scrape(subnet_id, err) => write!(f, "subnet {subnet_id}: {err}"),
        }
    }
}

impl std::error::Error for ReadinessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoNodes(_) => None,
            Self::Scrape(_, err) => Some(err),
        }
    }
}

/// Evaluates the terms of the "merge readiness" condition for the subnet that
/// is cooling down and the registry version `V` at which it was labeled as
/// such. Returns one term per condition.
///
/// Every term has to hold on every single replica: the registry version is the
/// minimum across all replicas, and every other term is the maximum across all
/// replicas.
/// Fails if any node of any subnet (the cooling down one included) cannot be
/// scraped, rather than evaluating the terms on partial data: most terms
/// compare against zero, which missing data would satisfy.
pub async fn evaluate_merge_readiness(
    subnets: &SubnetNodeIps,
    source_subnet_id: SubnetId,
    registry_version: u64,
) -> Result<Vec<Term>, ReadinessError> {
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
        ],
    )
    .await?;

    // Terms 1 and 2 range over all subnets: the registry version of every
    // replica of every subnet and the streams of all remote subnets towards
    // this one.
    let source_subnet = source_subnet_id.to_string();
    let mut min_registry_version = None;
    let mut incoming_stream_messages = 0.0;
    for (&subnet_id, node_ips) in subnets {
        let metrics = if subnet_id == source_subnet_id {
            own_metrics.clone()
        } else {
            subnet_metrics(
                subnets,
                subnet_id,
                &[METRIC_REGISTRY_VERSION, METRIC_STREAM_MESSAGES],
            )
            .await?
        };
        let version = metrics_helper::min_across_replicas(
            &metrics,
            METRIC_REGISTRY_VERSION,
            |_| true,
            node_ips,
        );
        min_registry_version = Some(min_registry_version.map_or(version, |v: f64| v.min(version)));
        if subnet_id != source_subnet_id {
            incoming_stream_messages +=
                metrics_helper::max_across_replicas(&metrics, METRIC_STREAM_MESSAGES, |labels| {
                    labels.get("remote") == Some(&source_subnet)
                });
        }
    }
    let min_registry_version = min_registry_version.unwrap_or(0.0);

    let outgoing_stream_messages =
        metrics_helper::max_across_replicas(&own_metrics, METRIC_STREAM_MESSAGES, |_| true);
    let ingress_history_messages = metrics_helper::max_across_replicas(
        &own_metrics,
        METRIC_INGRESS_HISTORY_BY_STATE,
        |labels| {
            labels
                .get("state")
                .is_some_and(|state| state != "processing")
        },
    );
    let subnet_input_queue_messages = metrics_helper::max_across_replicas(
        &own_metrics,
        METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
        |_| true,
    );
    let subnet_output_queue_messages = metrics_helper::max_across_replicas(
        &own_metrics,
        METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
        |_| true,
    );
    let subnet_call_contexts =
        metrics_helper::max_across_replicas(&own_metrics, METRIC_SUBNET_CALL_CONTEXTS, |_| true);
    let pending_refunds =
        metrics_helper::max_across_replicas(&own_metrics, METRIC_PENDING_REFUNDS, |_| true);

    let term = |condition, description: String, satisfied: bool| Term {
        condition,
        description,
        satisfied,
    };
    Ok(vec![
        term(
            Condition::RegistryVersion,
            format!(
                "every replica of every subnet has reached registry version {registry_version}"
            ),
            min_registry_version >= registry_version as f64,
        ),
        term(
            Condition::IncomingStreams,
            format!("no remote subnet holds a message in its stream to subnet {source_subnet_id}"),
            incoming_stream_messages == 0.0,
        ),
        term(
            Condition::OutgoingStreams,
            format!(
                "subnet {source_subnet_id} holds no message in any of its streams, loopback included"
            ),
            outgoing_stream_messages == 0.0,
        ),
        term(
            Condition::IngressHistory,
            "the ingress history holds nothing but `processing` entries".to_string(),
            ingress_history_messages == 0.0,
        ),
        term(
            Condition::SubnetInputQueues,
            "the subnet input queues are empty".to_string(),
            subnet_input_queue_messages == 0.0,
        ),
        term(
            Condition::SubnetOutputQueues,
            "the subnet output queues are empty".to_string(),
            subnet_output_queue_messages == 0.0,
        ),
        term(
            Condition::SubnetCallContexts,
            "the subnet call context manager holds no call context".to_string(),
            subnet_call_contexts == 0.0,
        ),
        term(
            Condition::RefundPool,
            "the refund pool holds no pending anonymous refund".to_string(),
            pending_refunds == 0.0,
        ),
    ])
}

/// Fetches the given metrics from all nodes of `subnet_id`.
async fn subnet_metrics(
    subnets: &SubnetNodeIps,
    subnet_id: SubnetId,
    metrics: &[&str],
) -> Result<Metrics, ReadinessError> {
    let node_ips = match subnets.get(&subnet_id) {
        Some(node_ips) if !node_ips.is_empty() => node_ips.as_slice(),
        _ => return Err(ReadinessError::NoNodes(subnet_id)),
    };

    metrics_helper::fetch_metrics(node_ips, metrics)
        .await
        .map_err(|err| ReadinessError::Scrape(subnet_id, err))
}
