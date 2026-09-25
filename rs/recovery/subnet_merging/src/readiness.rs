//! The "merge readiness" condition, evaluated from the metrics of the
//! replicas.
//!
//! A subnet that is cooling down is ready to be merged once it has come to a
//! complete rest: every subnet has observed that it is cooling down, nothing is
//! in flight to or from it, and it holds no state that only it could act upon.
//! The terms below spell that out, one per `Condition`.

use crate::metrics_helper::{self, Metrics};

use ic_base_types::SubnetId;
use slog::{Logger, warn};

use std::{collections::BTreeMap, net::IpAddr};

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
/// The total value of those refunds, which is logged next to the term above
/// when the refund pool is not empty, but is not itself a condition.
pub const METRIC_PENDING_REFUNDS_CYCLES: &str = "replicated_state_pending_refunds_cycles";

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

/// Evaluates the terms of the "merge readiness" condition for the subnet that
/// is cooling down and the registry version `V` at which it was labeled as
/// such. Returns one term per condition.
///
/// Every term is evaluated on the median across the replicas reporting the
/// respective series, and missing data reads as zero. The first term is the one
/// that keeps an unreachable subnet from reading as ready: a subnet whose
/// metrics cannot be scraped reports no registry version, i.e. zero, which is
/// below `V`.
pub async fn evaluate_merge_readiness(
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
    )
    .await;

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
            .await
        };
        let version =
            metrics_helper::median_across_replicas(&metrics, METRIC_REGISTRY_VERSION, |_| true)
                .unwrap_or(0.0);
        min_registry_version = Some(min_registry_version.map_or(version, |v: f64| v.min(version)));
        if subnet_id != source_subnet_id {
            incoming_stream_messages += metrics_helper::median_across_replicas(
                &metrics,
                METRIC_STREAM_MESSAGES,
                |labels| labels.contains(&remote_label),
            )
            .unwrap_or(0.0);
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

    let term = |condition, description: String, satisfied: bool| Term {
        condition,
        description,
        satisfied,
    };
    vec![
        term(
            Condition::RegistryVersion,
            format!(
                "every subnet has reached registry version {registry_version} (the lowest one is \
                 at {min_registry_version})"
            ),
            min_registry_version >= registry_version as f64,
        ),
        term(
            Condition::IncomingStreams,
            format!(
                "no remote subnet holds a message in its stream to subnet {source_subnet_id} \
                 ({incoming_stream_messages} messages)"
            ),
            incoming_stream_messages == 0.0,
        ),
        term(
            Condition::OutgoingStreams,
            format!(
                "subnet {source_subnet_id} holds no message in any of its streams, loopback \
                 included ({outgoing_stream_messages} messages)"
            ),
            outgoing_stream_messages == 0.0,
        ),
        term(
            Condition::IngressHistory,
            format!(
                "the ingress history holds nothing but `processing` entries \
                 ({ingress_history_messages} other entries)"
            ),
            ingress_history_messages == 0.0,
        ),
        term(
            Condition::SubnetInputQueues,
            format!("the subnet input queues are empty ({subnet_input_queue_messages} messages)"),
            subnet_input_queue_messages == 0.0,
        ),
        term(
            Condition::SubnetOutputQueues,
            format!("the subnet output queues are empty ({subnet_output_queue_messages} messages)"),
            subnet_output_queue_messages == 0.0,
        ),
        term(
            Condition::SubnetCallContexts,
            format!(
                "the subnet call context manager holds no call context ({subnet_call_contexts} \
                 call contexts)"
            ),
            subnet_call_contexts == 0.0,
        ),
        term(
            Condition::RefundPool,
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

/// Fetches the given metrics from all nodes of `subnet_id`.
async fn subnet_metrics(
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

    metrics_helper::fetch_metrics(logger, node_ips, metrics).await
}
