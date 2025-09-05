use ic_interfaces::{ingress_pool::UnvalidatedIngressArtifact, time_source::TimeSource};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{CountBytes, NodeId};
use ic_validator::RequestValidationError;
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGauge};

use crate::ingress_handler::IngressMessageValidationError;

const SOURCE_LABEL: &str = "source";

/// Keeps the metrics to be exported by the IngressManager
pub(crate) struct IngressManagerMetrics {
    node_id: NodeId,

    pub(crate) ingress_handler_time: Histogram,
    pub(crate) ingress_selector_get_payload_time: Histogram,
    pub(crate) ingress_selector_validate_payload_time: Histogram,
    pub(crate) ingress_payload_cache_size: IntGauge,

    validated_ingress_message_size: HistogramVec,
    validated_ingress_message_field_size: HistogramVec,
    validated_ingress_message_time: HistogramVec,

    pub(crate) invalidated_ingress_message_count: IntCounterVec,
}

impl IngressManagerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry, node_id: NodeId) -> Self {
        Self {
            node_id,
            ingress_handler_time: metrics_registry.histogram(
                "ingress_handler_execution_time",
                "Ingress Handler execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_get_payload_time: metrics_registry.histogram(
                "ingress_selector_get_payload_time",
                "Ingress Selector get_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_selector_validate_payload_time: metrics_registry.histogram(
                "ingress_selector_validate_payload_time",
                "Ingress Selector validate_payload execution time in seconds",
                decimal_buckets(-3, 1),
            ),
            ingress_payload_cache_size: metrics_registry.int_gauge(
                "ingress_payload_cache_size",
                "The number of HashSets in payload builder's ingress payload cache.",
            ),
            validated_ingress_message_size: metrics_registry.histogram_vec(
                "ingress_handler_validated_ingress_message_size",
                "The size of validated ingress message, in bytes",
                decimal_buckets(0, 6),
                &[SOURCE_LABEL],
            ),
            validated_ingress_message_field_size: metrics_registry.histogram_vec(
                "ingress_handler_validated_ingress_message_field_size",
                "The size of a given field (e.g. argument, method name, etc) of \
                the ingress message, in bytes",
                decimal_buckets(0, 6),
                &[SOURCE_LABEL, "part"],
            ),
            validated_ingress_message_time: metrics_registry.histogram_vec(
                "ingress_handler_validated_ingress_message_time",
                "How long, in seconds, the ingress message was in the pool before \
                it was validated",
                decimal_buckets(-4, 0),
                &[SOURCE_LABEL],
            ),
            invalidated_ingress_message_count: metrics_registry.int_counter_vec(
                "ingress_handler_invalidated_ingress_message_count",
                "The number of invalidated ingress messages, partitioned by the reason",
                &[SOURCE_LABEL, "reason"],
            ),
        }
    }

    pub(crate) fn observe_validated_ingress_message(
        &self,
        time_source: &dyn TimeSource,
        ingress: &UnvalidatedIngressArtifact,
    ) {
        let source_label = self.source_label(ingress);

        self.validated_ingress_message_time
            .with_label_values(&[source_label])
            .observe(
                time_source
                    .get_relative_time()
                    .saturating_duration_since(ingress.timestamp)
                    .as_secs_f64(),
            );

        let signed_ingress = &ingress.message.signed_ingress;
        self.validated_ingress_message_size
            .with_label_values(&[source_label])
            .observe(signed_ingress.count_bytes() as f64);

        let arg_size = signed_ingress.content().arg().len();
        let method_name_size = signed_ingress.content().method_name().len();
        let nonce_size = signed_ingress
            .content()
            .nonce()
            .map(Vec::len)
            .unwrap_or_default();
        let everything_else_size =
            signed_ingress.count_bytes() - arg_size - method_name_size - nonce_size;

        self.validated_ingress_message_field_size
            .with_label_values(&[source_label, "arg"])
            .observe(arg_size as f64);
        self.validated_ingress_message_field_size
            .with_label_values(&[source_label, "method_name"])
            .observe(method_name_size as f64);
        self.validated_ingress_message_field_size
            .with_label_values(&[source_label, "nonce"])
            .observe(nonce_size as f64);
        self.validated_ingress_message_field_size
            .with_label_values(&[source_label, "remainder"])
            .observe(everything_else_size as f64);
    }

    pub(crate) fn observe_invalidated_ingress_message(
        &self,
        ingress: &UnvalidatedIngressArtifact,
        err: IngressMessageValidationError,
    ) {
        let source_label = self.source_label(ingress);

        let reason_label = match err {
            IngressMessageValidationError::IngressMessageTooLarge { .. } => {
                "ingress_message_too_large"
            }
            IngressMessageValidationError::IngressMessageAlreadyKnown => {
                "ingress_message_already_known"
            }
            IngressMessageValidationError::InvalidRequest(
                RequestValidationError::InvalidRequestExpiry(_),
            ) => "invalid_request_expiry",
            IngressMessageValidationError::InvalidRequest(
                RequestValidationError::InvalidSignature(_),
            ) => "invalid_request_signature",
            IngressMessageValidationError::InvalidRequest(_) => "invalid_request_other",
        };

        self.invalidated_ingress_message_count
            .with_label_values(&[source_label, reason_label])
            .inc();
    }

    fn source_label(&self, ingress: &UnvalidatedIngressArtifact) -> &str {
        if ingress.message.originator_id == self.node_id {
            "boundary_node"
        } else {
            "peer"
        }
    }
}
