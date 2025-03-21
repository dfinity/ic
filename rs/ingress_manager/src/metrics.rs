use ic_interfaces::{ingress_pool::UnvalidatedIngressArtifact, time_source::TimeSource};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::CountBytes;
use prometheus::{Histogram, IntCounterVec, IntGauge};
use serde::ser::Serialize;

/// Keeps the metrics to be exported by the IngressManager
pub(crate) struct IngressManagerMetrics {
    pub(crate) ingress_handler_time: Histogram,
    pub(crate) ingress_selector_get_payload_time: Histogram,
    pub(crate) ingress_selector_validate_payload_time: Histogram,
    pub(crate) ingress_payload_cache_size: IntGauge,

    validated_ingress_message_size: Histogram,
    validated_ingress_message_signature_size: Histogram,
    validated_ingress_message_time: Histogram,

    pub(crate) invalidated_ingress_message_count: IntCounterVec,
}

impl IngressManagerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
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
            validated_ingress_message_size: metrics_registry.histogram(
                "ingress_handler_validated_ingress_message_size",
                "The size of validated ingress message, in bytes",
                decimal_buckets(0, 6),
            ),
            validated_ingress_message_signature_size: metrics_registry.histogram(
                "ingress_handler_validated_ingress_message_signature_size",
                "The size of the signature of validated ingress message, in bytes. \
                Just an estimate",
                decimal_buckets(0, 6),
            ),
            validated_ingress_message_time: metrics_registry.histogram(
                "ingress_handler_validated_ingress_message_time",
                "How long, in seconds, the ingress message was in the pool before \
                it was validated",
                decimal_buckets(-4, 0),
            ),
            invalidated_ingress_message_count: metrics_registry.int_counter_vec(
                "ingress_handler_invalidated_ingress_message_count",
                "The number of invalidated ingress messages, partitioned by the reason",
                &["reason"],
            ),
        }
    }

    pub(crate) fn observe_validated_ingress_message(
        &self,
        time_source: &dyn TimeSource,
        ingress: &UnvalidatedIngressArtifact,
    ) {
        self.validated_ingress_message_time.observe(
            time_source
                .get_relative_time()
                .saturating_duration_since(ingress.timestamp)
                .as_secs_f64(),
        );
        self.validated_ingress_message_size
            .observe(ingress.message.signed_ingress.count_bytes() as f64);

        // In order to estimate how many bytes of the CBOR encoded ingress message
        // belong to the signature, we serialize the signature and count the bytes.
        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        if ingress
            .message
            .signed_ingress
            .authentication()
            .serialize(&mut serializer)
            .is_ok()
        {
            self.validated_ingress_message_signature_size
                .observe(serialized_bytes.len() as f64);
        }
    }
}
