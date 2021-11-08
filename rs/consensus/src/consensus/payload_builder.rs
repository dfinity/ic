//! Payload creation/validation subcomponent

use crate::consensus::metrics::PayloadBuilderMetrics;
use ic_interfaces::{
    consensus::PayloadValidationError,
    ingress_manager::{IngressSelector, IngressSetQuery},
    ingress_pool::IngressPoolSelect,
    messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
    validation::ValidationResult,
};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::IngressMessageId,
    batch::{BatchPayload, SelfValidatingPayload, ValidationContext, XNetPayload},
    consensus::{BlockPayload, Payload},
    crypto::CryptoHashOf,
    messages::MAX_XNET_PAYLOAD_IN_BYTES,
    Height, Time,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};

/// The PayloadBuilder is responsible for creating and validating payload that
/// is included in consensus blocks.
pub trait PayloadBuilder: Send + Sync {
    /// Produces a payload that is valid given `past_payloads` and `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn get_payload(
        &self,
        ingress_pool: &dyn IngressPoolSelect,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> BatchPayload;

    /// Checks whether the provided `payload` is valid given `past_payloads` and
    /// `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn validate_payload(
        &self,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> ValidationResult<PayloadValidationError>;
}

/// Cache of sets of message ids for past payloads. The index used here is a
/// tuple (Height, HashOfBatchPayload) for two reasons:
/// 1. We want to purge this cache by height, for those below certified height.
/// 2. There could be more than one payloads at a given height due to blockchain
/// branching.
type IngressPayloadCache =
    BTreeMap<(Height, CryptoHashOf<BlockPayload>), Arc<HashSet<IngressMessageId>>>;

/// A list of hashsets that implements IngressSetQuery.
struct IngressSets {
    hash_sets: Vec<Arc<HashSet<IngressMessageId>>>,
    min_block_time: Time,
}

impl IngressSets {
    fn new(hash_sets: Vec<Arc<HashSet<IngressMessageId>>>, min_block_time: Time) -> Self {
        IngressSets {
            hash_sets,
            min_block_time,
        }
    }
}

impl IngressSetQuery for IngressSets {
    fn contains(&self, msg_id: &IngressMessageId) -> bool {
        self.hash_sets.iter().any(|set| set.contains(msg_id))
    }

    fn get_expiry_lower_bound(&self) -> Time {
        self.min_block_time
    }
}

/// Implementation of PayloadBuilder.
pub struct PayloadBuilderImpl {
    ingress_selector: Arc<dyn IngressSelector>,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    metrics: PayloadBuilderMetrics,
    ingress_payload_cache: RwLock<IngressPayloadCache>,
}

impl PayloadBuilderImpl {
    /// Helper to create PayloadBuilder
    pub fn new(
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
        metrics: MetricsRegistry,
    ) -> Self {
        Self {
            ingress_selector,
            xnet_payload_builder,
            self_validating_payload_builder,
            metrics: PayloadBuilderMetrics::new(metrics),
            ingress_payload_cache: RwLock::new(BTreeMap::new()),
        }
    }
}

impl PayloadBuilder for PayloadBuilderImpl {
    fn get_payload(
        &self,
        ingress_pool: &dyn IngressPoolSelect,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> BatchPayload {
        let _timer = self.metrics.get_payload_duration.start_timer();
        let mut ingress_payload_cache = self.ingress_payload_cache.write().unwrap();
        let min_block_time = match past_payloads.last() {
            None => context.time,
            Some((_, time, _)) => *time,
        };
        let (past_ingress, past_xnet, past_self_validating) =
            split_past_payloads(&mut ingress_payload_cache, past_payloads);
        self.metrics
            .past_payloads_length
            .observe(past_payloads.len() as f64);

        let xnet = self.xnet_payload_builder.get_xnet_payload(
            context,
            &past_xnet,
            MAX_XNET_PAYLOAD_IN_BYTES,
        );

        let ingress_query = IngressSets::new(past_ingress, min_block_time);
        let ingress =
            self.ingress_selector
                .get_ingress_payload(ingress_pool, &ingress_query, context);

        self.metrics
            .ingress_payload_cache_size
            .set(ingress_payload_cache.len() as i64);

        // TODO: Use real SELF_VALIDATING payload builder
        let self_validating = self
            .self_validating_payload_builder
            .get_self_validating_payload(context, &past_self_validating, MAX_XNET_PAYLOAD_IN_BYTES);

        BatchPayload {
            ingress,
            xnet,
            self_validating,
        }
    }

    fn validate_payload(
        &self,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> ValidationResult<PayloadValidationError> {
        let _timer = self.metrics.validate_payload_duration.start_timer();
        if payload.is_summary() {
            return Ok(());
        }
        let batch_payload = &payload.as_ref().as_data().batch;
        let mut ingress_payload_cache = self.ingress_payload_cache.write().unwrap();
        let min_block_time = match past_payloads.last() {
            None => context.time,
            Some((_, time, _)) => *time,
        };
        let (past_ingress, past_xnet, past_self_validating) =
            split_past_payloads(&mut ingress_payload_cache, past_payloads);
        self.metrics
            .ingress_payload_cache_size
            .set(ingress_payload_cache.len() as i64);

        let ingress_query = IngressSets::new(past_ingress, min_block_time);

        // If ingress valiation is not valid, return it early.
        self.ingress_selector.validate_ingress_payload(
            &batch_payload.ingress,
            &ingress_query,
            context,
        )?;

        self.xnet_payload_builder.validate_xnet_payload(
            &batch_payload.xnet,
            context,
            &past_xnet,
        )?;

        self.self_validating_payload_builder
            .validate_self_validating_payload(
                &batch_payload.self_validating,
                context,
                &past_self_validating,
            )?;

        Ok(())
    }
}

/// Split past_payloads into past_ingress and past_xnet payloads. The
/// past_ingress is actually a list of HashSet of MessageIds taken from the
/// ingress_payload_cache.
#[allow(clippy::type_complexity)]
fn split_past_payloads<'a, 'b>(
    ingress_payload_cache: &'a mut IngressPayloadCache,
    past_payloads: &'b [(Height, Time, Payload)],
) -> (
    Vec<Arc<HashSet<IngressMessageId>>>,
    Vec<&'b XNetPayload>,
    Vec<&'b SelfValidatingPayload>,
) {
    let past_xnet: Vec<_> = past_payloads
        .iter()
        .filter_map(|(_, _, payload)| {
            if payload.is_summary() {
                None
            } else {
                Some(&payload.as_ref().as_data().batch.xnet)
            }
        })
        .collect();
    let past_ingress: Vec<_> = past_payloads
        .iter()
        .filter_map(|(height, _, payload)| {
            if payload.is_summary() {
                None
            } else {
                let payload_hash = payload.get_hash();
                let batch = &payload.as_ref().as_data().batch;
                let ingress = ingress_payload_cache
                    .entry((*height, payload_hash.clone()))
                    .or_insert_with(|| Arc::new(batch.ingress.message_ids().into_iter().collect()));
                Some(ingress.clone())
            }
        })
        .collect();
    let past_self_validating: Vec<_> = past_payloads
        .iter()
        .filter_map(|(_, _, payload)| {
            if payload.is_summary() {
                None
            } else {
                Some(&payload.as_ref().as_data().batch.self_validating)
            }
        })
        .collect();
    // We assume that 'past_payloads' comes in descending heights, following the
    // block parent traversal order.
    if let Some((min_height, _, _)) = past_payloads.last() {
        // The step below is to garbage collect no longer used past ingress payload
        // cache. It assumes the sequence of calls to payload selection/validation
        // leads to a monotonic sequence of lower-bound (min_height).
        //
        // Usually this is true, but even when it is not true (e.g. in tests) it is
        // always safe to remove entries from ingress_payload_cache at the expense
        // of having to re-compute them.
        let keys: Vec<_> = ingress_payload_cache.keys().cloned().collect();
        for key in keys {
            if key.0 < *min_height {
                ingress_payload_cache.remove(&key);
            }
        }
    }
    (past_ingress, past_xnet, past_self_validating)
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_test_artifact_pool::ingress_pool::TestIngressPool;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector, mock_time,
        self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
        types::messages::SignedIngressBuilder, xnet_payload_builder::FakeXNetPayloadBuilder,
    };
    use ic_types::{
        consensus::certification::Certification, messages::SignedIngress,
        xnet::CertifiedStreamSlice, *,
    };
    use std::collections::BTreeMap;

    // Test that confirms that the output of messaging.get_messages aligns with the
    // messages acquired from the application layer.
    fn test_get_messages(
        provided_ingress_messages: Vec<SignedIngress>,
        provided_certified_streams: BTreeMap<SubnetId, CertifiedStreamSlice>,
    ) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ingress_selector = FakeIngressSelector::new();
            ingress_selector.enqueue(provided_ingress_messages.clone());
            let ingress_pool = TestIngressPool::new(pool_config);
            let xnet_payload_builder =
                FakeXNetPayloadBuilder::make(provided_certified_streams.clone());
            let self_validating_payload_builder = FakeSelfValidatingPayloadBuilder::new();
            let metrics_registry = MetricsRegistry::new();

            let ingress_selector = Arc::new(ingress_selector);
            let xnet_payload_builder = Arc::new(xnet_payload_builder);
            let self_validating_payload_builder = Arc::new(self_validating_payload_builder);

            let payload_builder = PayloadBuilderImpl::new(
                ingress_selector,
                xnet_payload_builder,
                self_validating_payload_builder,
                metrics_registry,
            );

            let prev_payloads = Vec::new();
            let context = ValidationContext {
                certified_height: Height::from(0),
                registry_version: RegistryVersion::from(1),
                time: mock_time(),
            };

            let (ingress_msgs, stream_msgs) = payload_builder
                .get_payload(&ingress_pool, &prev_payloads, &context)
                .into_messages()
                .unwrap();

            assert_eq!(ingress_msgs.len(), provided_ingress_messages.len());
            provided_ingress_messages
                .into_iter()
                .zip(ingress_msgs.into_iter())
                .for_each(|(a, b)| assert_eq!(a, b));

            assert_eq!(stream_msgs.len(), provided_certified_streams.len());
            provided_certified_streams
                .iter()
                .zip(stream_msgs.iter())
                .for_each(|(a, b)| assert_eq!(a, b));
        })
    }

    // Engine for changing the number of Ingress and RequestOrResponse messages
    // provided by the application.
    fn param_msgs_test(in_count: u64, stream_count: u64) {
        use ic_test_utilities::consensus::fake::Fake;
        use ic_types::consensus::{certification::CertificationContent, ThresholdSignature};
        use ic_types::crypto::{CryptoHash, Signed};

        let ingress = |i| SignedIngressBuilder::new().nonce(i).build();
        let inputs = (0..in_count).map(ingress).collect();
        let certified_streams = (0..stream_count)
            .map(|x| {
                (
                    subnet_test_id(x),
                    CertifiedStreamSlice {
                        payload: vec![],
                        merkle_proof: vec![],
                        certification: Certification {
                            height: Height::from(1),
                            signed: Signed {
                                signature: ThresholdSignature::fake(),
                                content: CertificationContent::new(CryptoHashOfPartialState::from(
                                    CryptoHash(vec![]),
                                )),
                            },
                        },
                    },
                )
            })
            .collect();

        test_get_messages(inputs, certified_streams)
    }

    #[test]
    fn test_get_messages_interface() {
        for i in 0..3 {
            for j in 0..3 {
                param_msgs_test(i, j);
            }
        }
    }
}
