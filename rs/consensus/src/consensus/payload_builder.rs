//! Payload creation/validation subcomponent

use crate::consensus::{
    metrics::{
        PayloadBuilderMetrics, CRITICAL_ERROR_PAYLOAD_TOO_LARGE, CRITICAL_ERROR_SUBNET_RECORD_ISSUE,
    },
    payload::BatchPayloadSectionBuilder,
};
use ic_consensus_utils::get_subnet_record;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, ProposalContext},
    consensus::{InvalidPayloadReason, PayloadBuilder, PayloadValidationError},
    ingress_manager::IngressSelector,
    messaging::XNetPayloadBuilder,
    self_validating_payload::SelfValidatingPayloadBuilder,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_types::{
    batch::{BatchPayload, ValidationContext, MAX_BITCOIN_PAYLOAD_IN_BYTES},
    consensus::{block_maker::SubnetRecords, Payload},
    messages::MAX_XNET_PAYLOAD_IN_BYTES,
    Height, NodeId, NumBytes, SubnetId, Time,
};
use std::sync::Arc;

/// Implementation of PayloadBuilder.
pub struct PayloadBuilderImpl {
    subnet_id: SubnetId,
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    section_builder: Vec<BatchPayloadSectionBuilder>,
    metrics: PayloadBuilderMetrics,
    logger: ReplicaLogger,
}

impl PayloadBuilderImpl {
    /// Helper to create PayloadBuilder
    pub fn new(
        subnet_id: SubnetId,
        node_id: NodeId,
        registry_client: Arc<dyn RegistryClient>,
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
        canister_http_payload_builder: Arc<dyn BatchPayloadBuilder>,
        query_stats_payload_builder: Arc<dyn BatchPayloadBuilder>,
        metrics: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let section_builder = vec![
            BatchPayloadSectionBuilder::Ingress(ingress_selector),
            BatchPayloadSectionBuilder::SelfValidating(self_validating_payload_builder),
            BatchPayloadSectionBuilder::XNet(xnet_payload_builder),
            BatchPayloadSectionBuilder::CanisterHttp(canister_http_payload_builder),
            BatchPayloadSectionBuilder::QueryStats(query_stats_payload_builder),
        ];

        Self {
            subnet_id,
            node_id,
            registry_client,
            section_builder,
            metrics: PayloadBuilderMetrics::new(metrics),
            logger,
        }
    }

    /// Helper to create PayloadBuilder for testing
    pub fn new_for_testing(
        subnet_id: SubnetId,
        node_id: NodeId,
        registry_client: Arc<dyn RegistryClient>,
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        canister_http_payload_builder: Arc<dyn BatchPayloadBuilder>,
        query_stats_payload_builder: Arc<dyn BatchPayloadBuilder>,
        metrics: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let section_builder = vec![
            BatchPayloadSectionBuilder::Ingress(ingress_selector),
            BatchPayloadSectionBuilder::XNet(xnet_payload_builder),
            BatchPayloadSectionBuilder::CanisterHttp(canister_http_payload_builder),
            BatchPayloadSectionBuilder::QueryStats(query_stats_payload_builder),
        ];

        Self {
            subnet_id,
            node_id,
            registry_client,
            section_builder,
            metrics: PayloadBuilderMetrics::new(metrics),
            logger,
        }
    }
}

impl PayloadBuilder for PayloadBuilderImpl {
    fn get_payload(
        &self,
        height: Height,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
        subnet_records: &SubnetRecords,
    ) -> BatchPayload {
        let _timer = self.metrics.get_payload_duration.start_timer();
        self.metrics
            .past_payloads_length
            .observe(past_payloads.len() as f64);

        // To call the section builders in a somewhat fair manner,
        // we call them in a rotation. Note that this is not really fair,
        // as payload builders that yield a lot always give precedence to the
        // same next payload builder. This might give an advantage to a particular
        // payload builder.
        let num_sections = self.section_builder.len();
        let mut section_select = (0..num_sections).collect::<Vec<_>>();
        section_select.rotate_right(height.get() as usize % num_sections);

        // Fetch Subnet Record for Consensus registry version, return empty batch payload is not available
        let max_block_payload_size =
            self.get_max_block_payload_size_bytes(&subnet_records.context_version);

        let mut batch_payload = BatchPayload::default();
        let mut accumulated_size = 0;

        for (priority, section_id) in section_select.into_iter().enumerate() {
            accumulated_size += self.section_builder[section_id]
                .build_payload(
                    &mut batch_payload,
                    height,
                    &ProposalContext {
                        proposer: self.node_id,
                        validation_context: context,
                    },
                    NumBytes::new(
                        max_block_payload_size
                            .get()
                            .saturating_sub(accumulated_size),
                    ),
                    past_payloads,
                    priority,
                    &self.metrics,
                    &self.logger,
                )
                .get();
        }

        batch_payload
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
    ) -> ValidationResult<PayloadValidationError> {
        let _timer = self.metrics.validate_payload_duration.start_timer();
        if payload.is_summary() {
            return Ok(());
        }
        let batch_payload = &payload.as_ref().as_data().batch;
        let subnet_record = self.get_subnet_record(proposal_context.validation_context)?;

        // Retrieve max_block_payload_size from subnet
        let max_block_payload_size = self.get_max_block_payload_size_bytes(&subnet_record);

        let mut accumulated_size = NumBytes::new(0);
        for builder in &self.section_builder {
            accumulated_size +=
                builder.validate_payload(height, batch_payload, proposal_context, past_payloads)?;
        }

        // Check the combined size of the payloads using a 2x safety margin.
        // We allow payloads that are bigger than the maximum size but log an error.
        // And reject outright payloads that are more than twice the maximum size.
        if accumulated_size > max_block_payload_size {
            error!(
                self.logger,
                "The overall block size is too large, even though the individual payloads are valid: {}",
                CRITICAL_ERROR_PAYLOAD_TOO_LARGE
            );
            self.metrics.critical_error_payload_too_large.inc();
        }
        if accumulated_size > max_block_payload_size * 2 {
            return Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::PayloadTooBig {
                    expected: max_block_payload_size,
                    received: accumulated_size,
                },
            ));
        }

        Ok(())
    }
}

impl PayloadBuilderImpl {
    /// Fetches the [`SubnetRecord`] corresponding to the registry version provided
    /// by the [`ValidationContext`]
    fn get_subnet_record(
        &self,
        context: &ValidationContext,
    ) -> Result<SubnetRecord, PayloadValidationError> {
        get_subnet_record(
            self.registry_client.as_ref(),
            self.subnet_id,
            context.registry_version,
            &self.logger,
        )
    }

    /// Returns the valid maximum block payload length from the registry and
    /// checks the invariants. Emits a warning in case the invariants are not
    /// met.
    fn get_max_block_payload_size_bytes(&self, subnet_record: &SubnetRecord) -> NumBytes {
        let required_min_size = MAX_BITCOIN_PAYLOAD_IN_BYTES
            .max(MAX_XNET_PAYLOAD_IN_BYTES.get())
            .max(subnet_record.max_ingress_bytes_per_message);

        let mut max_block_payload_size = subnet_record.max_block_payload_size;
        // In any case, ensure the value is bigger than inter canister payload and
        // message size
        if max_block_payload_size < required_min_size {
            warn!(every_n_seconds => 300, self.logger,
                "max_block_payload_size too small. current value: {}, required minimum: {}! \
                max_block_payload_size must be larger than max_ingress_bytes_per_message \
                and MAX_XNET_PAYLOAD_IN_BYTES. Update registry! @{}",
                max_block_payload_size, required_min_size, CRITICAL_ERROR_SUBNET_RECORD_ISSUE);
            self.metrics.critical_error_subnet_record_data_issue.inc();
            max_block_payload_size = required_min_size;
        }

        NumBytes::new(max_block_payload_size)
    }
}
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use ic_btc_replica_types::{
        BitcoinAdapterResponse, BitcoinAdapterResponseWrapper, GetSuccessorsResponseComplete,
    };
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_https_outcalls_consensus::test_utils::FakeCanisterHttpPayloadBuilder;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector,
        self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
        xnet_payload_builder::FakeXNetPayloadBuilder,
    };
    use ic_test_utilities_consensus::{batch::MockBatchPayloadBuilder, fake::Fake};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::{
        ids::{node_test_id, subnet_test_id},
        messages::SignedIngressBuilder,
    };
    use ic_types::{
        canister_http::CanisterHttpResponseWithConsensus,
        consensus::certification::{Certification, CertificationContent},
        crypto::{CryptoHash, Signed},
        messages::SignedIngress,
        signature::ThresholdSignature,
        time::UNIX_EPOCH,
        xnet::CertifiedStreamSlice,
        CryptoHashOfPartialState, RegistryVersion,
    };
    use std::collections::BTreeMap;

    #[cfg(feature = "proptest")]
    impl PayloadBuilderImpl {
        /// Return the number of critical errors that have occurred.
        ///
        /// This is useful for proptests.
        pub(crate) fn count_critical_errors(&self) -> u64 {
            self.metrics.critical_error_payload_too_large.get()
                + self.metrics.critical_error_subnet_record_data_issue.get()
                + self.metrics.critical_error_validation_not_passed.get()
        }
    }

    /// Builds a `PayloadBuilderImpl` wrapping fake payload
    /// builders that return the supplied ingress and XNet data.
    pub(crate) fn make_test_payload_impl(
        registry: Arc<dyn RegistryClient>,
        mut ingress_messages: Vec<Vec<SignedIngress>>,
        mut certified_streams: Vec<BTreeMap<SubnetId, CertifiedStreamSlice>>,
        responses_from_adapter: Vec<BitcoinAdapterResponse>,
        canister_http_responses: Vec<CanisterHttpResponseWithConsensus>,
    ) -> PayloadBuilderImpl {
        let ingress_selector = FakeIngressSelector::new();
        ingress_messages
            .drain(..)
            .for_each(|im| ingress_selector.enqueue(im));
        let xnet_payload_builder =
            FakeXNetPayloadBuilder::make(certified_streams.drain(..).collect());
        let self_validating_payload_builder =
            FakeSelfValidatingPayloadBuilder::new().with_responses(responses_from_adapter);
        let canister_http_payload_builder =
            FakeCanisterHttpPayloadBuilder::new().with_responses(canister_http_responses);
        let query_stats_payload_builder = MockBatchPayloadBuilder::new().expect_noop();

        PayloadBuilderImpl::new(
            subnet_test_id(0),
            node_test_id(0),
            registry,
            Arc::new(ingress_selector),
            Arc::new(xnet_payload_builder),
            Arc::new(self_validating_payload_builder),
            Arc::new(canister_http_payload_builder),
            Arc::new(query_stats_payload_builder),
            MetricsRegistry::new(),
            no_op_logger(),
        )
    }

    /// Builds a `CertifiedStreamSlice` from the supplied `payload` and
    /// `merkle_proof` bytes, without a valid certification.
    fn make_certified_stream_slice(
        height: u64,
        payload: Vec<u8>,
        merkle_proof: Vec<u8>,
    ) -> CertifiedStreamSlice {
        CertifiedStreamSlice {
            payload,
            merkle_proof,
            certification: Certification {
                height: Height::from(height),
                signed: Signed {
                    signature: ThresholdSignature::fake(),
                    content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                        vec![],
                    ))),
                },
            },
        }
    }

    // Test that confirms that the output of messaging.get_messages aligns with the
    // messages acquired from the application layer.
    fn test_get_messages(
        provided_ingress_messages: Vec<SignedIngress>,
        provided_certified_streams: BTreeMap<SubnetId, CertifiedStreamSlice>,
        provided_responses_from_adapter: Vec<BitcoinAdapterResponse>,
        provided_canister_http_responses: Vec<CanisterHttpResponseWithConsensus>,
    ) {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let Dependencies { registry, .. } = dependencies(pool_config, 1);
                let payload_builder = make_test_payload_impl(
                    registry,
                    vec![provided_ingress_messages.clone()],
                    vec![provided_certified_streams.clone()],
                    provided_responses_from_adapter.clone(),
                    provided_canister_http_responses.clone(),
                );

                let prev_payloads = Vec::new();
                let context = ValidationContext {
                    certified_height: Height::from(0),
                    registry_version: RegistryVersion::from(1),
                    time: UNIX_EPOCH,
                };
                let subnet_record = SubnetRecordBuilder::from(&[node_test_id(0)]).build();
                let subnet_records = SubnetRecords {
                    membership_version: subnet_record.clone(),
                    context_version: subnet_record,
                };

                let batch_messages = payload_builder
                    .get_payload(Height::from(1), &prev_payloads, &context, &subnet_records)
                    .into_messages()
                    .unwrap();

                assert_eq!(
                    batch_messages.signed_ingress_msgs,
                    provided_ingress_messages
                );
                assert_eq!(
                    batch_messages.certified_stream_slices,
                    provided_certified_streams
                );
                assert_eq!(
                    batch_messages.bitcoin_adapter_responses,
                    provided_responses_from_adapter
                );
            },
        )
    }

    // Engine for changing the number of Ingress and RequestOrResponse messages
    // provided by the application.
    fn param_msgs_test(in_count: u64, stream_count: u64) {
        let ingress = |i| SignedIngressBuilder::new().nonce(i).build();
        let inputs = (0..in_count).map(ingress).collect();
        let certified_streams = (0..stream_count)
            .map(|x| {
                (
                    subnet_test_id(x),
                    make_certified_stream_slice(1, vec![], vec![]),
                )
            })
            .collect();
        let responses_from_adapter = vec![BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                GetSuccessorsResponseComplete {
                    blocks: vec![],
                    next: vec![],
                },
            ),
            callback_id: 0,
        }];

        test_get_messages(inputs, certified_streams, responses_from_adapter, vec![])
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
