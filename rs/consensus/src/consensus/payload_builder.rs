//! Payload creation/validation subcomponent

use crate::consensus::{
    metrics::{
        CRITICAL_ERROR_PAYLOAD_TOO_LARGE, CRITICAL_ERROR_SUBNET_RECORD_ISSUE, PayloadBuilderMetrics,
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
use ic_logger::{ReplicaLogger, error, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_types::{
    Height, NodeId, NumBytes, SubnetId, Time,
    batch::{BatchPayload, MAX_BITCOIN_PAYLOAD_IN_BYTES, ValidationContext},
    consensus::{Payload, block_maker::SubnetRecords},
    messages::MAX_XNET_PAYLOAD_IN_BYTES,
};
use num_traits::SaturatingSub;
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
        vetkd_payload_builder: Arc<dyn BatchPayloadBuilder>,
        metrics: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let section_builder = vec![
            BatchPayloadSectionBuilder::Ingress(ingress_selector),
            BatchPayloadSectionBuilder::SelfValidating(self_validating_payload_builder),
            BatchPayloadSectionBuilder::XNet(xnet_payload_builder),
            BatchPayloadSectionBuilder::CanisterHttp(canister_http_payload_builder),
            BatchPayloadSectionBuilder::QueryStats(query_stats_payload_builder),
            BatchPayloadSectionBuilder::VetKd(vetkd_payload_builder),
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
        let mut accumulated_size = NumBytes::new(0);

        for (priority, section_id) in section_select.into_iter().enumerate() {
            accumulated_size += self.section_builder[section_id].build_payload(
                &mut batch_payload,
                height,
                &ProposalContext {
                    proposer: self.node_id,
                    validation_context: context,
                },
                max_block_payload_size.saturating_sub(&accumulated_size),
                past_payloads,
                priority,
                &self.metrics,
                &self.logger,
            );
        }
        self.metrics
            .payload_size_bytes
            .observe(accumulated_size.get() as f64);

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
    use ic_consensus_mocks::{Dependencies, dependencies};
    use ic_https_outcalls_consensus::test_utils::FakeCanisterHttpPayloadBuilder;
    use ic_interfaces_mocks::messaging::MockXNetPayloadBuilder;
    use ic_interfaces_mocks::payload_builder::{
        MockIngressSelector, MockSelfValidatingPayloadBuilder,
    };
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
        CountBytes, CryptoHashOfPartialState, RegistryVersion,
        batch::{IngressPayload, SelfValidatingPayload, XNetPayload},
        canister_http::CanisterHttpResponseWithConsensus,
        consensus::{
            BlockPayload, DataPayload,
            certification::{Certification, CertificationContent},
            dkg::DkgDataPayload,
        },
        crypto::{CryptoHash, Signed, crypto_hash},
        ingress::IngressSets,
        messages::SignedIngress,
        signature::ThresholdSignature,
        time::UNIX_EPOCH,
        xnet::CertifiedStreamSlice,
    };
    use ic_types_test_utils::ids::NODE_1;
    use mockall::predicate;
    use rstest::rstest;
    use std::collections::BTreeMap;

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
        let vetkd_payload_builder = MockBatchPayloadBuilder::new().expect_noop();

        PayloadBuilderImpl::new(
            subnet_test_id(0),
            node_test_id(0),
            registry,
            Arc::new(ingress_selector),
            Arc::new(xnet_payload_builder),
            Arc::new(self_validating_payload_builder),
            Arc::new(canister_http_payload_builder),
            Arc::new(query_stats_payload_builder),
            Arc::new(vetkd_payload_builder),
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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
        })
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

    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;

    #[test]
    // NOTE: this test is sensitive to the order in which the individual payload builders are executed.
    // At the time of the writing the test the order for a block at height 1 is:
    // 1. vetkd
    // 2. ingress
    // 3. bitcoin
    // 3. xnet
    // 4. canister hhtp
    // 5. query_stats
    fn test_get_payload_respect_limits() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { registry, .. } = dependencies(pool_config, 1);

            const MAX_BLOCK_SIZE: NumBytes = NumBytes::new(ic_limits::MAX_BLOCK_PAYLOAD_SIZE);
            const XNET_PAYLOAD_SIZE: NumBytes = NumBytes::new(64 * KB);
            const BITCOIN_PAYLOAD_SIZE: NumBytes = NumBytes::new(128 * KB);
            const CANISTER_HTTP_PAYLOAD_SIZE: NumBytes = NumBytes::new(256 * KB);
            const VETKD_PAYLOAD_SIZE: NumBytes = NumBytes::new(512 * KB);
            const QUERY_STATS_PAYLOAD_SIZE: NumBytes = NumBytes::new(MB);
            const INGRESS_MESSAGE_PAYLOAD_SIZE: NumBytes = NumBytes::new(2 * MB);

            let ingress = SignedIngressBuilder::new()
                .method_payload(vec![0; INGRESS_MESSAGE_PAYLOAD_SIZE.get() as usize])
                .build();
            let ingress_size = NumBytes::from(ingress.count_bytes() as u64);

            let payload_builder = set_up_payload_builder(
                registry,
                MocksSettings {
                    vetkd_payload_to_return: vec![0; VETKD_PAYLOAD_SIZE.get() as usize],
                    expected_vetkd_payload_size_limit: MAX_BLOCK_SIZE,
                    ingress_payload_to_return: IngressPayload::from(vec![ingress]),
                    expected_ingress_payload_size_limit: MAX_BLOCK_SIZE - VETKD_PAYLOAD_SIZE,
                    bitcoin_payload_size_to_return: BITCOIN_PAYLOAD_SIZE,
                    expected_bitcoin_payload_size_limit: MAX_BLOCK_SIZE
                        - VETKD_PAYLOAD_SIZE
                        - ingress_size,
                    xnet_payload_size_to_return: XNET_PAYLOAD_SIZE,
                    expected_xnet_payload_size_limit: NumBytes::new(
                        95 * (MAX_BLOCK_SIZE
                            - VETKD_PAYLOAD_SIZE
                            - ingress_size
                            - BITCOIN_PAYLOAD_SIZE)
                            .get()
                            / 100,
                    ),
                    http_outcalls_payload_to_return: vec![
                        0;
                        CANISTER_HTTP_PAYLOAD_SIZE.get() as usize
                    ],
                    expected_http_outcalls_size_limit: MAX_BLOCK_SIZE
                        - VETKD_PAYLOAD_SIZE
                        - ingress_size
                        - BITCOIN_PAYLOAD_SIZE
                        - XNET_PAYLOAD_SIZE,
                    query_stats_payload_to_return: vec![0; QUERY_STATS_PAYLOAD_SIZE.get() as usize],
                    expected_query_stats_size_limit: MAX_BLOCK_SIZE
                        - VETKD_PAYLOAD_SIZE
                        - ingress_size
                        - BITCOIN_PAYLOAD_SIZE
                        - XNET_PAYLOAD_SIZE
                        - CANISTER_HTTP_PAYLOAD_SIZE,
                },
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

            // this will fail if any of the expectations above are not met
            payload_builder.get_payload(Height::from(1), &prev_payloads, &context, &subnet_records);
        })
    }

    #[rstest]
    #[case(2 * MB, false, false)]
    #[case(3 * MB, true, false)]
    #[case(6 * MB, true, false)]
    #[case(7 * MB, true, true)]
    // Note: payloads other than the ingress payload sum to a little below 2 MB.
    fn test_validate_payload_respect_limits(
        #[case] ingress_payload_size: u64,
        #[case] expects_soft_error: bool,
        #[case] expects_hard_error: bool,
    ) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            const ZERO_BYTES: NumBytes = NumBytes::new(0);

            let Dependencies { registry, .. } = dependencies(pool_config, 1);

            let ingress = SignedIngressBuilder::new()
                .method_payload(vec![0; ingress_payload_size as usize])
                .build();

            let settings = MocksSettings {
                ingress_payload_to_return: IngressPayload::from(vec![ingress]),
                query_stats_payload_to_return: vec![0; MB as usize],
                vetkd_payload_to_return: vec![0; 512 * KB as usize],
                http_outcalls_payload_to_return: vec![0; 256 * KB as usize],
                bitcoin_payload_size_to_return: NumBytes::new(128 * KB),
                xnet_payload_size_to_return: NumBytes::new(64 * KB),
                // The fields below are irrelevant for the test
                expected_vetkd_payload_size_limit: ZERO_BYTES,
                expected_ingress_payload_size_limit: ZERO_BYTES,
                expected_bitcoin_payload_size_limit: ZERO_BYTES,
                expected_xnet_payload_size_limit: ZERO_BYTES,
                expected_http_outcalls_size_limit: ZERO_BYTES,
                expected_query_stats_size_limit: ZERO_BYTES,
            };
            let payload_builder = set_up_payload_builder(registry, settings.clone());

            let prev_payloads = Vec::new();
            let context = ValidationContext {
                certified_height: Height::from(0),
                registry_version: RegistryVersion::from(1),
                time: UNIX_EPOCH,
            };
            let proposal_context = ProposalContext {
                proposer: NODE_1,
                validation_context: &context,
            };
            let payload = Payload::new(
                crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload {
                        ingress: settings.ingress_payload_to_return,
                        xnet: XNetPayload::default(),
                        self_validating: SelfValidatingPayload::default(),
                        canister_http: settings.http_outcalls_payload_to_return,
                        query_stats: settings.query_stats_payload_to_return,
                        vetkd: settings.vetkd_payload_to_return,
                    },
                    dkg: DkgDataPayload::new_empty(Height::from(0)),
                    idkg: None,
                }),
            );

            assert_eq!(
                payload_builder
                    .validate_payload(Height::from(1), &proposal_context, &payload, &prev_payloads,)
                    .is_err(),
                expects_hard_error,
            );

            if expects_soft_error {
                assert!(payload_builder.count_critical_errors() > 0);
            } else {
                assert_eq!(payload_builder.count_critical_errors(), 0);
            }
        })
    }

    #[derive(Clone)]
    struct MocksSettings {
        ingress_payload_to_return: IngressPayload,
        expected_ingress_payload_size_limit: NumBytes,
        vetkd_payload_to_return: Vec<u8>,
        expected_vetkd_payload_size_limit: NumBytes,
        bitcoin_payload_size_to_return: NumBytes,
        expected_bitcoin_payload_size_limit: NumBytes,
        xnet_payload_size_to_return: NumBytes,
        expected_xnet_payload_size_limit: NumBytes,
        http_outcalls_payload_to_return: Vec<u8>,
        expected_http_outcalls_size_limit: NumBytes,
        query_stats_payload_to_return: Vec<u8>,
        expected_query_stats_size_limit: NumBytes,
    }

    fn set_up_payload_builder(
        registry: Arc<dyn RegistryClient>,
        settings: MocksSettings,
    ) -> PayloadBuilderImpl {
        let vetkd_payload_builder = MockBatchPayloadBuilder::new().with_response_and_max_size(
            settings.vetkd_payload_to_return,
            settings.expected_vetkd_payload_size_limit,
        );

        let mut ingress_selector = MockIngressSelector::new();
        ingress_selector
            .expect_filter_past_payloads()
            .return_once(|_, _| IngressSets::new(vec![], UNIX_EPOCH));
        ingress_selector
            .expect_validate_ingress_payload()
            .return_once(|_, _, _| Ok(()));
        ingress_selector
            .expect_get_ingress_payload()
            .with(
                predicate::always(),
                predicate::always(),
                predicate::eq(settings.expected_ingress_payload_size_limit),
            )
            .return_once(move |_, _, _| settings.ingress_payload_to_return);

        let mut self_validating_payload_builder = MockSelfValidatingPayloadBuilder::new();
        self_validating_payload_builder
            .expect_get_self_validating_payload()
            .with(
                predicate::always(),
                predicate::always(),
                predicate::eq(settings.expected_bitcoin_payload_size_limit),
                predicate::always(),
            )
            .return_once(move |_, _, _, _| {
                (
                    SelfValidatingPayload::default(),
                    settings.bitcoin_payload_size_to_return,
                )
            });
        self_validating_payload_builder
            .expect_validate_self_validating_payload()
            .return_once(move |_, _, _| Ok(settings.bitcoin_payload_size_to_return));

        let mut xnet_payload_builder = MockXNetPayloadBuilder::new();
        xnet_payload_builder
            .expect_get_xnet_payload()
            .with(
                predicate::always(),
                predicate::always(),
                predicate::eq(settings.expected_xnet_payload_size_limit),
            )
            .return_once(move |_, _, _| {
                (XNetPayload::default(), settings.xnet_payload_size_to_return)
            });
        xnet_payload_builder
            .expect_validate_xnet_payload()
            .return_once(move |_, _, _| Ok(settings.xnet_payload_size_to_return));

        let canister_http_payload_builder = MockBatchPayloadBuilder::new()
            .with_response_and_max_size(
                settings.http_outcalls_payload_to_return,
                settings.expected_http_outcalls_size_limit,
            );

        let query_stats_payload_builder = MockBatchPayloadBuilder::new()
            .with_response_and_max_size(
                settings.query_stats_payload_to_return,
                settings.expected_query_stats_size_limit,
            );

        PayloadBuilderImpl::new(
            subnet_test_id(0),
            node_test_id(0),
            registry,
            Arc::new(ingress_selector),
            Arc::new(xnet_payload_builder),
            Arc::new(self_validating_payload_builder),
            Arc::new(canister_http_payload_builder),
            Arc::new(query_stats_payload_builder),
            Arc::new(vetkd_payload_builder),
            MetricsRegistry::new(),
            no_op_logger(),
        )
    }
}
