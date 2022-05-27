//! Payload creation/validation subcomponent

use crate::consensus::{
    block_maker::SubnetRecords, metrics::PayloadBuilderMetrics, payload::BatchPayloadSectionBuilder,
};
use ic_interfaces::{
    canister_http::CanisterHttpPayloadBuilder,
    consensus::{PayloadPermanentError, PayloadTransientError, PayloadValidationError},
    ingress_manager::IngressSelector,
    messaging::XNetPayloadBuilder,
    registry::RegistryClient,
    self_validating_payload::SelfValidatingPayloadBuilder,
    validation::{ValidationError, ValidationResult},
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::Payload,
    messages::MAX_XNET_PAYLOAD_IN_BYTES,
    Height, NumBytes, SubnetId, Time,
};
use std::sync::Arc;

/// The [`PayloadBuilder`] is responsible for creating and validating payload that
/// is included in consensus blocks.
pub trait PayloadBuilder: Send + Sync {
    /// Produces a payload that is valid given `past_payloads` and `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn get_payload(
        &self,
        height: Height,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
        subnet_records: &SubnetRecords,
    ) -> BatchPayload;

    /// Checks whether the provided `payload` is valid given `past_payloads` and
    /// `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn validate_payload(
        &self,
        height: Height,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> ValidationResult<PayloadValidationError>;
}

/// Implementation of PayloadBuilder.
pub struct PayloadBuilderImpl {
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    section_builder: Vec<BatchPayloadSectionBuilder>,
    metrics: PayloadBuilderMetrics,
    logger: ReplicaLogger,
}

impl PayloadBuilderImpl {
    /// Helper to create PayloadBuilder
    pub fn new(
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        ingress_selector: Arc<dyn IngressSelector>,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
        canister_http_payload_builder: Arc<dyn CanisterHttpPayloadBuilder>,
        metrics: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let section_builder = vec![
            BatchPayloadSectionBuilder::Ingress(ingress_selector),
            BatchPayloadSectionBuilder::SelfValidating(self_validating_payload_builder),
            BatchPayloadSectionBuilder::XNet(xnet_payload_builder),
            BatchPayloadSectionBuilder::CanisterHttp(canister_http_payload_builder),
        ];

        Self {
            subnet_id,
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
        // as payload builders that yield a lot always give precendence to the
        // same next payload builder. This might give an advantage to a particular
        // payload builder.
        let num_sections = self.section_builder.len();
        let mut section_select = (0..num_sections).collect::<Vec<_>>();
        section_select.rotate_right(height.get() as usize % num_sections);

        let max_block_payload_size = self
            .get_max_block_payload_size_bytes(&subnet_records.stable)
            .get();

        let mut batch_payload = BatchPayload::default();
        let mut accumulated_size = 0;

        for section_id in section_select {
            accumulated_size += self.section_builder[section_id]
                .build_payload(
                    &mut batch_payload,
                    height,
                    context,
                    NumBytes::new(max_block_payload_size.saturating_sub(accumulated_size)),
                    section_id,
                    past_payloads,
                )
                .get();
        }

        batch_payload
    }

    fn validate_payload(
        &self,
        height: Height,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> ValidationResult<PayloadValidationError> {
        let _timer = self.metrics.validate_payload_duration.start_timer();
        if payload.is_summary() {
            return Ok(());
        }
        let batch_payload = &payload.as_ref().as_data().batch;

        // Retrieve max_block_payload_size from subnet
        let max_block_payload_size = match self
            .registry_client
            .get_subnet_record(self.subnet_id, context.registry_version)
        {
            Err(err) => {
                warn!(self.logger, "Failed to get subnet record in block_maker");
                return Err(ValidationError::Transient(
                    PayloadTransientError::RegistryUnavailable(err),
                ));
            }
            Ok(None) => {
                warn!(
                    self.logger,
                    "Subnet id {:?} not found in registry", self.subnet_id
                );
                return Err(ValidationError::Transient(
                    PayloadTransientError::SubnetNotFound(self.subnet_id),
                ));
            }
            Ok(Some(subnet_record)) => self.get_max_block_payload_size_bytes(&subnet_record),
        };

        let mut accumulated_size = NumBytes::new(0);
        for builder in &self.section_builder {
            accumulated_size +=
                builder.validate_payload(height, batch_payload, context, past_payloads)?;
            if accumulated_size > max_block_payload_size {
                return Err(ValidationError::Permanent(
                    PayloadPermanentError::PayloadTooBig {
                        expected: max_block_payload_size,
                        received: accumulated_size,
                    },
                ));
            }
        }
        Ok(())
    }
}

impl PayloadBuilderImpl {
    /// Returns the valid maximum block payload length from the registry and
    /// checks the invariants. Emits a warning in case the invariants are not
    /// met.
    fn get_max_block_payload_size_bytes(&self, subnet_record: &SubnetRecord) -> NumBytes {
        let required_min_size = MAX_XNET_PAYLOAD_IN_BYTES
            .get()
            .max(subnet_record.max_ingress_bytes_per_message);

        let mut max_block_payload_size = subnet_record.max_block_payload_size;
        // In any case, ensure the value is bigger than inter canister payload and
        // message size
        if max_block_payload_size < required_min_size {
            warn!(every_n_seconds => 300, self.logger,
                "max_block_payload_size too small. current value: {}, required minimum: {}! \
                max_block_payload_size must be larger than max_ingress_bytes_per_message \
                and MAX_XNET_PAYLOAD_IN_BYTES. Update registry!",
                max_block_payload_size, required_min_size);
            max_block_payload_size = required_min_size;
        }

        NumBytes::new(max_block_payload_size)
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::consensus::mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_btc_types_internal::{
        BitcoinAdapterResponse, BitcoinAdapterResponseWrapper, GetSuccessorsResponse,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        canister_http::FakeCanisterHttpPayloadBuilder,
        consensus::fake::Fake,
        ingress_selector::FakeIngressSelector,
        mock_time,
        self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
        types::ids::{node_test_id, subnet_test_id},
        types::messages::SignedIngressBuilder,
        xnet_payload_builder::FakeXNetPayloadBuilder,
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::{
        canister_http::CanisterHttpResponseWithConsensus,
        consensus::{
            certification::{Certification, CertificationContent},
            dkg::Dealings,
            BlockPayload, DataPayload, Payload,
        },
        crypto::{CryptoHash, Signed},
        messages::SignedIngress,
        signature::ThresholdSignature,
        xnet::CertifiedStreamSlice,
        CryptoHashOfPartialState, RegistryVersion,
    };
    use std::collections::BTreeMap;
    /// Builds a `PayloadBuilderImpl` wrapping fake ingress and XNet payload
    /// builders that return the supplied ingress and XNet data.
    fn make_test_payload_impl(
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

        PayloadBuilderImpl::new(
            subnet_test_id(0),
            registry,
            Arc::new(ingress_selector),
            Arc::new(xnet_payload_builder),
            Arc::new(self_validating_payload_builder),
            Arc::new(canister_http_payload_builder),
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

    /// Wraps a `BatchPayload` into the full `Payload` structure.
    fn wrap_batch_payload(height: u64, payload: BatchPayload) -> Payload {
        Payload::new(
            ic_crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: payload,
                dealings: Dealings::new_empty(Height::from(height)),
                ecdsa: None,
            }),
        )
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
                time: mock_time(),
            };
            let subnet_record = SubnetRecordBuilder::from(&[node_test_id(0)]).build();
            let subnet_records = SubnetRecords {
                latest: subnet_record.clone(),
                stable: subnet_record,
            };

            let (ingress_msgs, stream_msgs, responses_from_adapter) = payload_builder
                .get_payload(Height::from(1), &prev_payloads, &context, &subnet_records)
                .into_messages()
                .unwrap();

            assert_eq!(ingress_msgs, provided_ingress_messages);
            assert_eq!(stream_msgs, provided_certified_streams);
            assert_eq!(responses_from_adapter, provided_responses_from_adapter);
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
                GetSuccessorsResponse::default(),
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

    /// This test executes the `get_payload` and `validate_payload` functions
    /// in `PayloadBuilderImpl`.
    /// It builds the following blocks:
    /// - 3/4 of size is `XNetPayload`, 1/4 `IngressPayload`. Expected to pass validation.
    /// - 1/4 of size is `XNetPayload`, 3/4 `IngressPayload`. Expected to pass validation.
    /// - 3/4 of size is `XNetPayload`, 3/4 `IngressPayload`. Expected to fail validation.
    /// - 6/4 of size is `XNetPayload`, Expected to pass (with warning).
    #[test]
    fn test_payload_size_validation() {
        const MAX_SIZE: u64 = 2 * 1024 * 1024;
        // NOTE: Since the messages will also contain headers, the payload needs to be a
        // little bit smaller than the overall size
        const ONE_QUARTER: usize = 512 * 1024 - 1000;
        const THREE_QUARTER: usize = 3 * 512 * 1024 - 1000;

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut subnet_record = SubnetRecordBuilder::from(&[node_test_id(0)]).build();
            // NOTE: We can't set smaller values
            subnet_record.max_block_payload_size = MAX_SIZE;
            subnet_record.max_ingress_bytes_per_message = MAX_SIZE;

            let subnet_records = SubnetRecords {
                latest: subnet_record.clone(),
                stable: subnet_record.clone(),
            };

            let Dependencies { registry, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(1, subnet_record)],
            );
            let context = ValidationContext {
                certified_height: Height::from(0),
                registry_version: RegistryVersion::from(1),
                time: mock_time(),
            };

            // Prepare the messages in the mock
            let make_ingress = |nonce, size| {
                vec![SignedIngressBuilder::new()
                    .method_payload(vec![0; size])
                    .nonce(nonce)
                    .build()]
            };
            let make_slice = |height, size| {
                let mut map = BTreeMap::new();
                map.insert(
                    subnet_test_id(1),
                    make_certified_stream_slice(height, vec![0; size], vec![]),
                );
                map
            };
            let certified_streams: Vec<BTreeMap<SubnetId, CertifiedStreamSlice>> = vec![
                make_slice(0, THREE_QUARTER),
                make_slice(1, ONE_QUARTER),
                make_slice(2, THREE_QUARTER),
                make_slice(3, 2 * THREE_QUARTER),
            ];
            let ingress = vec![
                make_ingress(0, ONE_QUARTER),
                make_ingress(1, THREE_QUARTER),
                make_ingress(2, THREE_QUARTER),
                // No ingress for third block
            ];
            let payload_builder =
                make_test_payload_impl(registry, ingress, certified_streams, vec![], vec![]);

            // Build first payload and then validate it
            let payload0 =
                payload_builder.get_payload(Height::from(0), &[], &context, &subnet_records);
            let wrapped_payload0 = wrap_batch_payload(0, payload0);
            payload_builder
                .validate_payload(Height::from(0), &wrapped_payload0, &[], &context)
                .unwrap();

            // Build second payload and validate it
            let past_payload0 = [(Height::from(0), mock_time(), wrapped_payload0)];
            let payload1 = payload_builder.get_payload(
                Height::from(1),
                &past_payload0,
                &context,
                &subnet_records,
            );
            let wrapped_payload1 = wrap_batch_payload(0, payload1);
            payload_builder
                .validate_payload(Height::from(1), &wrapped_payload1, &past_payload0, &context)
                .unwrap();

            // Build third payload and validate it
            // This payload is oversized, therefore we expect the validator to fail
            let past_payload1 = [(Height::from(1), mock_time(), wrapped_payload1)];
            let payload2 = payload_builder.get_payload(
                Height::from(2),
                &past_payload1,
                &context,
                &subnet_records,
            );
            let wrapped_payload2 = wrap_batch_payload(1, payload2);

            let pb_result = payload_builder.validate_payload(
                Height::from(2),
                &wrapped_payload2,
                &past_payload1,
                &context,
            );

            match pb_result {
                Err(
                    ValidationError::<PayloadPermanentError, PayloadTransientError>::Permanent(
                        PayloadPermanentError::PayloadTooBig { .. },
                    ),
                ) => (),
                _ => panic!("Expected PayloadTooBig error"),
            }
        });
    }
}
