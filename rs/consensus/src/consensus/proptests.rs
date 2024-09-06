use crate::consensus::payload_builder::test::make_test_payload_impl;
use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
use ic_interfaces::{batch_payload::ProposalContext, consensus::PayloadBuilder};
use ic_test_utilities_consensus::fake::Fake;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{
        block_maker::SubnetRecords,
        certification::{Certification, CertificationContent},
        dkg::Dealings,
        BlockPayload, DataPayload, Payload,
    },
    crypto::{CryptoHash, Signed},
    messages::SignedIngress,
    signature::ThresholdSignature,
    time::UNIX_EPOCH,
    xnet::CertifiedStreamSlice,
    CryptoHashOfPartialState, Height, RegistryVersion, SubnetId,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

const MAX_MESSAGES: usize = 10;
const MAX_SIZE: usize = 5 * 1024 * 1024;
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_time: 60000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_payload_size_validation(
        height in (0..10u64),
        ingress in prop_ingress_vec(MAX_MESSAGES, MAX_SIZE),
        xnet in prop_xnet_slice(MAX_MESSAGES, MAX_SIZE)) {
            proptest_round(height, ingress, xnet);
    }
}

fn proptest_round(
    height: u64,
    ingress: Vec<SignedIngress>,
    xnet: BTreeMap<SubnetId, CertifiedStreamSlice>,
) {
    ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
        let mut subnet_record = SubnetRecordBuilder::from(&[node_test_id(0)]).build();

        subnet_record.max_block_payload_size = MAX_BLOCK_SIZE as u64;
        subnet_record.max_ingress_bytes_per_message = MAX_BLOCK_SIZE as u64;

        let subnet_records = SubnetRecords {
            membership_version: subnet_record.clone(),
            context_version: subnet_record.clone(),
        };

        let Dependencies { registry, .. } = dependencies_with_subnet_params(
            pool_config,
            subnet_test_id(0),
            vec![(1, subnet_record)],
        );

        let validation_context = ValidationContext {
            certified_height: Height::from(height),
            registry_version: RegistryVersion::from(1),
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &validation_context,
        };

        let payload_builder =
            make_test_payload_impl(registry, vec![ingress], vec![xnet], vec![], vec![]);

        // Build the payload and validate it
        let payload =
            payload_builder.get_payload(Height::from(0), &[], &validation_context, &subnet_records);

        let wrapped_payload = wrap_batch_payload(0, payload);
        payload_builder
            .validate_payload(Height::from(0), &proposal_context, &wrapped_payload, &[])
            .unwrap();

        // Check that no critical errors occurred during the run.
        assert_eq!(payload_builder.count_critical_errors(), 0);
    });
}

/// Build a number of ingress messages
fn prop_ingress_vec(
    max_messages: usize,
    max_size: usize,
) -> impl Strategy<Value = Vec<SignedIngress>> {
    prop::collection::vec((0..max_size).prop_map(make_ingress), 1..max_messages)
}

fn make_ingress(size: usize) -> SignedIngress {
    SignedIngressBuilder::new()
        .method_payload(vec![0; size])
        .build()
}

fn prop_xnet_slice(
    max_messages: usize,
    max_size: usize,
) -> impl Strategy<Value = BTreeMap<SubnetId, CertifiedStreamSlice>> {
    prop::collection::btree_map(
        (0..3u64).prop_map(subnet_test_id),
        (0..max_size).prop_map(make_xnet_slice),
        1..max_messages,
    )
}

fn make_xnet_slice(size: usize) -> CertifiedStreamSlice {
    CertifiedStreamSlice {
        payload: vec![0; size],
        merkle_proof: vec![],
        certification: Certification {
            height: Height::from(0),
            signed: Signed {
                signature: ThresholdSignature::fake(),
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    vec![],
                ))),
            },
        },
    }
}

// TODO: Prop CanisterHttp
// TODO: Prop SelfValidatingPayload

/// Wraps a [`BatchPayload`] into the full [`Payload`] structure.
fn wrap_batch_payload(height: u64, payload: BatchPayload) -> Payload {
    Payload::new(
        ic_types::crypto::crypto_hash,
        BlockPayload::Data(DataPayload {
            batch: payload,
            dealings: Dealings::new_empty(Height::from(height)),
            idkg: None,
        }),
    )
}

#[test]
fn regression1() {
    let ingress = vec![make_ingress(965988), make_ingress(1019914)];
    let mut xnet = BTreeMap::new();
    xnet.insert(subnet_test_id(0), make_xnet_slice(1389926));
    xnet.insert(subnet_test_id(1), make_xnet_slice(818147));

    proptest_round(0, ingress, xnet);
}
