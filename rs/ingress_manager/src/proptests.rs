//! This module implements property tests for the ingress selector.
//!
//! The ingress selector, like all payload builders, has to fulfill the property that
//! all payloads built by the payload builder have to be valid.
//! Property tests can test this in the following way:
//! 1. Prop up a bunch of ingress messages and put them into the pool
//! 2. Run the payload builder on the pool
//! 3. Check that the produced payload is valid
//!
//! NOTE:
//! Since mocking up all properties of an ingress message opens a huge value space which would
//! be impossible to cover in any reasonable time.
//! We therefore build multiple proptests, where we keep most properties fixed and only leave a
//! small number of values variable.

use crate::tests::{access_ingress_pool, setup_with_params};
use ic_constants::MAX_INGRESS_TTL;
use ic_interfaces::{
    ingress_manager::IngressSelector,
    ingress_pool::ChangeAction,
    p2p::consensus::{MutablePool, UnvalidatedArtifact, ValidatedPoolReader},
    time_source::TimeSource,
};
use ic_test_utilities_state::{CanisterStateBuilder, ReplicatedStateBuilder};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::{
    ids::{canister_test_id, node_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    artifact::IngressMessageId, batch::ValidationContext, messages::SignedIngress,
    time::UNIX_EPOCH, CountBytes, Height, NumBytes, RegistryVersion,
};
use proptest::prelude::*;
use std::collections::HashSet;

const MAX_BLOCK_SIZE: u64 = 4 * 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_time: 60000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_ingress_payload_builder_size(singed_ingress_vec in prop_signed_ingress_vec_for_size_test()) {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time = UNIX_EPOCH;
                let time_source = FastForwardTimeSource::new();
                let validation_context = ValidationContext {
                    time: time + MAX_INGRESS_TTL,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                assert!(!singed_ingress_vec.is_empty());

                for m in singed_ingress_vec.iter() {
                    let message_id = IngressMessageId::from(m);
                    access_ingress_pool(&ingress_pool, |ingress_pool| {
                        ingress_pool.insert(UnvalidatedArtifact {
                            message: m.clone(),
                            peer_id: node_test_id(0),
                            timestamp: time_source.get_relative_time(),
                        });
                        ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(
                            message_id.clone(),
                        )]);
                        // check that message is indeed in the pool
                        assert!(ingress_pool.get(&message_id).is_some());
                    });
                }

                // Generate a payload out of the propped up ingress
                let payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_BLOCK_SIZE),
                );

                // Also in this test the payload must contain some ingress messages
                assert!(!payload.is_empty());

                // Check the size explicitly
                assert!((payload.count_bytes() as u64) < MAX_BLOCK_SIZE);

                // Any payload generated should pass verification.
                // If not, we have an issue with the payload builder
                assert!(ingress_manager.validate_ingress_payload(&payload, &HashSet::new(), &validation_context).is_ok());
            },
        )
    }


}

/// Props up a mock ingress message, which varies in size.
///
/// This is to be used in size tests.
fn prop_signed_ingress_for_size_test(
    min: usize,
    max: usize,
) -> impl Strategy<Value = SignedIngress> {
    any_with::<Vec<u8>>(prop::collection::size_range(min..max).lift()).prop_map(|method_payload| {
        SignedIngressBuilder::new()
            .canister_id(canister_test_id(0))
            .method_name("Size proptest")
            .method_payload(method_payload)
            .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
            .build()
    })
}

fn prop_signed_ingress_vec_for_size_test() -> impl Strategy<Value = Vec<SignedIngress>> {
    prop::collection::vec(prop_signed_ingress_for_size_test(0, 1024), 1..6000)
}
