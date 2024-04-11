use std::collections::{BTreeMap, BTreeSet};

use ic_error_types::RejectCode;
use ic_management_canister_types::{EcdsaKeyId, Payload, SignWithECDSAReply};
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_types::{
    consensus::ecdsa,
    messages::{CallbackId, RejectContext},
    Time,
};

use crate::{consensus::metrics::EcdsaPayloadMetrics, ecdsa::signer::EcdsaSignatureBuilder};

/// Helper to create a reject response to the management canister
/// with the given code and message
fn reject_response(
    callback_id: CallbackId,
    code: RejectCode,
    message: impl ToString,
) -> ic_types::batch::ConsensusResponse {
    ic_types::batch::ConsensusResponse::new(
        callback_id,
        ic_types::messages::Payload::Reject(RejectContext::new(code, message)),
    )
}

/// Update signature agreements in the data payload by:
/// - dropping agreements that don't have a [SignWithEcdsaContext] anymore (because
///   the response has been delivered)
/// - setting remaining agreements to "Reported" (the signing response was delivered
///   in the previous round, the context will be removed when the previous block is
///   finalized)
/// - rejecting signature contexts that are expired or request an invalid key.
/// - adding new agreements as "Unreported" by combining shares in the ECDSA pool.
pub(crate) fn update_signature_agreements(
    all_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    signature_builder: &dyn EcdsaSignatureBuilder,
    request_expiry_time: Option<Time>,
    payload: &mut ecdsa::EcdsaPayload,
    valid_keys: &BTreeSet<EcdsaKeyId>,
    ecdsa_payload_metrics: Option<&EcdsaPayloadMetrics>,
) {
    let all_random_ids = all_requests
        .iter()
        .map(|(_, context)| context.pseudo_random_id)
        .collect::<BTreeSet<_>>();

    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    payload.signature_agreements = payload
        .signature_agreements
        .keys()
        .filter(|random_id| all_random_ids.contains(*random_id))
        .map(|random_id| (*random_id, ecdsa::CompletedSignature::ReportedToExecution))
        .collect();

    // Then we collect new signatures into the signature_agreements
    for (callback_id, context) in all_requests {
        if payload
            .signature_agreements
            .contains_key(&context.pseudo_random_id)
        {
            continue;
        }
        if !valid_keys.contains(&context.key_id) {
            // Reject new requests with unknown key Ids.
            // Note that no quadruples are consumed at this stage.
            payload.signature_agreements.insert(
                context.pseudo_random_id,
                ecdsa::CompletedSignature::Unreported(reject_response(
                    *callback_id,
                    RejectCode::CanisterReject,
                    format!("Invalid key_id in signature request: {:?}", context.key_id),
                )),
            );

            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("invalid_keyid_requests");
            }
            continue;
        }

        // We can only remove expired requests once they were matched with a
        // quadruple. Otherwise the context may be matched with a quadruple
        // at the next certified state height, which then wouldn't be removed.
        let Some((quadruple_id, _)) = context.matched_quadruple.as_ref() else {
            continue;
        };

        if request_expiry_time.is_some_and(|expiry| context.batch_time < expiry) {
            payload.signature_agreements.insert(
                context.pseudo_random_id,
                ecdsa::CompletedSignature::Unreported(reject_response(
                    *callback_id,
                    RejectCode::CanisterError,
                    "Signature request expired",
                )),
            );
            payload.available_quadruples.remove(quadruple_id);

            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("expired_requests");
            }

            continue;
        }

        // In case of subnet recoveries, available quadruples are purged.
        // This means that pre-existing requests that were already matched
        // cannot be completed, and we should reject them.
        if !payload.available_quadruples.contains_key(quadruple_id) {
            payload.signature_agreements.insert(
                context.pseudo_random_id,
                ecdsa::CompletedSignature::Unreported(reject_response(
                    *callback_id,
                    RejectCode::CanisterError,
                    "Signature request was matched to non-existent pre-signature.",
                )),
            );

            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("missing_pre_signature");
            }

            continue;
        }

        let Some(signature) = signature_builder.get_completed_signature(context) else {
            continue;
        };

        let response = ic_types::batch::ConsensusResponse::new(
            *callback_id,
            ic_types::messages::Payload::Data(
                SignWithECDSAReply {
                    signature: signature.signature.clone(),
                }
                .encode(),
            ),
        );
        payload.signature_agreements.insert(
            context.pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(response),
        );
        payload.available_quadruples.remove(quadruple_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use assert_matches::assert_matches;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        consensus::ecdsa::{EcdsaPayload, RequestId},
        crypto::canister_threshold_sig::ThresholdEcdsaCombinedSignature,
        Height,
    };

    use crate::ecdsa::{
        payload_builder::quadruples::test_utils::create_available_quadruple,
        test_utils::{
            empty_ecdsa_payload_with_key_ids, empty_response,
            fake_completed_sign_with_ecdsa_context, fake_ecdsa_key_id,
            fake_sign_with_ecdsa_context, fake_sign_with_ecdsa_context_with_quadruple,
            set_up_ecdsa_payload, TestEcdsaSignatureBuilder,
        },
    };

    use super::*;

    fn set_up(
        should_create_key_transcript: bool,
        pseudo_random_ids: Vec<[u8; 32]>,
        ecdsa_key_id: EcdsaKeyId,
    ) -> (EcdsaPayload, BTreeMap<CallbackId, SignWithEcdsaContext>) {
        let mut rng = reproducible_rng();
        let (ecdsa_payload, _env, _block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            vec![ecdsa_key_id.clone()],
            should_create_key_transcript,
        );

        let mut contexts = BTreeMap::new();
        for (index, pseudo_random_id) in pseudo_random_ids.into_iter().enumerate() {
            contexts.insert(
                CallbackId::from(index as u64),
                fake_sign_with_ecdsa_context(ecdsa_key_id.clone(), pseudo_random_id),
            );
        }

        (ecdsa_payload, contexts)
    }

    fn pseudo_random_id(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn test_update_signature_agreements_reporting() {
        let delivered_pseudo_random_id = pseudo_random_id(0);
        let old_pseudo_random_id = pseudo_random_id(1);
        let new_pseudo_random_id = pseudo_random_id(2);
        let key_id = fake_ecdsa_key_id();
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            vec![old_pseudo_random_id, new_pseudo_random_id],
            key_id.clone(),
        );
        ecdsa_payload.signature_agreements.insert(
            delivered_pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        ecdsa_payload.signature_agreements.insert(
            old_pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );

        // old signature in the agreement AND in state is replaced by `ReportedToExecution`
        // old signature in the agreement but NOT in state is removed.
        update_signature_agreements(
            &contexts,
            &TestEcdsaSignatureBuilder::new(),
            None,
            &mut ecdsa_payload,
            &BTreeSet::from([key_id]),
            None,
        );

        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        assert_eq!(
            ecdsa_payload.signature_agreements,
            BTreeMap::from([(
                old_pseudo_random_id,
                ecdsa::CompletedSignature::ReportedToExecution
            )])
        );
    }

    #[test]
    fn test_ecdsa_update_signature_agreements_success() {
        let subnet_id = subnet_test_id(0);
        let key_id = fake_ecdsa_key_id();
        let mut ecdsa_payload = empty_ecdsa_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let valid_keys = BTreeSet::from_iter([key_id.clone()]);
        let quadruple_ids = (0..4)
            .map(|i| create_available_quadruple(&mut ecdsa_payload, key_id.clone(), i as u8))
            .collect::<Vec<_>>();
        let missing_quadruple = ecdsa_payload.uid_generator.next_quadruple_id();

        let contexts = BTreeMap::from([
            // insert request without completed signature
            fake_completed_sign_with_ecdsa_context(0, quadruple_ids[0].clone()),
            // insert request to be completed
            fake_completed_sign_with_ecdsa_context(1, quadruple_ids[1].clone()),
            // insert request that was already completed
            fake_completed_sign_with_ecdsa_context(2, quadruple_ids[2].clone()),
            // insert request without a matched quadruple
            fake_sign_with_ecdsa_context_with_quadruple(3, key_id.clone(), None),
            // insert request matched to a non-existent quadruple
            fake_sign_with_ecdsa_context_with_quadruple(4, key_id.clone(), Some(missing_quadruple)),
        ]);

        // insert agreement for completed request
        ecdsa_payload.signature_agreements.insert(
            [2; 32],
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );

        let mut signature_builder = TestEcdsaSignatureBuilder::new();
        for (i, id) in quadruple_ids.iter().enumerate().skip(1) {
            signature_builder.signatures.insert(
                RequestId {
                    quadruple_id: id.clone(),
                    pseudo_random_id: [i as u8; 32],
                    height: Height::from(1),
                },
                ThresholdEcdsaCombinedSignature {
                    signature: vec![i as u8; 32],
                },
            );
        }

        // Only the uncompleted request with available quadruple should be completed
        update_signature_agreements(
            &contexts,
            &signature_builder,
            None,
            &mut ecdsa_payload,
            &valid_keys,
            None,
        );

        // Only the quadruple for the completed request should be removed
        assert_eq!(ecdsa_payload.available_quadruples.len(), 3);
        assert!(!ecdsa_payload
            .available_quadruples
            .contains_key(&quadruple_ids[1]));

        assert_eq!(ecdsa_payload.signature_agreements.len(), 3);
        let Some(ecdsa::CompletedSignature::Unreported(response_1)) =
            ecdsa_payload.signature_agreements.get(&[1; 32])
        else {
            panic!("Request 1 should have a response");
        };
        assert_matches!(&response_1.payload, ic_types::messages::Payload::Data(_));

        assert_matches!(
            ecdsa_payload.signature_agreements.get(&[2; 32]),
            Some(ecdsa::CompletedSignature::ReportedToExecution)
        );

        let Some(ecdsa::CompletedSignature::Unreported(response_3)) =
            ecdsa_payload.signature_agreements.get(&[4; 32])
        else {
            panic!("Request 3 should have a response");
        };
        assert_matches!(
            &response_3.payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("matched to non-existent pre-signature")
        );
    }
}
