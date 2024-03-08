use std::collections::{BTreeMap, BTreeSet};

use ic_error_types::RejectCode;
use ic_logger::{debug, ReplicaLogger};
use ic_management_canister_types::{EcdsaKeyId, Payload, SignWithECDSAReply};
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_types::{
    consensus::ecdsa,
    crypto::canister_threshold_sig::ExtendedDerivationPath,
    messages::{CallbackId, RejectContext},
    Time,
};
use phantom_newtype::Id;

use crate::{consensus::metrics::EcdsaPayloadMetrics, ecdsa::signer::EcdsaSignatureBuilder};

use super::EcdsaPayloadError;

/// Update signature agreements in the data payload by:
/// - dropping agreements that don't have a [SignWithEcdsaContext] anymore (because
///   the response has been delivered)
/// - setting remaining agreements to "Reported" (the signing response was delivered
///   in the previous round, the context will be removed when the previous block is
///   finalized)
/// - adding new agreements as "Unreported" by combining shares in the ECDSA pool.
pub(crate) fn update_signature_agreements(
    all_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    signature_builder: &dyn EcdsaSignatureBuilder,
    payload: &mut ecdsa::EcdsaPayload,
) {
    let all_random_ids = all_requests
        .iter()
        .map(|(callback_id, context)| (context.pseudo_random_id, (callback_id, context)))
        .collect::<BTreeMap<_, _>>();
    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    let mut new_agreements = BTreeMap::new();
    let mut old_agreements = BTreeMap::new();
    std::mem::swap(&mut payload.signature_agreements, &mut old_agreements);
    for (random_id, _) in old_agreements.into_iter() {
        if all_random_ids.get(&random_id).is_some() {
            new_agreements.insert(random_id, ecdsa::CompletedSignature::ReportedToExecution);
        }
    }
    payload.signature_agreements = new_agreements;

    // Then we collect new signatures into the signature_agreements
    let mut completed = BTreeMap::new();
    for request_id in payload.ongoing_signatures.keys() {
        let Some((callback_id, context)) = all_random_ids.get(&request_id.pseudo_random_id) else {
            continue;
        };

        let Some(signature) = signature_builder.get_completed_signature(request_id) else {
            continue;
        };

        let response = ic_types::messages::Response {
            originator: context.request.sender,
            respondent: ic_types::CanisterId::ic_00(),
            originator_reply_callback: **callback_id,
            // Execution is responsible for burning the appropriate cycles
            // before pushing the new context, so any remaining cycles can
            // be refunded to the canister.
            refund: context.request.payment,
            response_payload: ic_types::messages::Payload::Data(
                SignWithECDSAReply {
                    signature: signature.signature.clone(),
                }
                .encode(),
            ),
            // Not relevant, the consensus queue is flushed every round by the
            // scheduler, which uses only the payload and originator callback.
            deadline: context.request.deadline,
        };

        completed.insert(
            request_id.clone(),
            ecdsa::CompletedSignature::Unreported(response),
        );
    }

    for (request_id, signature) in completed {
        payload.ongoing_signatures.remove(&request_id);
        payload
            .signature_agreements
            .insert(request_id.pseudo_random_id, signature);
    }
}

/// For every new signing request, we only start to work on them if
/// their matched quadruple has been fully produced.
pub(crate) fn update_ongoing_signatures(
    new_requests: BTreeMap<ecdsa::RequestId, &SignWithEcdsaContext>,
    max_ongoing_signatures: u32,
    payload: &mut ecdsa::EcdsaPayload,
    log: &ReplicaLogger,
) -> Result<(), EcdsaPayloadError> {
    if let Some(key_transcript) = &payload.key_transcript.current {
        debug!(
            log,
            "update_ongoing_signatures: number of new_requests={}",
            new_requests.len()
        );
        for (request_id, context) in new_requests.into_iter() {
            if (payload.ongoing_signatures.len() as u32) >= max_ongoing_signatures {
                return Ok(());
            }
            if let Some(quadruple) = payload
                .available_quadruples
                .remove(&request_id.quadruple_id)
            {
                let sign_inputs = build_signature_inputs(context, &quadruple, key_transcript);
                payload.ongoing_signatures.insert(request_id, sign_inputs);
            }
        }
    }
    Ok(())
}

/// Helper to create a reject response to the management canister
/// with the given code and message
fn reject_response(
    callback_id: CallbackId,
    context: &SignWithEcdsaContext,
    code: RejectCode,
    message: impl ToString,
) -> ic_types::messages::Response {
    ic_types::messages::Response {
        originator: context.request.sender,
        respondent: ic_types::CanisterId::ic_00(),
        originator_reply_callback: callback_id,
        refund: context.request.payment,
        response_payload: ic_types::messages::Payload::Reject(RejectContext::new(code, message)),
        // Not relevant, the consensus queue is flushed every round by the
        // scheduler, which uses only the payload and originator callback.
        deadline: context.request.deadline,
    }
}

/// Update signature agreements in the data payload by:
/// - dropping agreements that don't have a [SignWithEcdsaContext] anymore (because
///   the response has been delivered)
/// - setting remaining agreements to "Reported" (the signing response was delivered
///   in the previous round, the context will be removed when the previous block is
///   finalized)
/// - rejecting signature contexts that are expired or request an invalid key.
/// - adding new agreements as "Unreported" by combining shares in the ECDSA pool.
pub(crate) fn update_signature_agreements_improved_latency(
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
                    context,
                    RejectCode::CanisterReject,
                    format!(
                        "Invalid or disabled key_id in signature request: {:?}",
                        context.key_id
                    ),
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
                    context,
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
                    context,
                    RejectCode::CanisterError,
                    "Signature request was matched to non-existent pre-signature.",
                )),
            );

            if let Some(metrics) = ecdsa_payload_metrics {
                metrics.payload_errors_inc("missing_pre_signature");
            }

            continue;
        }

        let Some(signature) = signature_builder.get_completed_signature_from_context(context)
        else {
            continue;
        };

        let response = ic_types::messages::Response {
            originator: context.request.sender,
            respondent: ic_types::CanisterId::ic_00(),
            originator_reply_callback: *callback_id,
            // Execution is responsible for burning the appropriate cycles
            // before pushing the new context, so any remaining cycles can
            // be refunded to the canister.
            refund: context.request.payment,
            response_payload: ic_types::messages::Payload::Data(
                SignWithECDSAReply {
                    signature: signature.signature.clone(),
                }
                .encode(),
            ),
            // Not relevant, the consensus queue is flushed every round by the
            // scheduler, which uses only the payload and originator callback.
            deadline: context.request.deadline,
        };
        payload.signature_agreements.insert(
            context.pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(response),
        );
        payload.available_quadruples.remove(quadruple_id);
    }
}

/// Helper to build threshold signature inputs from the context and
/// the pre-signature quadruple
pub(crate) fn build_signature_inputs(
    context: &SignWithEcdsaContext,
    quadruple_ref: &ecdsa::PreSignatureQuadrupleRef,
    key_transcript_ref: &ecdsa::UnmaskedTranscriptWithAttributes,
) -> ecdsa::ThresholdEcdsaSigInputsRef {
    let extended_derivation_path = ExtendedDerivationPath {
        caller: context.request.sender.into(),
        derivation_path: context.derivation_path.clone(),
    };
    ecdsa::ThresholdEcdsaSigInputsRef::new(
        extended_derivation_path,
        context.message_hash,
        Id::from(context.pseudo_random_id),
        quadruple_ref.clone(),
        key_transcript_ref.unmasked_transcript(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use assert_matches::assert_matches;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_types::{
        consensus::ecdsa::{EcdsaPayload, RequestId},
        crypto::canister_threshold_sig::ThresholdEcdsaCombinedSignature,
        Height,
    };

    use crate::ecdsa::{
        payload_builder::{
            get_signing_requests, quadruples::test_utils::create_available_quadruple,
        },
        test_utils::{
            empty_ecdsa_payload, empty_response, fake_completed_sign_with_ecdsa_context,
            fake_sign_with_ecdsa_context, fake_sign_with_ecdsa_context_with_quadruple,
            set_up_ecdsa_payload, TestEcdsaSignatureBuilder,
        },
    };

    use super::*;

    fn set_up(
        should_create_key_transcript: bool,
        pseudo_random_ids: Vec<[u8; 32]>,
    ) -> (EcdsaPayload, BTreeMap<CallbackId, SignWithEcdsaContext>) {
        let mut rng = reproducible_rng();
        let (ecdsa_payload, _env, _block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            should_create_key_transcript,
        );

        let mut contexts = BTreeMap::new();
        for (index, pseudo_random_id) in pseudo_random_ids.into_iter().enumerate() {
            contexts.insert(
                CallbackId::from(index as u64),
                fake_sign_with_ecdsa_context(
                    ecdsa_payload.key_transcript.key_id.clone(),
                    pseudo_random_id,
                ),
            );
        }

        (ecdsa_payload, contexts)
    }

    fn create_request_id_with_available_quadruple(
        ecdsa_payload: &mut EcdsaPayload,
        key_id: EcdsaKeyId,
        pseudo_random_id: [u8; 32],
    ) -> ecdsa::RequestId {
        let quadruple_id = create_available_quadruple(ecdsa_payload, key_id, pseudo_random_id[0]);

        ecdsa::RequestId {
            quadruple_id,
            pseudo_random_id,
            height: Height::from(0),
        }
    }

    fn pseudo_random_id(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn test_get_signing_requests_returns_nothing_when_no_quadruples_available() {
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            /*pseudo_random_ids=*/ vec![],
        );
        let valid_key_ids = BTreeSet::from([ecdsa_payload.key_transcript.key_id.clone()]);

        let result = get_signing_requests(
            Height::from(1),
            /*request_expiry_time=*/ None,
            &mut ecdsa_payload,
            &contexts,
            &valid_key_ids,
            /*ecdsa_payload_metrics=*/ None,
        );

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_signing_requests() {
        let height = Height::new(789);
        let pseudo_random_id = pseudo_random_id(0);
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            /*pseudo_random_ids=*/ vec![pseudo_random_id],
        );
        let valid_key_id = ecdsa_payload.key_transcript.key_id.clone();
        let valid_key_ids = BTreeSet::from([valid_key_id.clone()]);
        // Add a quadruple
        let quadruple_id = create_available_quadruple(&mut ecdsa_payload, valid_key_id.clone(), 10);
        let _quadruple_id_2 =
            create_available_quadruple(&mut ecdsa_payload, valid_key_id.clone(), 11);

        let signing_requests = get_signing_requests(
            height,
            /*request_expiry_time=*/ None,
            &mut ecdsa_payload,
            &contexts,
            &valid_key_ids,
            /*ecdsa_payload_metrics=*/ None,
        );

        assert_eq!(signing_requests.len(), 1);
        // Check if it is matched with the smaller quadruple ID
        assert_eq!(
            *signing_requests.keys().next().unwrap(),
            ecdsa::RequestId {
                quadruple_id,
                pseudo_random_id,
                height,
            }
        );
    }

    #[test]
    fn test_update_ongoing_signatures_returns_nothing_when_no_created_keys() {
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ false,
            /*pseudo_random_ids=*/ vec![pseudo_random_id(0), pseudo_random_id(1)],
        );
        let key_id = ecdsa_payload.key_transcript.key_id.clone();
        let mut requests = BTreeMap::new();
        for context in contexts.values() {
            let request_id = create_request_id_with_available_quadruple(
                &mut ecdsa_payload,
                key_id.clone(),
                context.pseudo_random_id,
            );

            requests.insert(request_id, context);
        }

        update_ongoing_signatures(
            requests,
            /*max_ongoing_signatures=*/ 10,
            &mut ecdsa_payload,
            &no_op_logger(),
        )
        .expect("Should successfully execute");

        assert!(ecdsa_payload.ongoing_signatures.is_empty());
        assert_eq!(ecdsa_payload.available_quadruples.len(), 2);
    }

    #[test]
    fn test_update_ongoing_signatures_respects_max_ongoing_signatures() {
        let contexts_count: usize = 10;
        let max_ongoing_signatures: usize = 6;
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            /*pseudo_random_ids=*/
            (0..contexts_count)
                .map(|i| pseudo_random_id(i as u8))
                .collect(),
        );
        let key_id = ecdsa_payload.key_transcript.key_id.clone();
        let mut requests = BTreeMap::new();
        for context in contexts.values() {
            let request_id = create_request_id_with_available_quadruple(
                &mut ecdsa_payload,
                key_id.clone(),
                context.pseudo_random_id,
            );

            requests.insert(request_id, context);
        }

        update_ongoing_signatures(
            requests,
            max_ongoing_signatures as u32,
            &mut ecdsa_payload,
            &no_op_logger(),
        )
        .expect("Should successfully execute");

        assert_eq!(
            ecdsa_payload.ongoing_signatures.len(),
            max_ongoing_signatures
        );
        assert_eq!(
            ecdsa_payload.available_quadruples.len(),
            contexts_count - max_ongoing_signatures
        );
    }

    #[test]
    fn test_update_signature_agreements() {
        let delivered_pseudo_random_id = pseudo_random_id(0);
        let old_pseudo_random_id = pseudo_random_id(1);
        let new_pseudo_random_id = pseudo_random_id(2);
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            vec![old_pseudo_random_id, new_pseudo_random_id],
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
            &mut ecdsa_payload,
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
    fn test_update_signature_agreements_reporting_improved_latency() {
        let delivered_pseudo_random_id = pseudo_random_id(0);
        let old_pseudo_random_id = pseudo_random_id(1);
        let new_pseudo_random_id = pseudo_random_id(2);
        let (mut ecdsa_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            vec![old_pseudo_random_id, new_pseudo_random_id],
        );
        ecdsa_payload.signature_agreements.insert(
            delivered_pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        ecdsa_payload.signature_agreements.insert(
            old_pseudo_random_id,
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        let key_id = ecdsa_payload.key_transcript.key_id.clone();

        // old signature in the agreement AND in state is replaced by `ReportedToExecution`
        // old signature in the agreement but NOT in state is removed.
        update_signature_agreements_improved_latency(
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
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let key_id = ecdsa_payload.key_transcript.key_id.clone();
        let valid_keys = BTreeSet::from_iter([key_id.clone()]);
        let quadruple_ids = (0..4)
            .map(|i| create_available_quadruple(&mut ecdsa_payload, key_id.clone(), i as u8))
            .collect::<Vec<_>>();
        let missing_quadruple = ecdsa_payload
            .uid_generator
            .next_quadruple_id(key_id.clone());

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
        update_signature_agreements_improved_latency(
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
        assert_matches!(
            &response_1.response_payload,
            ic_types::messages::Payload::Data(_)
        );

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
            &response_3.response_payload,
            ic_types::messages::Payload::Reject(context)
            if context.message().contains("matched to non-existent pre-signature")
        );
    }
}
