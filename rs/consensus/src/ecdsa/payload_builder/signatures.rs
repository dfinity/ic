use std::collections::BTreeMap;

use ic_ic00_types::{Payload, SignWithECDSAReply};
use ic_logger::{debug, ReplicaLogger};
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_types::{
    consensus::ecdsa, crypto::canister_threshold_sig::ExtendedDerivationPath, messages::CallbackId,
};
use phantom_newtype::Id;

use crate::ecdsa::signer::EcdsaSignatureBuilder;

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
        let (callback_id, context) = match all_random_ids.get(&request_id.pseudo_random_id) {
            Some((callback_id, context)) => (callback_id, context),
            None => continue,
        };

        let signature = match signature_builder.get_completed_signature(request_id) {
            Some(signature) => signature,
            None => continue,
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
        };
        completed.insert(*request_id, ecdsa::CompletedSignature::Unreported(response));
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
    use std::{collections::BTreeSet, str::FromStr};

    use assert_matches::assert_matches;
    use ic_ic00_types::EcdsaKeyId;
    use ic_test_utilities::{
        mock_time,
        state::ReplicatedStateBuilder,
        types::{ids::subnet_test_id, messages::RequestBuilder},
    };
    use ic_types::Height;

    use crate::ecdsa::{
        payload_builder::get_signing_requests,
        test_utils::{
            create_sig_inputs, empty_ecdsa_payload, empty_response, TestEcdsaSignatureBuilder,
        },
    };

    use super::*;

    #[test]
    fn test_ecdsa_update_ongoing_signatures() {
        let subnet_id = subnet_test_id(1);
        let pseudo_random_id = [0; 32];
        let mut state = ReplicatedStateBuilder::default().build();
        let mut valid_keys = BTreeSet::new();
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        valid_keys.insert(key_id.clone());
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id,
                    pseudo_random_id,
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);
        let height = Height::from(1);
        let result = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
            None,
        );
        // Because there is no quadruples available, expect empty return
        assert!(result.is_empty());
        // Add a quadruple
        let sig_inputs = create_sig_inputs(10);
        let quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload
            .available_quadruples
            .insert(quadruple_id, quadruple_ref.clone());
        let sig_inputs = create_sig_inputs(11);
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload.available_quadruples.insert(
            ecdsa_payload.uid_generator.next_quadruple_id(),
            quadruple_ref.clone(),
        );
        let result = get_signing_requests(
            height,
            None,
            &mut ecdsa_payload,
            &state
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts,
            &valid_keys,
            None,
        );
        assert_eq!(result.len(), 1);
        // Check if it is matched with the smaller quadruple ID
        let request_id = &result.keys().next().unwrap().clone();
        assert_eq!(request_id.quadruple_id, quadruple_id);
    }

    #[test]
    fn test_ecdsa_update_signature_agreements() {
        let subnet_id = subnet_test_id(0);
        let mut state = ReplicatedStateBuilder::default().build();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(1),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    pseudo_random_id: [1; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .insert(
                CallbackId::from(2),
                SignWithEcdsaContext {
                    request: RequestBuilder::new().build(),
                    key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    pseudo_random_id: [2; 32],
                    message_hash: [0; 32],
                    derivation_path: vec![],
                    batch_time: mock_time(),
                },
            );
        let mut ecdsa_payload = empty_ecdsa_payload(subnet_id);

        let all_requests = &state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts;

        ecdsa_payload.signature_agreements.insert(
            [1; 32],
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        ecdsa_payload.signature_agreements.insert(
            [0; 32],
            ecdsa::CompletedSignature::Unreported(empty_response()),
        );
        let signature_builder = TestEcdsaSignatureBuilder::new();
        // old signature in the agreement AND in state is replaced by ReportedToExecution
        // old signature in the agreement but NOT in state is removed.
        update_signature_agreements(all_requests, &signature_builder, &mut ecdsa_payload);
        assert_eq!(ecdsa_payload.signature_agreements.len(), 1);
        assert_eq!(
            ecdsa_payload.signature_agreements.keys().next().unwrap(),
            &[1; 32],
        );
        assert_matches!(
            ecdsa_payload.signature_agreements.values().next().unwrap(),
            ecdsa::CompletedSignature::ReportedToExecution
        );
    }
}
