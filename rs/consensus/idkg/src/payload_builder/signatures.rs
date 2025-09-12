use crate::{metrics::IDkgPayloadMetrics, signer::ThresholdSignatureBuilder};
use ic_error_types::RejectCode;
use ic_management_canister_types_private::{Payload, SignWithECDSAReply, SignWithSchnorrReply};
use ic_replicated_state::metadata_state::subnet_call_context_manager::IDkgSignWithThresholdContext;
use ic_types::{
    Time,
    consensus::idkg::{self, IDkgMasterPublicKeyId, common::CombinedSignature},
    messages::{CallbackId, RejectContext},
};
use std::collections::{BTreeMap, BTreeSet};

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
/// - dropping agreements that don't have a [SignWithThresholdContext] anymore (because
///   the response has been delivered)
/// - setting remaining agreements to "Reported" (the signing response was delivered
///   in the previous round, the context will be removed when the previous block is
///   finalized)
/// - rejecting signature contexts that are expired or request an invalid key.
/// - adding new agreements as "Unreported" by combining shares in the IDKG pool.
pub(crate) fn update_signature_agreements(
    all_requests: &BTreeMap<CallbackId, IDkgSignWithThresholdContext<'_>>,
    signature_builder: &dyn ThresholdSignatureBuilder,
    request_expiry_time: Option<Time>,
    payload: &mut idkg::IDkgPayload,
    valid_keys: &BTreeSet<IDkgMasterPublicKeyId>,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    store_pre_signatures_in_state: bool,
) {
    let all_random_ids = all_requests
        .values()
        .map(|ctxt| ctxt.pseudo_random_id)
        .collect::<BTreeSet<_>>();

    // We first clean up the existing signature_agreements by keeping those
    // that can still be found in the signing_requests for dedup purpose.
    // We only need the "Reported" status because they would have already
    // been reported when the previous block become finalized.
    payload.signature_agreements = payload
        .signature_agreements
        .keys()
        .filter(|random_id| all_random_ids.contains(*random_id))
        .map(|random_id| (*random_id, idkg::CompletedSignature::ReportedToExecution))
        .collect();

    // Then we collect new signatures into the signature_agreements
    for (&callback_id, context) in all_requests {
        if payload
            .signature_agreements
            .contains_key(&context.pseudo_random_id)
        {
            continue;
        }
        if !valid_keys.contains(&context.key_id()) {
            // Reject new requests with unknown key Ids.
            // Note that no pre-signatures are consumed at this stage.
            payload.signature_agreements.insert(
                context.pseudo_random_id,
                idkg::CompletedSignature::Unreported(reject_response(
                    callback_id,
                    RejectCode::CanisterReject,
                    format!(
                        "Invalid key_id in signature request: {:?}",
                        context.key_id()
                    ),
                )),
            );

            if let Some(metrics) = idkg_payload_metrics {
                metrics.payload_errors_inc("invalid_keyid_requests");
            }
            continue;
        }

        let pre_sig_id = if !store_pre_signatures_in_state {
            // If pre-signatures are stored on the blockchain, then that means
            // we can only reject expired requests once the request was matched with a
            // pre-signature. Otherwise the context may be matched with a pre-signature
            // at a subsequent state height (before the rejection here is executed).
            // In that case, the pre-signature would not be removed from the payload,
            // and would be used again for a different request, which shouldn't to happen.
            match context.matched_pre_signature {
                Some((pre_sig_id, _)) => Some(pre_sig_id),
                None => continue,
            }
        } else {
            // If pre-signatures are stored in the state, then it is safe to reject
            // the request even if it hasn't been paired yet. While it may be paired
            // by the time this reject is executed, the paired pre-signature is consumed
            // from the stash, so there is no risk of using it again for a different
            // request.
            None
        };

        if request_expiry_time.is_some_and(|expiry| context.batch_time < expiry) {
            payload.signature_agreements.insert(
                context.pseudo_random_id,
                idkg::CompletedSignature::Unreported(reject_response(
                    callback_id,
                    RejectCode::CanisterError,
                    "Signature request expired",
                )),
            );
            if let Some(pre_sig_id) = pre_sig_id.as_ref() {
                payload.available_pre_signatures.remove(pre_sig_id);
            }

            if let Some(metrics) = idkg_payload_metrics {
                metrics.payload_errors_inc("expired_requests");
            }

            continue;
        }

        let signature = match signature_builder.get_completed_signature(callback_id, context) {
            Some(CombinedSignature::Ecdsa(signature)) => SignWithECDSAReply {
                signature: signature.signature.clone(),
            }
            .encode(),
            Some(CombinedSignature::Schnorr(signature)) => SignWithSchnorrReply {
                signature: signature.signature.clone(),
            }
            .encode(),
            Some(CombinedSignature::VetKd(_)) => {
                if let Some(metrics) = idkg_payload_metrics {
                    metrics.payload_errors_inc("vetkd_in_idkg_payload");
                }
                continue;
            }
            None => continue,
        };

        let response = ic_types::batch::ConsensusResponse::new(
            callback_id,
            ic_types::messages::Payload::Data(signature),
        );
        payload.signature_agreements.insert(
            context.pseudo_random_id,
            idkg::CompletedSignature::Unreported(response),
        );
        if let Some(pre_sig_id) = pre_sig_id.as_ref() {
            payload.available_pre_signatures.remove(pre_sig_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        TestThresholdSignatureBuilder, create_available_pre_signature, into_idkg_contexts,
        set_up_idkg_payload,
    };
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_management_canister_types_private::MasterPublicKeyId;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithThresholdContext;
    use ic_test_utilities_consensus::idkg::*;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        Height,
        consensus::idkg::IDkgPayload,
        crypto::canister_threshold_sig::{
            ThresholdEcdsaCombinedSignature, ThresholdSchnorrCombinedSignature,
        },
    };
    use std::collections::BTreeSet;

    fn set_up(
        should_create_key_transcript: bool,
        pseudo_random_ids: Vec<[u8; 32]>,
        key_id: IDkgMasterPublicKeyId,
    ) -> (IDkgPayload, BTreeMap<CallbackId, SignWithThresholdContext>) {
        let mut rng = reproducible_rng();
        let (idkg_payload, _env, _block_reader) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            vec![key_id.clone()],
            should_create_key_transcript,
        );

        let mut contexts = BTreeMap::new();
        for (index, pseudo_random_id) in pseudo_random_ids.into_iter().enumerate() {
            contexts.insert(
                CallbackId::from(index as u64),
                fake_signature_request_context(key_id.clone().into(), pseudo_random_id),
            );
        }

        (idkg_payload, contexts)
    }

    fn pseudo_random_id(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn test_update_signature_agreements_reporting_with_flags() {
        test_update_signature_agreements_reporting(false);
        test_update_signature_agreements_reporting(true);
    }

    fn test_update_signature_agreements_reporting(store_pre_signatures_in_state: bool) {
        let delivered_pseudo_random_id = pseudo_random_id(0);
        let old_pseudo_random_id = pseudo_random_id(1);
        let new_pseudo_random_id = pseudo_random_id(2);
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        let (mut idkg_payload, contexts) = set_up(
            /*should_create_key_transcript=*/ true,
            vec![old_pseudo_random_id, new_pseudo_random_id],
            key_id.clone(),
        );
        let contexts = into_idkg_contexts(&contexts);

        idkg_payload.signature_agreements.insert(
            delivered_pseudo_random_id,
            idkg::CompletedSignature::Unreported(empty_response()),
        );
        idkg_payload.signature_agreements.insert(
            old_pseudo_random_id,
            idkg::CompletedSignature::Unreported(empty_response()),
        );

        // old signature in the agreement AND in state is replaced by `ReportedToExecution`
        // old signature in the agreement but NOT in state is removed.
        update_signature_agreements(
            &contexts,
            &TestThresholdSignatureBuilder::new(),
            None,
            &mut idkg_payload,
            &BTreeSet::from([key_id]),
            None,
            store_pre_signatures_in_state,
        );

        assert_eq!(idkg_payload.signature_agreements.len(), 1);
        assert_eq!(
            idkg_payload.signature_agreements,
            BTreeMap::from([(
                old_pseudo_random_id,
                idkg::CompletedSignature::ReportedToExecution
            )])
        );
    }

    #[test]
    fn test_update_signature_agreements_success_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_update_signature_agreements_success(&key_id, false);
            test_update_signature_agreements_success(&key_id, true);
        }
    }

    fn test_update_signature_agreements_success(
        key_id: &IDkgMasterPublicKeyId,
        store_pre_signatures_in_state: bool,
    ) {
        let subnet_id = subnet_test_id(0);
        let mut idkg_payload = empty_idkg_payload_with_key_ids(subnet_id, vec![key_id.clone()]);
        let valid_keys = BTreeSet::from_iter([key_id.clone()]);
        let pre_sig_ids = (0..4)
            .map(|i| {
                if !store_pre_signatures_in_state {
                    // If pre-signatures aren't stored in the state, then we expect them to exist
                    // in the payload
                    create_available_pre_signature(&mut idkg_payload, key_id.clone(), i as u8)
                } else {
                    // If pre-signatures are stored in the state, they are not expected to still be
                    // in the payload
                    idkg_payload.uid_generator.next_pre_signature_id()
                }
            })
            .collect::<Vec<_>>();
        let ids = (0..4)
            .map(|i| request_id(i, Height::from(0)))
            .collect::<Vec<_>>();

        let contexts = BTreeMap::from([
            // insert request without completed signature
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_ids[0], ids[0]),
            // insert request to be completed
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_ids[1], ids[1]),
            // insert request that was already completed
            fake_signature_request_context_from_id(key_id.clone().into(), pre_sig_ids[2], ids[2]),
            // insert request without a matched pre-signature
            fake_signature_request_context_with_pre_sig(ids[3], key_id.clone(), None),
        ]);
        let contexts = into_idkg_contexts(&contexts);

        // insert agreement for completed request
        let pseudo_random_id = contexts.get(&ids[2].callback_id).unwrap().pseudo_random_id;
        idkg_payload.signature_agreements.insert(
            pseudo_random_id,
            idkg::CompletedSignature::Unreported(empty_response()),
        );

        let mut signature_builder = TestThresholdSignatureBuilder::new();
        for (i, _) in pre_sig_ids.iter().enumerate().skip(1) {
            signature_builder.signatures.insert(
                ids[i],
                match key_id.inner() {
                    MasterPublicKeyId::Ecdsa(_) => {
                        CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                            signature: vec![i as u8; 32],
                        })
                    }
                    MasterPublicKeyId::Schnorr(_) => {
                        CombinedSignature::Schnorr(ThresholdSchnorrCombinedSignature {
                            signature: vec![i as u8; 32],
                        })
                    }
                    MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
                },
            );
        }

        // Only the uncompleted request with available pre-signature should be completed
        update_signature_agreements(
            &contexts,
            &signature_builder,
            None,
            &mut idkg_payload,
            &valid_keys,
            None,
            store_pre_signatures_in_state,
        );

        if !store_pre_signatures_in_state {
            // If pre-signatures are stored on the blockchain, then the pre-signature
            // for the completed request should be removed, after a response to the
            // request is generated.
            assert_eq!(idkg_payload.available_pre_signatures.len(), 3);
            assert!(
                !idkg_payload
                    .available_pre_signatures
                    .contains_key(&pre_sig_ids[1])
            );
        }

        assert_eq!(idkg_payload.signature_agreements.len(), 2);
        let Some(idkg::CompletedSignature::Unreported(response_1)) =
            idkg_payload.signature_agreements.get(&[1; 32])
        else {
            panic!("Request 1 should have a response");
        };
        assert_matches!(&response_1.payload, ic_types::messages::Payload::Data(_));

        assert_matches!(
            idkg_payload.signature_agreements.get(&[2; 32]),
            Some(idkg::CompletedSignature::ReportedToExecution)
        );
    }

    #[test]
    fn test_update_signature_agreements_ignores_vetkd_contexts_with_flags() {
        test_update_signature_agreements_ignores_vetkd_contexts(false);
        test_update_signature_agreements_ignores_vetkd_contexts(true);
    }

    fn test_update_signature_agreements_ignores_vetkd_contexts(
        store_pre_signatures_in_state: bool,
    ) {
        let subnet_id = subnet_test_id(0);
        let ecdsa_key_id = fake_ecdsa_idkg_master_public_key_id();
        let vet_key_id = fake_vetkd_master_public_key_id();
        let mut idkg_payload =
            empty_idkg_payload_with_key_ids(subnet_id, vec![ecdsa_key_id.clone()]);
        let valid_keys = BTreeSet::from_iter([ecdsa_key_id.clone()]);
        let pre_sig_ids = (0..2)
            .map(|i| {
                if !store_pre_signatures_in_state {
                    // If pre-signatures aren't stored in the state, then we expect them to exist
                    // in the payload
                    create_available_pre_signature(&mut idkg_payload, ecdsa_key_id.clone(), i as u8)
                } else {
                    // If pre-signatures are stored in the state, they are not expected to still be
                    // in the payload
                    idkg_payload.uid_generator.next_pre_signature_id()
                }
            })
            .collect::<Vec<_>>();
        let ids = (0..2)
            .map(|i| request_id(i, Height::from(0)))
            .collect::<Vec<_>>();

        let vetkd_random_id = [2; 32];

        let contexts = BTreeMap::from([
            // insert ecdsa request to be completed
            fake_signature_request_context_from_id(
                ecdsa_key_id.clone().into(),
                pre_sig_ids[0],
                ids[0],
            ),
            // insert vet kd request to be ignored
            (
                ids[1].callback_id,
                fake_signature_request_context(vet_key_id.clone(), vetkd_random_id),
            ),
        ]);
        let contexts = into_idkg_contexts(&contexts);

        let mut signature_builder = TestThresholdSignatureBuilder::new();
        // insert ecdsa signature to be returned
        signature_builder.signatures.insert(
            ids[0],
            CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                signature: vec![0; 32],
            }),
        );
        // insert vet kd response to be ignored
        signature_builder.signatures.insert(
            ids[1],
            CombinedSignature::Ecdsa(ThresholdEcdsaCombinedSignature {
                signature: vec![1; 32],
            }),
        );

        // Only the ecdsa request should be completed
        update_signature_agreements(
            &contexts,
            &signature_builder,
            None,
            &mut idkg_payload,
            &valid_keys,
            None,
            store_pre_signatures_in_state,
        );

        if !store_pre_signatures_in_state {
            // If pre-signatures are stored on the blockchain, then the pre-signature
            // for the completed request should be removed, after a response to the
            // request is generated.
            assert_eq!(idkg_payload.available_pre_signatures.len(), 1);
            assert!(
                !idkg_payload
                    .available_pre_signatures
                    .contains_key(&pre_sig_ids[0])
            );
        }

        assert_eq!(idkg_payload.signature_agreements.len(), 1);
        let Some(idkg::CompletedSignature::Unreported(response_1)) =
            idkg_payload.signature_agreements.get(&[0; 32])
        else {
            panic!("Request 1 should have a response");
        };
        assert_matches!(&response_1.payload, ic_types::messages::Payload::Data(_));
    }
}
