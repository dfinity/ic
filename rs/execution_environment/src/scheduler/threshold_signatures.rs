use std::{collections::BTreeMap, sync::Arc};

use ic_crypto_prng::Csprng;
use ic_interfaces::execution_environment::RegistryExecutionSettings;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    EcdsaMatchedPreSignature, PreSignatureStash, SchnorrMatchedPreSignature,
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::{
    batch::AvailablePreSignatures,
    consensus::idkg::{
        common::{PreSignature, STORE_PRE_SIGNATURES_IN_STATE},
        IDkgMasterPublicKeyId, PreSigId,
    },
    crypto::canister_threshold_sig::idkg::IDkgTranscript,
    ExecutionRound, Height,
};
use more_asserts::debug_unreachable;
use rand::RngCore;

use super::SchedulerMetrics;

/// Update [`SignatureRequestContext`]s by assigning randomness and matching pre-signatures.
pub(crate) fn update_signature_request_contexts(
    current_round: ExecutionRound,
    delivered_pre_signatures: BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
    mut contexts: Vec<&mut SignWithThresholdContext>,
    pre_signature_stashes: &mut BTreeMap<IDkgMasterPublicKeyId, PreSignatureStash>,
    csprng: &mut Csprng,
    registry_settings: &RegistryExecutionSettings,
    metrics: &SchedulerMetrics,
) {
    let _timer = metrics
        .round_update_signature_request_contexts_duration
        .start_timer();

    // Assign a random nonce to the context in the round immediately subsequent to its successful
    // match with a pre-signature.
    for context in &mut contexts {
        if context.nonce.is_none()
            && context
                .matched_pre_signature
                .is_some_and(|(_, height)| height.get() + 1 == current_round.get())
        {
            let mut nonce = [0u8; 32];
            csprng.fill_bytes(&mut nonce);
            let _ = context.nonce.insert(nonce);
            metrics
                .completed_signature_request_contexts
                .with_label_values(&[&context.key_id().to_string()])
                .inc();
        }
    }

    if STORE_PRE_SIGNATURES_IN_STATE {
        // Purge all pre-signature stashes for which a different (or no) key transcript was delivered.
        pre_signature_stashes.retain(|key_id, stash| {
            delivered_pre_signatures.get(key_id).is_some_and(|data| {
                data.key_transcript.transcript_id == stash.key_transcript.transcript_id
            })
        });

        // Merge delivered pre-signatures into the pre-signature stash.
        for (key_id, mut delivered) in delivered_pre_signatures {
            metrics
                .delivered_pre_signatures
                .with_label_values(&[&key_id.to_string()])
                .observe(delivered.pre_signatures.len() as f64);

            pre_signature_stashes
                .entry(key_id)
                .and_modify(|stash| stash.pre_signatures.append(&mut delivered.pre_signatures))
                .or_insert_with(|| PreSignatureStash {
                    key_transcript: Arc::new(delivered.key_transcript),
                    pre_signatures: delivered.pre_signatures,
                });
        }

        for (key_id, stash) in pre_signature_stashes {
            match_stashed_pre_signatures_by_key_id(
                key_id,
                stash,
                &mut contexts,
                Height::from(current_round.get()),
            );
        }
    } else {
        // Clear the pre-signature stash in case of a downgrade.
        pre_signature_stashes.clear();

        for (key_id, delivered) in delivered_pre_signatures {
            // Match up to the maximum number of contexts per key ID to delivered pre-signatures.
            let max_ongoing_signatures = registry_settings
                .chain_key_settings
                .get(&key_id)
                .map(|setting| setting.pre_signatures_to_create_in_advance)
                .unwrap_or_default() as usize;

            match_delivered_pre_signatures_by_key_id(
                key_id,
                delivered,
                &mut contexts,
                max_ongoing_signatures,
                Height::from(current_round.get()),
            );
        }
    }
}

/// Match up to `max_ongoing_signatures` pre-signatures to unmatched signature request contexts
/// of the given `key_id`.
fn match_delivered_pre_signatures_by_key_id(
    key_id: IDkgMasterPublicKeyId,
    mut pre_sigs: AvailablePreSignatures,
    contexts: &mut [&mut SignWithThresholdContext],
    max_ongoing_signatures: usize,
    height: Height,
) {
    // Remove and count already matched pre-signatures.
    let mut matched = 0;
    for (pre_sig_id, _) in contexts
        .iter_mut()
        .filter(|context| context.key_id() == *key_id.inner())
        .flat_map(|context| context.matched_pre_signature)
    {
        pre_sigs.pre_signatures.remove(&pre_sig_id);
        matched += 1;
    }

    // Assign pre-signatures to unmatched contexts until `max_ongoing_signatures` is reached.
    for context in contexts.iter_mut() {
        if !(context.requires_pre_signature() && context.key_id() == *key_id.inner()) {
            continue;
        }
        if matched >= max_ongoing_signatures {
            break;
        }
        let Some((pre_sig_id, pre_signature)) = pre_sigs.pre_signatures.pop_first() else {
            break;
        };
        if match_context_with_pre_signature(
            context,
            pre_sig_id,
            pre_signature,
            Arc::new(pre_sigs.key_transcript.clone()),
            height,
        ) {
            matched += 1;
        }
    }
}

/// Match pre-signatures to unmatched signature request contexts of the given `key_id`.
fn match_stashed_pre_signatures_by_key_id(
    key_id: &IDkgMasterPublicKeyId,
    stash: &mut PreSignatureStash,
    contexts: &mut [&mut SignWithThresholdContext],
    height: Height,
) {
    // Assign pre-signatures to unmatched contexts until `max_ongoing_signatures` is reached.
    for context in contexts.iter_mut() {
        if !(context.requires_pre_signature() && context.key_id() == *key_id.inner()) {
            continue;
        }
        let Some((pre_sig_id, pre_signature)) = stash.pre_signatures.pop_first() else {
            break;
        };
        match_context_with_pre_signature(
            context,
            pre_sig_id,
            pre_signature,
            Arc::clone(&stash.key_transcript),
            height,
        );
    }
}

fn match_context_with_pre_signature(
    context: &mut SignWithThresholdContext,
    pre_sig_id: PreSigId,
    pre_signature: PreSignature,
    key_transcript: Arc<IDkgTranscript>,
    height: Height,
) -> bool {
    match (&mut context.args, pre_signature) {
        (ThresholdArguments::Ecdsa(args), PreSignature::Ecdsa(pre_signature)) => {
            args.pre_signature = Some(EcdsaMatchedPreSignature {
                id: pre_sig_id,
                height,
                pre_signature,
                key_transcript,
            })
        }
        (ThresholdArguments::Schnorr(args), PreSignature::Schnorr(pre_signature)) => {
            args.pre_signature = Some(SchnorrMatchedPreSignature {
                id: pre_sig_id,
                height,
                pre_signature,
                key_transcript,
            })
        }
        _ => {
            debug_unreachable!("Attempted to pair signature request context with pre-signature of different scheme.");
            return false;
        }
    }
    let _ = context.matched_pre_signature.insert((pre_sig_id, height));
    true
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
    };
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, SignWithThresholdContext, ThresholdArguments,
    };
    use ic_test_utilities_consensus::idkg::{key_transcript_for_tests, pre_signature_for_tests};
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::{consensus::idkg::PreSigId, messages::CallbackId, time::UNIX_EPOCH};

    fn ecdsa_key_id(i: u8) -> IDkgMasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: format!("ecdsa_key_id_{i}"),
        })
        .try_into()
        .unwrap()
    }

    fn schnorr_key_id(i: u8) -> IDkgMasterPublicKeyId {
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: format!("schnorr_key_id_{i}"),
        })
        .try_into()
        .unwrap()
    }

    fn fake_context(
        id: u64,
        key_id: &IDkgMasterPublicKeyId,
        matched_pre_signature: Option<(u64, Height)>,
    ) -> (CallbackId, SignWithThresholdContext) {
        let callback_id = CallbackId::from(id);
        let args = match key_id.inner() {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
                key_id: ecdsa_key_id.clone(),
                message_hash: [0; 32],
                pre_signature: matched_pre_signature.map(|(id, height)| EcdsaMatchedPreSignature {
                    id: PreSigId(id),
                    height,
                    pre_signature: pre_signature_for_tests(key_id).as_ecdsa().unwrap(),
                    key_transcript: Arc::new(key_transcript_for_tests(key_id)),
                }),
            }),
            MasterPublicKeyId::Schnorr(schnorr_key_id) => {
                ThresholdArguments::Schnorr(SchnorrArguments {
                    key_id: schnorr_key_id.clone(),
                    message: Arc::new(vec![1; 64]),
                    taproot_tree_root: None,
                    pre_signature: matched_pre_signature.map(|(id, height)| {
                        SchnorrMatchedPreSignature {
                            id: PreSigId(id),
                            height,
                            pre_signature: pre_signature_for_tests(key_id).as_schnorr().unwrap(),
                            key_transcript: Arc::new(key_transcript_for_tests(key_id)),
                        }
                    }),
                })
            }
            MasterPublicKeyId::VetKd(_) => panic!("vetKD does not have pre-signatures"),
        };
        let context = SignWithThresholdContext {
            request: RequestBuilder::new().build(),
            args,
            pseudo_random_id: [id as u8; 32],
            derivation_path: Arc::new(vec![]),
            batch_time: UNIX_EPOCH,
            matched_pre_signature: matched_pre_signature.map(|(id, h)| (PreSigId(id), h)),
            nonce: None,
        };

        (callback_id, context)
    }

    fn setup_pre_signatures<T: IntoIterator<Item = u64>>(
        key_id: &IDkgMasterPublicKeyId,
        ids: T,
    ) -> AvailablePreSignatures {
        AvailablePreSignatures {
            key_transcript: key_transcript_for_tests(key_id),
            pre_signatures: BTreeMap::from_iter(
                ids.into_iter()
                    .map(|i| (PreSigId(i), pre_signature_for_tests(key_id))),
            ),
        }
    }

    fn assert_matched_pre_signature(
        context: &SignWithThresholdContext,
        expected_id: u64,
        expected_height: Height,
    ) {
        assert!(context
            .matched_pre_signature
            .is_some_and(|(pid, h)| pid.id() == expected_id && h == expected_height));
        match &context.args {
            ThresholdArguments::Ecdsa(args) => {
                let pre_sig = args.pre_signature.clone().unwrap();
                assert_eq!(pre_sig.height, expected_height);
                assert_eq!(pre_sig.id.0, expected_id);
            }
            ThresholdArguments::Schnorr(args) => {
                let pre_sig = args.pre_signature.clone().unwrap();
                assert_eq!(pre_sig.height, expected_height);
                assert_eq!(pre_sig.id.0, expected_id);
            }
            ThresholdArguments::VetKd(_) => panic!("Unexpected VetKD context"),
        }
        assert!(!context.requires_pre_signature());
    }

    fn match_pre_signatures_basic_test(
        key_id: &IDkgMasterPublicKeyId,
        pre_sigs: AvailablePreSignatures,
        mut contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
        max_ongoing_signatures: usize,
        height: Height,
        cutoff: u64,
    ) {
        let mut context_vec: Vec<_> = contexts.values_mut().collect();
        match_delivered_pre_signatures_by_key_id(
            key_id.clone(),
            pre_sigs,
            &mut context_vec,
            max_ongoing_signatures,
            height,
        );

        // All contexts up until the cut-off point should have been matched at the given height,
        // the remaining contexts should remain unmatched.
        contexts.iter_mut().for_each(|(id, context)| {
            if id.get() <= cutoff {
                assert_matched_pre_signature(context, id.get(), height);
            } else {
                assert!(context.requires_pre_signature());
            }
        });
    }

    #[test]
    fn test_match_pre_signatures_doesnt_match_other_key_ids_all() {
        let ecdsa_key1 = ecdsa_key_id(1);
        let ecdsa_key2 = ecdsa_key_id(2);
        let schnorr_key1 = schnorr_key_id(2);
        let schnorr_key2 = schnorr_key_id(1);
        test_match_pre_signatures_doesnt_match_other_key_ids(&ecdsa_key1, &schnorr_key1);
        test_match_pre_signatures_doesnt_match_other_key_ids(&schnorr_key1, &ecdsa_key1);
        test_match_pre_signatures_doesnt_match_other_key_ids(&ecdsa_key1, &ecdsa_key2);
        test_match_pre_signatures_doesnt_match_other_key_ids(&schnorr_key1, &schnorr_key2);
    }

    fn test_match_pre_signatures_doesnt_match_other_key_ids(
        key_id1: &IDkgMasterPublicKeyId,
        key_id2: &IDkgMasterPublicKeyId,
    ) {
        // 2 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id1, 1..3);
        // 3 contexts for key 2
        let contexts = BTreeMap::from_iter((1..4).map(|i| fake_context(i, key_id2, None)));
        // No contexts should be matched
        match_pre_signatures_basic_test(key_id1, pre_sigs, contexts, 5, Height::from(1), 0);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_match_more_than_delivered_all() {
        test_match_pre_signatures_doesnt_match_more_than_delivered(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_match_more_than_delivered(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_match_more_than_delivered(key_id: &IDkgMasterPublicKeyId) {
        // 2 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 1..3);
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id, None)));
        // The first 2 contexts should be matched
        match_pre_signatures_basic_test(key_id, pre_sigs, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_match_more_than_requested_all() {
        test_match_pre_signatures_doesnt_match_more_than_requested(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_match_more_than_requested(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_match_more_than_requested(key_id: &IDkgMasterPublicKeyId) {
        // 3 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 1..4);
        // 2 contexts for key 1
        let contexts = BTreeMap::from_iter((1..3).map(|i| fake_context(i, key_id, None)));
        // The first 2 contexts should be matched
        match_pre_signatures_basic_test(key_id, pre_sigs, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_pre_signatures_respects_max_all() {
        test_match_pre_signatures_respects_max(&ecdsa_key_id(1));
        test_match_pre_signatures_respects_max(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_respects_max(key_id: &IDkgMasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 1..5);
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id, None)));
        // The first 3 contexts (up to max_ongoing_signatures) should be matched
        match_pre_signatures_basic_test(key_id, pre_sigs, contexts, 3, Height::from(1), 3);
    }

    #[test]
    fn test_match_pre_signatures_respects_max_per_key_id_all() {
        let ecdsa_key1 = ecdsa_key_id(1);
        let ecdsa_key2 = ecdsa_key_id(2);
        let schnorr_key1 = schnorr_key_id(2);
        let schnorr_key2 = schnorr_key_id(1);
        test_match_pre_signatures_respects_max_per_key_id(&ecdsa_key1, &schnorr_key1);
        test_match_pre_signatures_respects_max_per_key_id(&schnorr_key1, &ecdsa_key1);
        test_match_pre_signatures_respects_max_per_key_id(&ecdsa_key1, &ecdsa_key2);
        test_match_pre_signatures_respects_max_per_key_id(&schnorr_key1, &schnorr_key2);
    }

    fn test_match_pre_signatures_respects_max_per_key_id(
        key_id1: &IDkgMasterPublicKeyId,
        key_id2: &IDkgMasterPublicKeyId,
    ) {
        // 4 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id1, [1, 3, 4, 5]);
        let height = Height::from(1);
        // 4 contexts for key 1 and 1 context for key 2
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id1, None),
            fake_context(2, key_id2, Some((2, height))),
            fake_context(3, key_id1, None),
            fake_context(4, key_id1, None),
            fake_context(5, key_id1, None),
        ]);
        // With max_ongoing_signatures = 3 per key, the first 4 contexts should be matched in total.
        match_pre_signatures_basic_test(key_id1, pre_sigs, contexts, 3, height, 4);
    }

    #[test]
    fn test_matched_pre_signatures_arent_matched_again_all() {
        test_matched_pre_signatures_arent_matched_again(&ecdsa_key_id(1));
        test_matched_pre_signatures_arent_matched_again(&schnorr_key_id(2));
    }

    fn test_matched_pre_signatures_arent_matched_again(key_id: &IDkgMasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 1..5);
        let height = Height::from(1);
        // 5 contexts for key 1, 2 are already matched
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id, None),
            fake_context(2, key_id, Some((2, height))),
            fake_context(3, key_id, None),
            fake_context(4, key_id, Some((4, height))),
            fake_context(5, key_id, None),
        ]);
        // The first 4 contexts should be matched
        match_pre_signatures_basic_test(key_id, pre_sigs, contexts, 5, height, 4);
    }

    #[test]
    fn test_matched_pre_signatures_arent_overwritten_all() {
        test_matched_pre_signatures_arent_overwritten(&ecdsa_key_id(1));
        test_matched_pre_signatures_arent_overwritten(&schnorr_key_id(2));
    }

    fn test_matched_pre_signatures_arent_overwritten(key_id: &IDkgMasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 3..7);
        let height = Height::from(2);
        // 4 contexts for key 1, the first 3 are already matched
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id, Some((1, height))),
            fake_context(2, key_id, Some((2, height))),
            fake_context(3, key_id, Some((3, height))),
            fake_context(4, key_id, None),
        ]);
        // The first 4 contexts should be matched
        match_pre_signatures_basic_test(key_id, pre_sigs, contexts, 5, height, 4);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_update_height_all() {
        test_match_pre_signatures_doesnt_update_height(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_update_height(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_update_height(key_id: &IDkgMasterPublicKeyId) {
        // 2 pre-signatures for key 1
        let pre_sigs = setup_pre_signatures(key_id, 5..=6);
        // 2 contexts for key 1, the first was already matched to the first pre-signature
        // in the previous round.
        let mut contexts = BTreeMap::from_iter([
            fake_context(2, key_id, Some((5, Height::from(2)))),
            fake_context(4, key_id, None),
        ]);
        let mut context_vec: Vec<_> = contexts.values_mut().collect();

        // Match them at height 3
        match_delivered_pre_signatures_by_key_id(
            key_id.clone(),
            pre_sigs,
            &mut context_vec,
            5,
            Height::from(3),
        );

        // The first context should still be matched at the height of the previous round (height 2).
        let first_context = contexts.pop_first().unwrap().1;
        assert_matched_pre_signature(&first_context, 5, Height::from(2));

        // The second context should have been matched to the second pre-signature at height 3.
        let second_context = contexts.pop_first().unwrap().1;
        assert_matched_pre_signature(&second_context, 6, Height::from(3));
    }
}
