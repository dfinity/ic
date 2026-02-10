use std::{collections::BTreeMap, sync::Arc};

use ic_crypto_prng::Csprng;
use ic_interfaces::execution_environment::RegistryExecutionSettings;
use ic_logger::{ReplicaLogger, error, warn};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    EcdsaMatchedPreSignature, PreSignatureStash, SchnorrMatchedPreSignature,
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::{
    ExecutionRound, Height,
    batch::AvailablePreSignatures,
    consensus::idkg::{IDkgMasterPublicKeyId, PreSigId, common::PreSignature},
    crypto::canister_threshold_sig::idkg::IDkgTranscript,
};
use more_asserts::debug_unreachable;
use rand::RngCore;

use super::SchedulerMetrics;

pub(crate) const THRESHOLD_SIGNATURE_SCHEME_MISMATCH: &str =
    "scheduler_threshold_signature_scheme_mismatch";

/// Update [`SignatureRequestContext`]s by assigning randomness and matching pre-signatures.
pub(crate) fn update_signature_request_contexts(
    current_round: ExecutionRound,
    delivered_pre_signatures: BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
    mut contexts: Vec<&mut SignWithThresholdContext>,
    pre_signature_stashes: &mut BTreeMap<IDkgMasterPublicKeyId, PreSignatureStash>,
    csprng: &mut Csprng,
    registry_settings: &RegistryExecutionSettings,
    metrics: &SchedulerMetrics,
    logger: &ReplicaLogger,
) {
    let _timer = metrics
        .round_update_signature_request_contexts_duration
        .start_timer();

    // Assign a random nonce to the context in the round immediately subsequent to its successful
    // match with a pre-signature.
    for context in &mut contexts {
        if context.nonce.is_none()
            && context.key_id().requires_pre_signatures()
            && context
                .height()
                .is_some_and(|height| height.get() + 1 == current_round.get())
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

        let stash = pre_signature_stashes
            .entry(key_id.clone())
            .and_modify(|stash| stash.pre_signatures.append(&mut delivered.pre_signatures))
            .or_insert_with(|| PreSignatureStash {
                key_transcript: Arc::new(delivered.key_transcript),
                pre_signatures: delivered.pre_signatures,
            });

        // In case the maximum stash size was reduced via proposal (or due to a bug in consensus),
        // the current size of the stash may exceed the configured maximum.
        // In that case, log a warning and trim the stash back to the maximum size.
        let max_stash_size = registry_settings
            .chain_key_settings
            .get(&key_id)
            .map(|setting| {
                setting
                    .pre_signatures_to_create_in_advance
                    .unwrap_or_default()
            })
            .unwrap_or_default() as usize;
        let exceeding = stash.pre_signatures.len().saturating_sub(max_stash_size);
        if exceeding > 0 {
            warn!(
                every_n_seconds => 10,
                logger,
                "Pre-signature stash of key {key_id} exceeded configured size of {max_stash_size}"
            );
            metrics
                .exceeding_pre_signatures
                .with_label_values(&[&key_id.to_string()])
                .inc_by(exceeding as u64);
            // Trim the stash by splitting off the highest exceeding entries
            let Some(split_key) = stash.pre_signatures.keys().rev().nth(exceeding - 1) else {
                continue;
            };
            stash.pre_signatures.split_off(&split_key.clone());
        }
    }

    match_contexts_with_stashed_pre_signatures(
        pre_signature_stashes,
        &mut contexts,
        Height::from(current_round.get()),
        metrics,
        logger,
    );
}

/// Match pre-signatures to unmatched signature request contexts of the given `key_id`.
fn match_contexts_with_stashed_pre_signatures(
    stashes: &mut BTreeMap<IDkgMasterPublicKeyId, PreSignatureStash>,
    contexts: &mut [&mut SignWithThresholdContext],
    height: Height,
    metrics: &SchedulerMetrics,
    logger: &ReplicaLogger,
) {
    for context in contexts.iter_mut() {
        if !context.requires_pre_signature() {
            continue;
        }
        let Ok(key_id) = IDkgMasterPublicKeyId::try_from(context.key_id()) else {
            // Not an IDkg context.
            continue;
        };
        let Some(stash) = stashes.get_mut(&key_id) else {
            // No pre-signature stash available for this key ID.
            continue;
        };
        let Some((pre_sig_id, pre_signature)) = stash.pre_signatures.pop_first() else {
            // No pre-signature available in the stash for this key ID.
            continue;
        };
        match_context_with_pre_signature(
            context,
            pre_sig_id,
            pre_signature,
            Arc::clone(&stash.key_transcript),
            height,
            metrics,
            logger,
        );
    }
}

fn match_context_with_pre_signature(
    context: &mut SignWithThresholdContext,
    pre_sig_id: PreSigId,
    pre_signature: PreSignature,
    key_transcript: Arc<IDkgTranscript>,
    height: Height,
    metrics: &SchedulerMetrics,
    logger: &ReplicaLogger,
) {
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
        (_, pre_signature) => {
            let message = format!(
                "Attempted to pair signature request context for key {:?}, with pre-signature {:?} of different scheme.",
                context.key_id(),
                pre_signature
            );
            error!(
                every_n_seconds => 5,
                logger,
                "{}: {}", THRESHOLD_SIGNATURE_SCHEME_MISMATCH, message
            );
            metrics.threshold_signature_scheme_mismatch.inc();
            debug_unreachable!(message);
        }
    }
    let _ = context.matched_pre_signature.insert((pre_sig_id, height));
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use super::*;
    use ic_interfaces::execution_environment::ChainKeySettings;
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
    };
    use ic_metrics::MetricsRegistry;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, SignWithThresholdContext, ThresholdArguments,
    };
    use ic_test_utilities_consensus::idkg::{key_transcript_for_tests, pre_signature_for_tests};
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::{
        Randomness, RegistryVersion, consensus::idkg::PreSigId, messages::CallbackId,
        time::UNIX_EPOCH,
    };

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

    fn setup_pre_signature_stash<T: IntoIterator<Item = u64>>(
        key_id: &IDkgMasterPublicKeyId,
        ids: T,
    ) -> PreSignatureStash {
        PreSignatureStash {
            key_transcript: Arc::new(key_transcript_for_tests(key_id)),
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
        assert!(
            context
                .matched_pre_signature
                .is_some_and(|(pid, h)| pid.id() == expected_id && h == expected_height)
        );
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

    fn pre_signature_delivery_test(
        delivered_pre_signatures: BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
        pre_signature_stashes: &mut BTreeMap<IDkgMasterPublicKeyId, PreSignatureStash>,
        max_stash_size: u32,
    ) {
        let chain_key_settings = delivered_pre_signatures
            .keys()
            .chain(pre_signature_stashes.keys())
            .map(|key_id| {
                let settings = ChainKeySettings {
                    max_queue_size: 20,
                    pre_signatures_to_create_in_advance: key_id
                        .requires_pre_signatures()
                        .then_some(max_stash_size),
                };
                (key_id.inner().clone(), settings)
            })
            .collect();

        // Call the function under test with the given arguments and some dummy parameters.
        update_signature_request_contexts(
            ExecutionRound::new(10),
            delivered_pre_signatures,
            vec![],
            pre_signature_stashes,
            &mut Csprng::from_seed_and_purpose(
                &Randomness::new([1; 32]),
                &ic_crypto_prng::RandomnessPurpose::ExecutionThread(1),
            ),
            &RegistryExecutionSettings {
                provisional_whitelist: ic_registry_provisional_whitelist::ProvisionalWhitelist::All,
                chain_key_settings,
                max_number_of_canisters: 0,
                subnet_size: 0,
                node_ids: BTreeSet::new(),
                registry_version: RegistryVersion::from(0),
                canister_cycles_cost_schedule: Default::default(),
            },
            &SchedulerMetrics::new(&MetricsRegistry::new()),
            &no_op_logger(),
        )
    }

    #[test]
    fn test_pre_signature_stashes_are_replaced_if_key_transcript_changes() {
        let key_id = ecdsa_key_id(1);
        let pre_sigs_before = vec![1, 2, 3];
        let pre_sigs_delivered = vec![4, 5, 6];
        let mut pre_signature_stashes = BTreeMap::new();
        pre_signature_stashes.insert(
            key_id.clone(),
            setup_pre_signature_stash(&key_id, pre_sigs_before),
        );
        let mut delivered_pre_signatures = BTreeMap::new();
        let delivered = setup_pre_signatures(&key_id, pre_sigs_delivered.clone());
        delivered_pre_signatures.insert(key_id.clone(), delivered.clone());
        assert_ne!(
            delivered.key_transcript.transcript_id,
            pre_signature_stashes[&key_id].key_transcript.transcript_id,
            "Delivered key transcript should be different than the one in the stash"
        );
        pre_signature_delivery_test(delivered_pre_signatures, &mut pre_signature_stashes, 20);
        let pre_sigs_after = pre_signature_stashes[&key_id]
            .pre_signatures
            .keys()
            .map(|pid| pid.id())
            .collect::<Vec<_>>();
        assert_eq!(
            pre_sigs_delivered, pre_sigs_after,
            "Pre-signature stashes should contain only the delivered pre-signatures after delivery"
        );
        assert_eq!(
            delivered.key_transcript.transcript_id,
            pre_signature_stashes[&key_id].key_transcript.transcript_id,
            "Stashed key transcript should be set to the delivered one"
        );
    }

    #[test]
    fn test_pre_signature_stashes_are_purged_if_no_key_transcript_delivered() {
        let key_id = ecdsa_key_id(1);
        let mut pre_signature_stashes = BTreeMap::new();
        pre_signature_stashes.insert(key_id.clone(), setup_pre_signature_stash(&key_id, 0..5));
        pre_signature_delivery_test(BTreeMap::new(), &mut pre_signature_stashes, 20);
        assert!(pre_signature_stashes.is_empty());
    }

    #[test]
    fn test_delivered_pre_signatures_are_merged_with_stash() {
        let key_id = ecdsa_key_id(1);
        let pre_sigs_before = vec![1, 2, 3];
        let pre_sigs_delivered = vec![4, 5, 6];
        let mut pre_signature_stashes = BTreeMap::new();
        pre_signature_stashes.insert(
            key_id.clone(),
            setup_pre_signature_stash(&key_id, pre_sigs_before),
        );
        let mut delivered_pre_signatures = BTreeMap::new();
        let mut delivered = setup_pre_signatures(&key_id, pre_sigs_delivered);
        // The delivered key transcript should be the same as the one in the stash.
        delivered.key_transcript = pre_signature_stashes[&key_id]
            .key_transcript
            .as_ref()
            .clone();
        delivered_pre_signatures.insert(key_id.clone(), delivered);
        pre_signature_delivery_test(delivered_pre_signatures, &mut pre_signature_stashes, 20);
        let pre_sigs_after = pre_signature_stashes[&key_id]
            .pre_signatures
            .keys()
            .map(|pid| pid.id())
            .collect::<Vec<_>>();
        assert_eq!(
            vec![1, 2, 3, 4, 5, 6],
            pre_sigs_after,
            "Pre-signature stashes should contain both the initial and the delivered pre-signatures"
        );
    }

    #[test]
    fn test_exceeding_pre_signatures_are_purged() {
        let key_id = ecdsa_key_id(1);
        let pre_sigs_before = vec![1, 2, 3];
        let pre_sigs_delivered = vec![4, 5, 6];
        let mut pre_signature_stashes = BTreeMap::new();
        pre_signature_stashes.insert(
            key_id.clone(),
            setup_pre_signature_stash(&key_id, pre_sigs_before),
        );
        let mut delivered_pre_signatures = BTreeMap::new();
        let mut delivered = setup_pre_signatures(&key_id, pre_sigs_delivered);
        // The delivered key transcript should be the same as the one in the stash.
        delivered.key_transcript = pre_signature_stashes[&key_id]
            .key_transcript
            .as_ref()
            .clone();
        delivered_pre_signatures.insert(key_id.clone(), delivered);
        pre_signature_delivery_test(
            delivered_pre_signatures.clone(),
            &mut pre_signature_stashes,
            4, // Max stash size is lower than final stash size
        );
        let pre_sigs_after = pre_signature_stashes[&key_id]
            .pre_signatures
            .keys()
            .map(|pid| pid.id())
            .collect::<Vec<_>>();
        assert_eq!(vec![1, 2, 3, 4], pre_sigs_after);

        // Don't deliver more pre-signatures, but reduce max stash size even further
        delivered_pre_signatures
            .get_mut(&key_id)
            .unwrap()
            .pre_signatures
            .clear();
        pre_signature_delivery_test(
            delivered_pre_signatures.clone(),
            &mut pre_signature_stashes,
            2, // Max stash size is lower than current stash size
        );
        let pre_sigs_after = pre_signature_stashes[&key_id]
            .pre_signatures
            .keys()
            .map(|pid| pid.id())
            .collect::<Vec<_>>();
        assert_eq!(vec![1, 2], pre_sigs_after);

        pre_signature_delivery_test(
            delivered_pre_signatures,
            &mut pre_signature_stashes,
            0, // Max stash size is lower than current stash size
        );
        assert!(pre_signature_stashes[&key_id].pre_signatures.is_empty());
    }

    #[test]
    fn test_match_contexts_with_stashed_pre_signatures() {
        let key_id1 = ecdsa_key_id(1);
        let key_id2 = schnorr_key_id(2);
        let key_id3 = ecdsa_key_id(3);
        // There is one stash with 1 pre-signatures, and one with no pre-signatures.
        let mut pre_signature_stashes = BTreeMap::new();
        pre_signature_stashes.insert(key_id1.clone(), setup_pre_signature_stash(&key_id1, [1]));
        pre_signature_stashes.insert(key_id2.clone(), setup_pre_signature_stash(&key_id2, []));

        let mut contexts = [
            // One context requesting key_id3 (no stash).
            &mut fake_context(1, &key_id3, None).1,
            // Three context requesting key_id1, one of which is already matched.
            &mut fake_context(2, &key_id1, Some((3, Height::from(1)))).1,
            &mut fake_context(3, &key_id1, None).1,
            &mut fake_context(4, &key_id1, None).1,
            // One context requesting key_id2, which has no pre-signatures in the stash.
            &mut fake_context(5, &key_id2, None).1,
        ];

        match_contexts_with_stashed_pre_signatures(
            &mut pre_signature_stashes,
            &mut contexts,
            Height::from(10),
            &SchedulerMetrics::new(&MetricsRegistry::new()),
            &no_op_logger(),
        );

        // The 1st context should remain unmatched, as it requested a key ID with no pre-signatures.
        assert!(contexts[0].requires_pre_signature());
        // The 2nd context should remain matched to the pre-signature with ID 3.
        assert_matched_pre_signature(contexts[1], 3, Height::from(1));
        // The 3rd context should be matched to the pre-signature with ID 1.
        assert_matched_pre_signature(contexts[2], 1, Height::from(10));
        // The 4th context should not be matched, as there are no more pre-signatures in the stash.
        assert!(contexts[3].requires_pre_signature());
        // The 5th context should remain unmatched, as there are no pre-signatures in the stash.
        assert!(contexts[4].requires_pre_signature());

        // The pre-signature stash for key_id1 should now be empty
        assert!(pre_signature_stashes[&key_id1].pre_signatures.is_empty());
    }
}
