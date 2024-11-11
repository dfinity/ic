use std::collections::{BTreeMap, BTreeSet};

use ic_crypto_prng::Csprng;
use ic_interfaces::execution_environment::RegistryExecutionSettings;
use ic_management_canister_types::MasterPublicKeyId;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithThresholdContext;
use ic_types::{consensus::idkg::PreSigId, ExecutionRound, Height};
use rand::RngCore;

use super::SchedulerMetrics;

/// Update [`SignatureRequestContext`]s by assigning randomness and matching pre-signatures.
pub(crate) fn update_signature_request_contexts(
    current_round: ExecutionRound,
    idkg_pre_signature_ids: BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>>,
    mut contexts: Vec<&mut SignWithThresholdContext>,
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

    for (key_id, pre_sig_ids) in idkg_pre_signature_ids {
        // Match up to the maximum number of contexts per key ID to delivered pre-signatures.
        let max_ongoing_signatures = registry_settings
            .chain_key_settings
            .get(&key_id)
            .map(|setting| setting.pre_signatures_to_create_in_advance)
            .unwrap_or_default() as usize;

        metrics
            .delivered_pre_signatures
            .with_label_values(&[&key_id.to_string()])
            .observe(pre_sig_ids.len() as f64);

        match_pre_signatures_by_key_id(
            key_id,
            pre_sig_ids,
            &mut contexts,
            max_ongoing_signatures,
            Height::from(current_round.get()),
        );
    }
}

/// Match up to `max_ongoing_signatures` pre-signature IDs to unmatched signature request contexts
/// of the given `key_id`.
fn match_pre_signatures_by_key_id(
    key_id: MasterPublicKeyId,
    mut pre_sig_ids: BTreeSet<PreSigId>,
    contexts: &mut [&mut SignWithThresholdContext],
    max_ongoing_signatures: usize,
    height: Height,
) {
    // Remove and count already matched pre-signatures.
    let mut matched = 0;
    for (pre_sig_id, _) in contexts
        .iter_mut()
        .filter(|context| context.key_id() == key_id)
        .flat_map(|context| context.matched_pre_signature)
    {
        pre_sig_ids.remove(&pre_sig_id);
        matched += 1;
    }

    // Assign pre-signatures to unmatched contexts until `max_ongoing_signatures` is reached.
    for context in contexts.iter_mut() {
        if !(context.matched_pre_signature.is_none() && context.key_id() == key_id) {
            continue;
        }
        if matched >= max_ongoing_signatures {
            break;
        }
        let Some(pre_sig_id) = pre_sig_ids.pop_first() else {
            break;
        };
        let _ = context.matched_pre_signature.insert((pre_sig_id, height));
        matched += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId};
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, SignWithThresholdContext, ThresholdArguments,
    };
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::{messages::CallbackId, time::UNIX_EPOCH};

    fn ecdsa_key_id(i: u8) -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: format!("ecdsa_key_id_{i}"),
        })
    }

    fn schnorr_key_id(i: u8) -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: format!("schnorr_key_id_{i}"),
        })
    }

    fn fake_context(
        id: u64,
        key_id: &MasterPublicKeyId,
        matched_pre_signature: Option<(u64, Height)>,
    ) -> (CallbackId, SignWithThresholdContext) {
        let callback_id = CallbackId::from(id);
        let args = match key_id {
            MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
                key_id: key_id.clone(),
                message_hash: [0; 32],
            }),
            MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
                key_id: key_id.clone(),
                message: Arc::new(vec![1; 64]),
            }),
        };
        let context = SignWithThresholdContext {
            request: RequestBuilder::new().build(),
            args,
            pseudo_random_id: [id as u8; 32],
            derivation_path: vec![],
            batch_time: UNIX_EPOCH,
            matched_pre_signature: matched_pre_signature.map(|(id, h)| (PreSigId(id), h)),
            nonce: None,
        };

        (callback_id, context)
    }

    fn match_pre_signatures_basic_test(
        key_id: &MasterPublicKeyId,
        pre_sig_ids: BTreeSet<PreSigId>,
        mut contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
        max_ongoing_signatures: usize,
        height: Height,
        cutoff: u64,
    ) {
        let mut context_vec: Vec<_> = contexts.values_mut().collect();
        match_pre_signatures_by_key_id(
            key_id.clone(),
            pre_sig_ids,
            &mut context_vec,
            max_ongoing_signatures,
            height,
        );

        // All contexts up until the cut-off point should have been matched at the given height,
        // the remaining contexts should remain unmatched.
        contexts.iter_mut().for_each(|(id, context)| {
            if id.get() <= cutoff {
                assert!(context
                    .matched_pre_signature
                    .is_some_and(|(pid, h)| pid.id() == id.get() && h == height))
            } else {
                assert!(context.matched_pre_signature.is_none())
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
        key_id1: &MasterPublicKeyId,
        key_id2: &MasterPublicKeyId,
    ) {
        // 2 pre-signatures for key 1
        let ids = BTreeSet::from_iter((1..3).map(PreSigId));
        // 3 contexts for key 2
        let contexts = BTreeMap::from_iter((1..4).map(|i| fake_context(i, key_id2, None)));
        // No contexts should be matched
        match_pre_signatures_basic_test(key_id1, ids, contexts, 5, Height::from(1), 0);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_match_more_than_delivered_all() {
        test_match_pre_signatures_doesnt_match_more_than_delivered(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_match_more_than_delivered(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_match_more_than_delivered(key_id: &MasterPublicKeyId) {
        // 2 pre-signatures for key 1
        let ids = BTreeSet::from_iter((1..3).map(PreSigId));
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id, None)));
        // The first 2 contexts should be matched
        match_pre_signatures_basic_test(key_id, ids, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_match_more_than_requested_all() {
        test_match_pre_signatures_doesnt_match_more_than_requested(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_match_more_than_requested(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_match_more_than_requested(key_id: &MasterPublicKeyId) {
        // 3 pre-signatures for key 1
        let ids = BTreeSet::from_iter((1..4).map(PreSigId));
        // 2 contexts for key 1
        let contexts = BTreeMap::from_iter((1..3).map(|i| fake_context(i, key_id, None)));
        // The first 2 contexts should be matched
        match_pre_signatures_basic_test(key_id, ids, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_pre_signatures_respects_max_all() {
        test_match_pre_signatures_respects_max(&ecdsa_key_id(1));
        test_match_pre_signatures_respects_max(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_respects_max(key_id: &MasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let ids = BTreeSet::from_iter((1..5).map(PreSigId));
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id, None)));
        // The first 3 contexts (up to max_ongoing_signatures) should be matched
        match_pre_signatures_basic_test(key_id, ids, contexts, 3, Height::from(1), 3);
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
        key_id1: &MasterPublicKeyId,
        key_id2: &MasterPublicKeyId,
    ) {
        // 4 pre-signatures for key 1
        let ids = BTreeSet::from_iter([PreSigId(1), PreSigId(3), PreSigId(4), PreSigId(5)]);
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
        match_pre_signatures_basic_test(key_id1, ids, contexts, 3, height, 4);
    }

    #[test]
    fn test_matched_pre_signatures_arent_matched_again_all() {
        test_matched_pre_signatures_arent_matched_again(&ecdsa_key_id(1));
        test_matched_pre_signatures_arent_matched_again(&schnorr_key_id(2));
    }

    fn test_matched_pre_signatures_arent_matched_again(key_id: &MasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let ids = BTreeSet::from_iter((1..5).map(PreSigId));
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
        match_pre_signatures_basic_test(key_id, ids, contexts, 5, height, 4);
    }

    #[test]
    fn test_matched_pre_signatures_arent_overwritten_all() {
        test_matched_pre_signatures_arent_overwritten(&ecdsa_key_id(1));
        test_matched_pre_signatures_arent_overwritten(&schnorr_key_id(2));
    }

    fn test_matched_pre_signatures_arent_overwritten(key_id: &MasterPublicKeyId) {
        // 4 pre-signatures for key 1
        let ids = BTreeSet::from_iter((3..7).map(PreSigId));
        let height = Height::from(2);
        // 4 contexts for key 1, the first 3 are already matched
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id, Some((1, height))),
            fake_context(2, key_id, Some((2, height))),
            fake_context(3, key_id, Some((3, height))),
            fake_context(4, key_id, None),
        ]);
        // The first 4 contexts should be matched
        match_pre_signatures_basic_test(key_id, ids, contexts, 5, height, 4);
    }

    #[test]
    fn test_match_pre_signatures_doesnt_update_heightn_all() {
        test_match_pre_signatures_doesnt_update_height(&ecdsa_key_id(1));
        test_match_pre_signatures_doesnt_update_height(&schnorr_key_id(2));
    }

    fn test_match_pre_signatures_doesnt_update_height(key_id: &MasterPublicKeyId) {
        // 2 pre-signatures for key 1
        let ids = BTreeSet::from_iter([PreSigId(5), PreSigId(6)]);
        // 2 contexts for key 1, the first was already matched to the first pre-signature
        // in the previous round.
        let mut contexts = BTreeMap::from_iter([
            fake_context(2, key_id, Some((5, Height::from(2)))),
            fake_context(4, key_id, None),
        ]);
        let mut context_vec: Vec<_> = contexts.values_mut().collect();

        // Match them at height 3
        match_pre_signatures_by_key_id(key_id.clone(), ids, &mut context_vec, 5, Height::from(3));

        // The first context should still be matched at the height of the previous round (height 2).
        let first_context = contexts.pop_first().unwrap().1;
        assert!(first_context
            .matched_pre_signature
            .is_some_and(|(pid, h)| { pid == PreSigId(5) && h == Height::from(2) }));

        // The second context should have been matched to the second pre-signature at height 3.
        let second_context = contexts.pop_first().unwrap().1;
        assert!(second_context
            .matched_pre_signature
            .is_some_and(|(pid, h)| { pid == PreSigId(6) && h == Height::from(3) }));
    }
}
