use std::collections::{BTreeMap, BTreeSet};

use ic_crypto_prng::Csprng;
use ic_interfaces::execution_environment::RegistryExecutionSettings;
use ic_management_canister_types::EcdsaKeyId;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_types::{consensus::ecdsa::QuadrupleId, messages::CallbackId, ExecutionRound, Height};
use rand::RngCore;

use super::SchedulerMetrics;

/// Update [`SignWithEcdsaContext`]s by assigning randomness and matching quadruples.
pub(crate) fn update_sign_with_ecdsa_contexts(
    current_round: ExecutionRound,
    ecdsa_quadruple_ids: BTreeMap<EcdsaKeyId, BTreeSet<QuadrupleId>>,
    contexts: &mut BTreeMap<CallbackId, SignWithEcdsaContext>,
    csprng: &mut Csprng,
    registry_settings: &RegistryExecutionSettings,
    metrics: &SchedulerMetrics,
) {
    let _timer = metrics
        .round_update_sign_with_ecdsa_contexts_duration
        .start_timer();

    // Assign a random nonce to the context in the round immediately subsequent to its successful
    // match with a quadruple.
    for context in contexts.values_mut() {
        if context.nonce.is_none()
            && context
                .matched_quadruple
                .as_ref()
                .is_some_and(|(_, height)| height.get() + 1 == current_round.get())
        {
            let mut nonce = [0u8; 32];
            csprng.fill_bytes(&mut nonce);
            context.nonce = Some(nonce);
            metrics
                .ecdsa_completed_contexts
                .with_label_values(&[&context.key_id.to_string()])
                .inc();
        }
    }

    // Match up to the maximum number of contexts per key ID to delivered quadruples.
    let max_ongoing_signatures = registry_settings.quadruples_to_create_in_advance as usize;
    for (key_id, quadruple_ids) in ecdsa_quadruple_ids {
        metrics
            .ecdsa_delivered_quadruples
            .with_label_values(&[&key_id.to_string()])
            .observe(quadruple_ids.len() as f64);
        match_quadruples_by_key_id(
            key_id,
            quadruple_ids,
            contexts,
            max_ongoing_signatures,
            Height::from(current_round.get()),
        );
    }
}

/// Match up to `max_ongoing_signatures` quadruple IDs to unmatched sign with ecdsa contexts
/// of the given `key_id`.
fn match_quadruples_by_key_id(
    key_id: EcdsaKeyId,
    mut quadruple_ids: BTreeSet<QuadrupleId>,
    contexts: &mut BTreeMap<CallbackId, SignWithEcdsaContext>,
    max_ongoing_signatures: usize,
    height: Height,
) {
    // Remove and count already matched quadruples.
    let mut matched = 0;
    for (quadruple_id, _) in contexts
        .values()
        .filter(|context| context.key_id == key_id)
        .flat_map(|context| context.matched_quadruple.as_ref())
    {
        quadruple_ids.remove(quadruple_id);
        matched += 1;
    }

    // Assign quadruples to unmatched contexts until `max_ongoing_signatures` is reached.
    for context in contexts
        .values_mut()
        .filter(|context| context.matched_quadruple.is_none() && context.key_id == key_id)
    {
        if matched >= max_ongoing_signatures {
            break;
        }
        let Some(quadruple_id) = quadruple_ids.pop_first() else {
            break;
        };
        context.matched_quadruple = Some((quadruple_id, height));
        matched += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::tests::make_key_id;
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::time::UNIX_EPOCH;

    fn fake_context(
        id: u64,
        key_id: EcdsaKeyId,
        matched_quadruple: Option<(u64, Height)>,
    ) -> (CallbackId, SignWithEcdsaContext) {
        (
            CallbackId::from(id),
            SignWithEcdsaContext {
                request: RequestBuilder::new().build(),
                key_id: key_id.clone(),
                pseudo_random_id: [id as u8; 32],
                message_hash: [0; 32],
                derivation_path: vec![],
                batch_time: UNIX_EPOCH,
                matched_quadruple: matched_quadruple.map(|(id, h)| (QuadrupleId::new(id), h)),
                nonce: None,
            },
        )
    }

    fn match_quadruples_basic_test(
        key_id: EcdsaKeyId,
        quadruple_ids: BTreeSet<QuadrupleId>,
        mut contexts: BTreeMap<CallbackId, SignWithEcdsaContext>,
        max_ongoing_signatures: usize,
        height: Height,
        cutoff: u64,
    ) {
        match_quadruples_by_key_id(
            key_id,
            quadruple_ids,
            &mut contexts,
            max_ongoing_signatures,
            height,
        );

        // All contexts up until the cut-off point should have been matched at the given height,
        // the remaining contexts should remain unmatched.
        contexts.into_iter().for_each(|(id, context)| {
            if id.get() <= cutoff {
                assert!(context
                    .matched_quadruple
                    .is_some_and(|(qid, h)| qid.id() == id.get() && h == height))
            } else {
                assert!(context.matched_quadruple.is_none())
            }
        });
    }

    #[test]
    fn test_match_quadruples_doesnt_match_other_key_ids() {
        let key_id1 = make_key_id(1);
        let key_id2 = make_key_id(2);
        // 2 quadruples for key 1
        let ids = BTreeSet::from_iter((1..3).map(QuadrupleId::new));
        // 3 contexts for key 2
        let contexts = BTreeMap::from_iter((1..4).map(|i| fake_context(i, key_id2.clone(), None)));
        // No contexts should be matched
        match_quadruples_basic_test(key_id1, ids, contexts, 5, Height::from(1), 0);
    }

    #[test]
    fn test_match_quadruples_doesnt_match_more_than_delivered() {
        let key_id = make_key_id(1);
        // 2 quadruples for key 1
        let ids = BTreeSet::from_iter((1..3).map(QuadrupleId::new));
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id.clone(), None)));
        // The first 2 contexts should be matched
        match_quadruples_basic_test(key_id, ids, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_quadruples_doesnt_match_more_than_requested() {
        let key_id = make_key_id(1);
        // 3 quadruples for key 1
        let ids = BTreeSet::from_iter((1..4).map(QuadrupleId::new));
        // 2 contexts for key 1
        let contexts = BTreeMap::from_iter((1..3).map(|i| fake_context(i, key_id.clone(), None)));
        // The first 2 contexts should be matched
        match_quadruples_basic_test(key_id, ids, contexts, 5, Height::from(1), 2);
    }

    #[test]
    fn test_match_quadruples_respects_max() {
        let key_id = make_key_id(1);
        // 4 quadruples for key 1
        let ids = BTreeSet::from_iter((1..5).map(QuadrupleId::new));
        // 4 contexts for key 1
        let contexts = BTreeMap::from_iter((1..5).map(|i| fake_context(i, key_id.clone(), None)));
        // The first 3 contexts (up to max_ongoing_signatures) should be matched
        match_quadruples_basic_test(key_id, ids, contexts, 3, Height::from(1), 3);
    }

    #[test]
    fn test_match_quadruples_respects_max_per_key_id() {
        let key_id1 = make_key_id(1);
        let key_id2 = make_key_id(2);
        // 4 quadruples for key 1
        let ids = BTreeSet::from_iter([
            QuadrupleId::new(1),
            QuadrupleId::new(3),
            QuadrupleId::new(4),
            QuadrupleId::new(5),
        ]);
        let height = Height::from(1);
        // 4 contexts for key 1 and 1 context for key 2
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id1.clone(), None),
            fake_context(2, key_id2, Some((2, height))),
            fake_context(3, key_id1.clone(), None),
            fake_context(4, key_id1.clone(), None),
            fake_context(5, key_id1.clone(), None),
        ]);
        // With max_ongoing_signatures = 3 per key, the first 4 contexts should be matched in total.
        match_quadruples_basic_test(key_id1, ids, contexts, 3, height, 4);
    }

    #[test]
    fn test_matched_quadruples_arent_matched_again() {
        let key_id = make_key_id(1);
        // 4 quadruples for key 1
        let ids = BTreeSet::from_iter((1..5).map(QuadrupleId::new));
        let height = Height::from(1);
        // 5 contexts for key 1, 2 are already matched
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id.clone(), None),
            fake_context(2, key_id.clone(), Some((2, height))),
            fake_context(3, key_id.clone(), None),
            fake_context(4, key_id.clone(), Some((4, height))),
            fake_context(5, key_id.clone(), None),
        ]);
        // The first 4 contexts should be matched
        match_quadruples_basic_test(key_id, ids, contexts, 5, height, 4);
    }

    #[test]
    fn test_matched_quadruples_arent_overwritten() {
        let key_id = make_key_id(1);
        // 4 quadruples for key 1
        let ids = BTreeSet::from_iter((3..7).map(QuadrupleId::new));
        let height = Height::from(2);
        // 4 contexts for key 1, the first 3 are already matched
        let contexts = BTreeMap::from_iter([
            fake_context(1, key_id.clone(), Some((1, height))),
            fake_context(2, key_id.clone(), Some((2, height))),
            fake_context(3, key_id.clone(), Some((3, height))),
            fake_context(4, key_id.clone(), None),
        ]);
        // The first 4 contexts should be matched
        match_quadruples_basic_test(key_id, ids, contexts, 5, height, 4);
    }

    #[test]
    fn test_match_quadruples_doesnt_update_height() {
        let key_id = make_key_id(1);
        // 2 quadruples for key 1
        let ids = BTreeSet::from_iter([QuadrupleId::new(5), QuadrupleId::new(6)]);
        // 2 contexts for key 1, the first was already matched to the first quadruple
        // in the previous round.
        let mut contexts = BTreeMap::from_iter([
            fake_context(2, key_id.clone(), Some((5, Height::from(2)))),
            fake_context(4, key_id.clone(), None),
        ]);
        // Match them at height 3
        match_quadruples_by_key_id(key_id.clone(), ids, &mut contexts, 5, Height::from(3));

        // The first context should still be matched at the height of the previous round (height 2).
        let first_context = contexts.pop_first().unwrap().1;
        assert!(first_context
            .matched_quadruple
            .is_some_and(|(qid, h)| { qid == QuadrupleId::new(5) && h == Height::from(2) }));

        // The second context should have been matched to the second quadruple at height 3.
        let second_context = contexts.pop_first().unwrap().1;
        assert!(second_context
            .matched_quadruple
            .is_some_and(|(qid, h)| { qid == QuadrupleId::new(6) && h == Height::from(3) }));
    }
}
