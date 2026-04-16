//! Tests for ECDSA signing.

use super::super::test_utilities::{SchedulerTest, SchedulerTestBuilder};
use super::super::*;
use super::make_ecdsa_key_id;
use candid::Encode;
use ic_management_canister_types_private::{
    DerivationPath, EcdsaKeyId, MasterPublicKeyId, Method, SignWithECDSAArgs,
};
use ic_replicated_state::metadata_state::subnet_call_context_manager::EcdsaMatchedPreSignature;
use ic_test_utilities_consensus::idkg::{key_transcript_for_tests, pre_signature_for_tests};
use ic_types::Height;
use ic_types::batch::AvailablePreSignatures;
use ic_types::consensus::idkg::{IDkgMasterPublicKeyId, PreSigId};
use ic_types::messages::CallbackId;

fn inject_ecdsa_signing_request(test: &mut SchedulerTest, key_id: &EcdsaKeyId) {
    let canister_id = test.create_canister();

    let payload = Encode!(&SignWithECDSAArgs {
        message_hash: [0; 32],
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: key_id.clone()
    })
    .unwrap();

    test.inject_call_to_ic00(
        Method::SignWithECDSA,
        payload.clone(),
        test.ecdsa_signature_fee().real(),
        canister_id,
        InputQueueType::RemoteSubnet,
    );
}

#[test]
fn test_sign_with_ecdsa_contexts_are_not_updated_without_quadruples() {
    let key_id = make_ecdsa_key_id(0);
    let mut test = SchedulerTestBuilder::new()
        .with_chain_key(MasterPublicKeyId::Ecdsa(key_id.clone()))
        .build();

    inject_ecdsa_signing_request(&mut test, &key_id);

    // Check that nonce isn't set in the following round
    for _ in 0..2 {
        test.execute_round(ExecutionRoundType::OrdinaryRound);

        let contexts = test
            .state()
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts();
        let sign_with_ecdsa_context = contexts.values().next().expect("Context should exist");

        // Check that quadruple and nonce are none
        assert!(sign_with_ecdsa_context.nonce.is_none());
        assert!(sign_with_ecdsa_context.requires_pre_signature());
    }
}

#[test]
fn test_sign_with_ecdsa_contexts_are_updated_with_quadruples() {
    let key_id = make_ecdsa_key_id(0);
    let master_key_id = MasterPublicKeyId::Ecdsa(key_id.clone()).try_into().unwrap();
    let mut test = SchedulerTestBuilder::new()
        .with_chain_key(MasterPublicKeyId::Ecdsa(key_id.clone()))
        .build();
    let pre_sig_id = PreSigId(0);
    let pre_sig = pre_signature_for_tests(&master_key_id);
    let pre_signatures = BTreeMap::from_iter([(pre_sig_id, pre_sig.clone())]);

    let key_transcript = key_transcript_for_tests(&master_key_id);
    test.deliver_pre_signatures(BTreeMap::from_iter([(
        master_key_id.clone(),
        AvailablePreSignatures {
            key_transcript: key_transcript.clone(),
            pre_signatures,
        },
    )]));

    // If the stash is enabled, deliver pre-signatures only once.
    // They should be stored in the stash and don't have to be delivered in every round.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    test.deliver_pre_signatures(BTreeMap::from_iter([(
        master_key_id.clone(),
        AvailablePreSignatures {
            key_transcript: key_transcript.clone(),
            pre_signatures: BTreeMap::new(),
        },
    )]));
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let stashes = test.state().pre_signature_stashes();
    assert_eq!(stashes.len(), 1);
    assert!(
        stashes[&master_key_id]
            .pre_signatures
            .contains_key(&pre_sig_id),
    );

    inject_ecdsa_signing_request(&mut test, &key_id);

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let contexts = test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();
    let sign_with_ecdsa_context = contexts.values().next().expect("Context should exist");

    let expected_height = Height::from(test.last_round().get());

    // Check that quadruple was matched
    assert_eq!(
        sign_with_ecdsa_context
            .ecdsa_args()
            .pre_signature
            .clone()
            .unwrap(),
        EcdsaMatchedPreSignature {
            id: pre_sig_id,
            height: expected_height,
            pre_signature: pre_sig.as_ecdsa().unwrap(),
            key_transcript: Arc::new(key_transcript.clone()),
        }
    );

    // Check that nonce is still none
    assert!(sign_with_ecdsa_context.nonce.is_none());

    // If pre-signatures were stored in the state, they should now have been consumed.
    let stashes = test.state().pre_signature_stashes();
    assert_eq!(stashes.len(), 1);
    assert!(stashes[&master_key_id].pre_signatures.is_empty());

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let contexts = test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();
    let sign_with_ecdsa_context = contexts.values().next().expect("Context should exist");

    // Check that quadruple is still matched
    assert_eq!(
        sign_with_ecdsa_context
            .ecdsa_args()
            .pre_signature
            .clone()
            .unwrap(),
        EcdsaMatchedPreSignature {
            id: pre_sig_id,
            height: expected_height,
            pre_signature: pre_sig.as_ecdsa().unwrap(),
            key_transcript: Arc::new(key_transcript),
        }
    );
    // Check that nonce is set
    let nonce = sign_with_ecdsa_context.nonce;
    assert!(nonce.is_some());

    test.execute_round(ExecutionRoundType::OrdinaryRound);
    let contexts = test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();
    let sign_with_ecdsa_context = contexts.values().next().expect("Context should exist");

    // Check that nonce wasn't changed
    let nonce = sign_with_ecdsa_context.nonce;
    assert_eq!(sign_with_ecdsa_context.nonce, nonce);
}

#[test]
fn test_sign_with_ecdsa_contexts_are_matched_under_multiple_keys() {
    let key_ids: Vec<_> = (0..3).map(make_ecdsa_key_id).collect();
    let master_key_ids: Vec<_> = key_ids
        .iter()
        .cloned()
        .map(MasterPublicKeyId::Ecdsa)
        .flat_map(IDkgMasterPublicKeyId::try_from)
        .collect();
    let mut test = SchedulerTestBuilder::new()
        .with_chain_keys(
            key_ids
                .iter()
                .cloned()
                .map(MasterPublicKeyId::Ecdsa)
                .collect(),
        )
        .build();

    // Deliver 2 quadruples for the first key, 1 for the second, 0 for the third
    let pre_sigs0 = BTreeMap::from_iter([
        (PreSigId(0), pre_signature_for_tests(&master_key_ids[0])),
        (PreSigId(1), pre_signature_for_tests(&master_key_ids[0])),
    ]);
    let key_transcript0 = key_transcript_for_tests(&master_key_ids[0]);
    let pre_sigs1 =
        BTreeMap::from_iter([(PreSigId(2), pre_signature_for_tests(&master_key_ids[1]))]);
    let key_transcript1 = key_transcript_for_tests(&master_key_ids[1]);
    let mut pre_signatures = BTreeMap::from_iter([
        (
            master_key_ids[0].clone(),
            AvailablePreSignatures {
                key_transcript: key_transcript0.clone(),
                pre_signatures: pre_sigs0.clone(),
            },
        ),
        (
            master_key_ids[1].clone(),
            AvailablePreSignatures {
                key_transcript: key_transcript1.clone(),
                pre_signatures: pre_sigs1.clone(),
            },
        ),
    ]);
    test.deliver_pre_signatures(pre_signatures.clone());

    // Pre-signatures are delivered only once.
    // They should be stored in the stash and don't have to be delivered in every round.
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    pre_signatures
        .values_mut()
        .for_each(|pre_sigs| pre_sigs.pre_signatures.clear());
    test.deliver_pre_signatures(pre_signatures);
    test.execute_round(ExecutionRoundType::OrdinaryRound);

    let stashes = test.state().pre_signature_stashes();
    assert_eq!(stashes.len(), 2);
    assert_eq!(stashes[&master_key_ids[0]].pre_signatures, pre_sigs0);
    assert_eq!(stashes[&master_key_ids[1]].pre_signatures, pre_sigs1);

    // Inject 3 contexts requesting the third, second and first key in order
    for i in (0..3).rev() {
        inject_ecdsa_signing_request(&mut test, &key_ids[i])
    }

    // Execute two rounds
    for _ in 0..2 {
        test.execute_round(ExecutionRoundType::OrdinaryRound);

        // Pre-signatures in the state should now have been consumed.
        let stashes = test.state().pre_signature_stashes();
        assert_eq!(stashes.len(), 2);
        assert_eq!(stashes[&master_key_ids[0]].pre_signatures.len(), 1);
        assert!(
            stashes[&master_key_ids[0]]
                .pre_signatures
                .contains_key(&PreSigId(1))
        );
        assert!(stashes[&master_key_ids[1]].pre_signatures.is_empty());
    }

    let sign_with_ecdsa_contexts = &test
        .state()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts();

    // First context (requesting key 3) should be unmatched
    let context0 = sign_with_ecdsa_contexts.get(&CallbackId::from(0)).unwrap();
    assert!(context0.nonce.is_none());
    assert!(context0.requires_pre_signature());

    // Remaining contexts should have been matched
    let expected_height = Height::from(test.last_round().get() - 1);
    let context1 = sign_with_ecdsa_contexts.get(&CallbackId::from(1)).unwrap();
    assert!(context1.nonce.is_some());
    assert_eq!(
        context1.ecdsa_args().pre_signature.clone().unwrap(),
        EcdsaMatchedPreSignature {
            id: *pre_sigs1.keys().next().unwrap(),
            height: expected_height,
            pre_signature: pre_sigs1.values().next().unwrap().as_ecdsa().unwrap(),
            key_transcript: Arc::new(key_transcript1),
        }
    );

    let context2 = sign_with_ecdsa_contexts.get(&CallbackId::from(2)).unwrap();
    assert!(context2.nonce.is_some());
    assert_eq!(
        context2.ecdsa_args().pre_signature.clone().unwrap(),
        EcdsaMatchedPreSignature {
            id: *pre_sigs0.keys().next().unwrap(),
            height: expected_height,
            pre_signature: pre_sigs0.values().next().unwrap().as_ecdsa().unwrap(),
            key_transcript: Arc::new(key_transcript0),
        }
    );
}
