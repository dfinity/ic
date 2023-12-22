use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    mock_transcript, mock_unmasked_transcript_type,
};
use crate::crypto::tests::set_of;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

#[test]
fn should_return_true_if_receiver_for_single_receiver() {
    let rng = &mut reproducible_rng();
    let local_node_id = node_id_from_u64(42);
    let receivers = set_of(&[local_node_id]);
    let transcript = mock_transcript(Some(receivers), mock_unmasked_transcript_type(rng), rng);
    assert!(transcript.has_receiver(local_node_id));
}

#[test]
fn should_return_true_if_receiver_for_multiple_receivers() {
    let rng = &mut reproducible_rng();
    let local_node_id = node_id_from_u64(42);
    let receivers = set_of(&[
        node_id_from_u64(4),
        node_id_from_u64(34),
        local_node_id,
        node_id_from_u64(1),
    ]);
    let transcript = mock_transcript(Some(receivers), mock_unmasked_transcript_type(rng), rng);
    assert!(transcript.has_receiver(local_node_id));
}

#[test]
fn should_return_true_if_receiver_for_duplicate_receivers() {
    let rng = &mut reproducible_rng();
    let local_node_id = node_id_from_u64(42);
    let receivers = set_of(&[
        node_id_from_u64(4),
        local_node_id,
        node_id_from_u64(1),
        node_id_from_u64(34),
        local_node_id,
        node_id_from_u64(1),
    ]);
    let transcript = mock_transcript(Some(receivers), mock_unmasked_transcript_type(rng), rng);
    assert!(transcript.has_receiver(local_node_id));
}

#[test]
fn should_return_false_if_not_receiver_for_single_receiver() {
    let rng = &mut reproducible_rng();
    let local_node_id = node_id_from_u64(42);
    let receivers = set_of(&[node_id_from_u64(34)]);
    let transcript = mock_transcript(Some(receivers), mock_unmasked_transcript_type(rng), rng);
    assert!(!transcript.has_receiver(local_node_id));
}

#[test]
fn should_return_false_if_not_receiver_for_multiple_receivers() {
    let rng = &mut reproducible_rng();
    let local_node_id = node_id_from_u64(42);
    let receivers = set_of(&[
        node_id_from_u64(4),
        node_id_from_u64(34),
        node_id_from_u64(99),
        node_id_from_u64(1),
    ]);
    let transcript = mock_transcript(Some(receivers), mock_unmasked_transcript_type(rng), rng);
    assert!(!transcript.has_receiver(local_node_id));
}

fn node_id_from_u64(node_id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(node_id))
}
