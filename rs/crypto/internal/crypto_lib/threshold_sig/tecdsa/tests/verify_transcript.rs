use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

use ic_crypto_internal_threshold_sig_ecdsa_test_utils::*;

fn remove_dealing_and_verify(
    node_index: NodeIndex,
    setup: &ProtocolSetup,
    round: &ProtocolRound,
) -> bool {
    let mut modified_dealings = round.dealings.clone();
    modified_dealings.remove(&node_index);
    round.verify_transcript(setup, &modified_dealings).is_ok()
}

fn swap_dealing_and_verify(
    node_index0: NodeIndex,
    node_index1: NodeIndex,
    setup: &ProtocolSetup,
    round: &ProtocolRound,
) -> bool {
    let mut modified_dealings = round.dealings.clone();
    let dealing0 = modified_dealings.get(&node_index0).unwrap().clone();
    let dealing1 = modified_dealings.get(&node_index1).unwrap().clone();

    modified_dealings.insert(node_index0, dealing1);
    modified_dealings.insert(node_index1, dealing0);

    round.verify_transcript(setup, &modified_dealings).is_ok()
}

fn dup_dealing_and_verify(
    node_index: NodeIndex,
    setup: &ProtocolSetup,
    round: &ProtocolRound,
) -> bool {
    let mut modified_dealings = round.dealings.clone();
    let dealing = modified_dealings.get(&node_index).unwrap().clone();
    modified_dealings.insert(modified_dealings.len() as u32 + 1, dealing);
    round.verify_transcript(setup, &modified_dealings).is_ok()
}

#[test]
fn should_verify_transcript_reject_if_dealing_is_removed() -> Result<(), CanisterThresholdError> {
    let nodes = 4;
    let threshold = 2;
    let corrupted = 0;

    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, nodes, threshold, random_seed)?;
        let random = ProtocolRound::random(&setup, nodes, corrupted)?;
        let urandom = ProtocolRound::random_unmasked(&setup, nodes, corrupted)?;
        let reshared = ProtocolRound::reshare_of_masked(&setup, &random, nodes, corrupted)?;
        let product = ProtocolRound::multiply(&setup, &random, &reshared, nodes, corrupted)?;
        let reshared2 = ProtocolRound::reshare_of_unmasked(&setup, &reshared, nodes, corrupted)?;

        for node_index in 0..nodes as u32 {
            assert!(!remove_dealing_and_verify(node_index, &setup, &random));
        }

        for node_index in 0..nodes as u32 {
            assert!(!remove_dealing_and_verify(node_index, &setup, &urandom));
        }

        for node_index in 0..nodes as u32 {
            assert!(!remove_dealing_and_verify(node_index, &setup, &reshared));
        }

        for node_index in 0..nodes as u32 {
            assert!(!remove_dealing_and_verify(node_index, &setup, &product));
        }

        for node_index in 0..nodes as u32 {
            assert!(!remove_dealing_and_verify(node_index, &setup, &reshared2));
        }
    }

    Ok(())
}

#[test]
fn should_verify_transcript_reject_if_dealing_is_swapped() -> Result<(), CanisterThresholdError> {
    let nodes = 4;
    let threshold = 2;
    let corrupted = 0;

    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, nodes, threshold, random_seed)?;
        let random = ProtocolRound::random(&setup, nodes, corrupted)?;
        let urandom = ProtocolRound::random_unmasked(&setup, nodes, corrupted)?;
        let reshared = ProtocolRound::reshare_of_masked(&setup, &random, nodes, corrupted)?;
        let product = ProtocolRound::multiply(&setup, &random, &reshared, nodes, corrupted)?;
        let reshared2 = ProtocolRound::reshare_of_unmasked(&setup, &reshared, nodes, corrupted)?;

        /*
        Random dealings are combined via summation. As a consequence, it is possible
        for dealings to be swapped and the verification will still succeed. This is OK -
        verify_transcript should be thought of as verifying that the dealings and
        the transcript are *consistent with each other*, rather than asserting that
        this is the unique set of dealings that can create a particular transcript.
         */
        assert!(swap_dealing_and_verify(0, 1, &setup, &random));
        assert!(swap_dealing_and_verify(0, 1, &setup, &urandom));
        assert!(!swap_dealing_and_verify(0, 1, &setup, &reshared));
        assert!(!swap_dealing_and_verify(0, 1, &setup, &product));
        assert!(!swap_dealing_and_verify(0, 1, &setup, &reshared2));
    }

    Ok(())
}

#[test]
fn should_verify_transcript_reject_if_dealing_is_duplicated() -> Result<(), CanisterThresholdError>
{
    let nodes = 4;
    let threshold = 2;
    let corrupted = 0;

    let mut rng = &mut reproducible_rng();

    for cfg in TestConfig::all() {
        let random_seed = Seed::from_rng(&mut rng);
        let setup = ProtocolSetup::new(cfg, nodes, threshold, random_seed)?;
        let random = ProtocolRound::random(&setup, nodes, corrupted)?;
        let urandom = ProtocolRound::random_unmasked(&setup, nodes, corrupted)?;
        let reshared = ProtocolRound::reshare_of_masked(&setup, &random, nodes, corrupted)?;
        let product = ProtocolRound::multiply(&setup, &random, &reshared, nodes, corrupted)?;
        let reshared2 = ProtocolRound::reshare_of_unmasked(&setup, &reshared, nodes, corrupted)?;

        for node_index in 0..nodes as u32 {
            assert!(!dup_dealing_and_verify(node_index, &setup, &random));
        }

        for node_index in 0..nodes as u32 {
            assert!(!dup_dealing_and_verify(node_index, &setup, &urandom));
        }

        for node_index in 0..nodes as u32 {
            assert!(!dup_dealing_and_verify(node_index, &setup, &reshared));
        }

        for node_index in 0..nodes as u32 {
            assert!(!dup_dealing_and_verify(node_index, &setup, &product));
        }

        for node_index in 0..nodes as u32 {
            assert!(!dup_dealing_and_verify(node_index, &setup, &reshared2));
        }
    }

    Ok(())
}
