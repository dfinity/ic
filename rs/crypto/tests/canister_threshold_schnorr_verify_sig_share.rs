use ic_crypto_test_utils_canister_threshold_sigs::schnorr::environment_with_sig_inputs;
use ic_crypto_test_utils_canister_threshold_sigs::CanisterThresholdSigTestEnvironment;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::{ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
};
use ic_types::{crypto::AlgorithmId, NodeId};
use rand::{CryptoRng, RngCore};

#[test]
fn should_verify_sig_share_successfully() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, rng);
        let verifier = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);

        let result = verifier.verify_sig_share(signer_id, &inputs, &sig_share);

        assert_eq!(result, Ok(()));
    }
}

fn signature_share_from_random_receiver<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    inputs: &ThresholdSchnorrSigInputs,
    rng: &mut R,
) -> (NodeId, ThresholdSchnorrSigShare) {
    let signer = env
        .nodes
        .random_filtered_by_receivers(inputs.receivers(), rng);
    signer.load_tschnorr_sig_transcripts(inputs);
    let sig_share = signer
        .create_sig_share(inputs)
        .expect("failed to create sig share");
    (signer.id(), sig_share)
}
