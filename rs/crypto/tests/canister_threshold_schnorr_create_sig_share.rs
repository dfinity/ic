use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_threshold_sigs::schnorr::environment_with_sig_inputs;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::ThresholdSchnorrSigner;
use ic_types::crypto::AlgorithmId;

#[test]
fn should_create_signature_share_successfully_with_new_key() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let receiver = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        receiver.load_tschnorr_sig_transcripts(&inputs);
        let result = receiver.create_sig_share(&inputs);
        assert_matches!(result, Ok(_));
    }
}
