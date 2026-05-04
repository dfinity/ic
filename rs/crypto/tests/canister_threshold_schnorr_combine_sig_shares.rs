use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_threshold_sigs::{
    random_crypto_component_not_in_receivers, schnorr::environment_with_sig_inputs,
    schnorr_sig_share_from_each_receiver,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::ThresholdSchnorrSigVerifier;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::error::ThresholdSchnorrCombineSigSharesError;

#[test]
fn should_combine_sig_shares_successfully() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result = combiner.combine_sig_shares(&inputs.as_ref(), &sig_shares);

        assert_matches!(result, Ok(_));
    }
}

#[test]
fn should_fail_combining_sig_shares_with_too_few_shares() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let too_few_sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref())
            .into_iter()
            .take(inputs.reconstruction_threshold().get() as usize - 1)
            .collect();
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result = combiner.combine_sig_shares(&inputs.as_ref(), &too_few_sig_shares);

        assert_matches!(
            result,
            Err(ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold {threshold, share_count})
                if threshold == inputs.reconstruction_threshold().get() && share_count == (threshold as usize - 1)
        );
    }
}
