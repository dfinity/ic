use ic_crypto::get_master_public_key_from_transcript;
use ic_crypto_internal_threshold_sig_ecdsa_test_utils::verify_bip340_signature_using_third_party;
use ic_crypto_tecdsa::derive_threshold_public_key;
use ic_crypto_test_utils_canister_threshold_sigs::{
    random_crypto_component_not_in_receivers, run_tschnorr_protocol,
    schnorr::environment_with_sig_inputs, schnorr_sig_share_from_each_receiver,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::ThresholdSchnorrSigVerifier;
use ic_types::crypto::AlgorithmId;

#[test]
fn should_verify_combined_sig() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs);
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result = verifier_crypto_component.verify_combined_sig(&inputs, &signature);

        assert_eq!(result, Ok(()));
    }
}

#[test]
fn should_verify_combined_signature_with_usual_basic_sig_verification() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let combined_sig = run_tschnorr_protocol(&env, &inputs, rng);
        let master_public_key = get_master_public_key_from_transcript(inputs.key_transcript())
            .expect("Master key extraction failed");
        let canister_public_key =
            derive_threshold_public_key(&master_public_key, inputs.derivation_path())
                .expect("Public key derivation failed");

        match alg {
            AlgorithmId::ThresholdSchnorrBip340 => {
                assert!(verify_bip340_signature_using_third_party(
                    &canister_public_key.public_key,
                    &combined_sig.signature,
                    inputs.message()
                ))
            }
            alg if alg.is_threshold_schnorr() => {
                panic!("this test is not implemented for {:?}", alg)
            }
            _ => panic!("unexpected algorithm {:?}", alg),
        }
    }
}
