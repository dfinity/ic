mod root_of_trust {
    use crate::internal::{nns_root_public_key, ConstantRootOfTrustProvider};
    use ic_types::crypto::threshold_sig::RootOfTrustProvider;

    #[test]
    fn should_retrieve_root_of_trust() {
        let root_of_trust = nns_root_public_key();
        let provider = ConstantRootOfTrustProvider::new(root_of_trust);

        let result = provider.root_of_trust();

        assert_eq!(result, Ok(root_of_trust));
    }
}

mod standalone_ingress_sig_verifier {
    use crate::internal::StandaloneIngressSigVerifier;
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::crypto::CanisterSigVerifier;
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_error_when_user_public_key_algorithm_id_wrong() {
        use strum::IntoEnumIterator;

        let verifier = StandaloneIngressSigVerifier;
        let mut rng = reproducible_rng();
        let mut data = new_valid_sig_and_crypto_component(&mut rng, false);

        AlgorithmId::iter()
            .filter(|algorithm_id| *algorithm_id != AlgorithmId::IcCanisterSignature)
            .for_each(|wrong_algorithm_id| {
                data.canister_pk.algorithm_id = wrong_algorithm_id;

                let result = verifier.verify_canister_sig(
                    &data.canister_sig,
                    &data.msg,
                    &data.canister_pk,
                    &data.root_of_trust,
                );

                assert_matches!(
                result,
                Err(CryptoError::AlgorithmNotSupported { algorithm, .. }) if algorithm == wrong_algorithm_id
            );
            });
    }
}
