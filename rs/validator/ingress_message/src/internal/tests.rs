mod root_of_trust {
    use crate::AuthenticationError::InvalidCanisterSignature;
    use crate::internal::{
        ConstantRootOfTrustProvider, StandaloneIngressSigVerifier, nns_root_public_key,
    };
    use crate::{
        HttpRequestVerifier, IngressMessageVerifier, RequestValidationError, TimeProvider,
    };
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_crypto_test_utils_root_of_trust::{
        MockRootOfTrustProvider, MockRootOfTrustProviderError,
    };
    use ic_types::Time;
    use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider};
    use ic_types::time::GENESIS;
    use ic_validator_http_request_test_utils::AuthenticationScheme::Direct;
    use ic_validator_http_request_test_utils::{
        DirectAuthenticationScheme, HttpRequestBuilder, all_authentication_schemes,
        canister_signature_with_hard_coded_root_of_trust, hard_coded_root_of_trust,
    };
    use std::sync::Arc;

    #[test]
    fn should_retrieve_root_of_trust() {
        let root_of_trust = nns_root_public_key();
        let provider = ConstantRootOfTrustProvider::new(root_of_trust);

        let result = provider.root_of_trust();

        assert_eq!(result, Ok(root_of_trust));
    }

    #[test]
    fn should_not_query_root_of_trust_provider_for_non_canister_signature() {
        let rng = &mut reproducible_rng();
        let current_time = GENESIS;
        let mut root_of_trust_provider = MockRootOfTrustProvider::new();
        root_of_trust_provider.expect_root_of_trust().never();
        let verifier =
            verifier_at_time_with_root_of_trust_provider(current_time, root_of_trust_provider);
        let authentication_schemes = all_authentication_schemes(rng);
        for authentication_scheme in authentication_schemes {
            let request = HttpRequestBuilder::new_update_call()
                .with_ingress_expiry_at(current_time)
                .with_authentication(authentication_scheme.clone())
                .build();

            match authentication_scheme {
                Direct(DirectAuthenticationScheme::CanisterSignature(_)) => {
                    // tested separately
                }
                _ => {
                    assert_eq!(verifier.validate_request(&request), Ok(()));
                }
            }
        }
    }

    #[test]
    fn should_propagate_root_of_trust_error_for_canister_signature() {
        let current_time = GENESIS;
        let mut root_of_trust_provider = MockRootOfTrustProvider::new();
        let err_msg = "test: failed to retrieve root of trust";
        let root_of_trust_provider_error = MockRootOfTrustProviderError::new(err_msg);
        root_of_trust_provider
            .expect_root_of_trust()
            .times(1)
            .return_const(Err(root_of_trust_provider_error));
        let verifier =
            verifier_at_time_with_root_of_trust_provider(current_time, root_of_trust_provider);
        let canister_sig_auth_scheme = Direct(canister_signature_with_hard_coded_root_of_trust());
        let request = HttpRequestBuilder::new_update_call()
            .with_ingress_expiry_at(current_time)
            .with_authentication(canister_sig_auth_scheme)
            .build();

        assert_matches!(
            verifier.validate_request(&request),
            Err(RequestValidationError::InvalidSignature(InvalidCanisterSignature(err)))
            if err.contains(err_msg)
        );
    }

    #[test]
    fn should_query_root_of_trust_provider_for_canister_signature() {
        let current_time = GENESIS;
        let mut root_of_trust_provider = MockRootOfTrustProvider::new();
        root_of_trust_provider
            .expect_root_of_trust()
            .times(1)
            .return_const(Ok(IcRootOfTrust::from(
                hard_coded_root_of_trust().public_key,
            )));
        let verifier =
            verifier_at_time_with_root_of_trust_provider(current_time, root_of_trust_provider);
        let canister_sig_auth_scheme = Direct(canister_signature_with_hard_coded_root_of_trust());
        let request = HttpRequestBuilder::new_update_call()
            .with_ingress_expiry_at(current_time)
            .with_authentication(canister_sig_auth_scheme)
            .build();

        assert_eq!(verifier.validate_request(&request), Ok(()));
    }

    fn verifier_at_time_with_root_of_trust_provider(
        current_time: Time,
        root_of_trust_provider: MockRootOfTrustProvider,
    ) -> IngressMessageVerifier<MockRootOfTrustProvider> {
        IngressMessageVerifier {
            root_of_trust_provider,
            time_source: TimeProvider::Constant(current_time),
            validator: ic_validator::HttpRequestVerifierImpl::new(Arc::new(
                StandaloneIngressSigVerifier,
            )),
        }
    }
}

mod standalone_ingress_sig_verifier {
    use crate::internal::StandaloneIngressSigVerifier;
    use assert_matches::assert_matches;
    use ic_crypto_interfaces_sig_verification::CanisterSigVerifier;
    use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::{AlgorithmId, CryptoError};

    #[test]
    fn should_error_when_user_public_key_algorithm_id_wrong() {
        use strum::IntoEnumIterator;

        let verifier = StandaloneIngressSigVerifier;
        let rng = &mut reproducible_rng();
        let mut data = new_valid_sig_and_crypto_component(rng, false);

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
