use assert_matches::assert_matches;

mod registry {
    use super::*;
    use crate::internal::{
        nns_root_public_key, registry_with_root_of_trust, DUMMY_REGISTRY_VERSION,
    };
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::crypto::CryptoRegistry;
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
    use ic_types::RegistryVersion;

    #[test]
    fn should_get_registry_with_nns_root_public_key() {
        let (registry_client, _registry_data) = registry_with_root_of_trust(nns_root_public_key());

        let retrieved_nns_root_public_key =
            crypto_logic_to_retrieve_root_subnet_pubkey(&registry_client, DUMMY_REGISTRY_VERSION);

        assert_matches!(retrieved_nns_root_public_key, Some(actual_key)
            if actual_key == nns_root_public_key());
    }

    #[test]
    fn should_get_registry_with_other_subnet_public_key() {
        let other_root_of_trust = parse_threshold_sig_key_from_der(&hex::decode("308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100923A67B791270CD8F5320212AE224377CF407D3A8A2F44F11FED5915A97EE67AD0E90BC382A44A3F14C363AD2006640417B4BBB3A304B97088EC6B4FC87A25558494FC239B47E129260232F79973945253F5036FD520DDABD1E2DE57ABFB40CB").unwrap()).unwrap();
        let (registry_client, _registry_data) = registry_with_root_of_trust(other_root_of_trust);

        let retrieved_root_of_trust =
            crypto_logic_to_retrieve_root_subnet_pubkey(&registry_client, DUMMY_REGISTRY_VERSION);

        assert_matches!(retrieved_root_of_trust, Some(actual_key)
            if actual_key == other_root_of_trust);
    }

    fn crypto_logic_to_retrieve_root_subnet_pubkey(
        registry: &FakeRegistryClient,
        registry_version: RegistryVersion,
    ) -> Option<ThresholdSigPublicKey> {
        let root_subnet_id = registry
            .get_root_subnet_id(registry_version)
            .expect("error retrieving root subnet ID")
            .expect("missing root subnet ID");
        registry
            .get_threshold_signing_public_key_for_subnet(root_subnet_id, registry_version)
            .expect("error retrieving root public key")
    }
}

mod delegations {
    use super::*;
    use crate::RequestValidationError::InvalidDelegation;
    use crate::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};
    use ic_canister_client_sender::Ed25519KeyPair;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::time::GENESIS;
    use ic_types::Time;
    use ic_validator_http_request_test_utils::DirectAuthenticationScheme::UserKeyPair;
    use ic_validator_http_request_test_utils::{
        AuthenticationScheme, DelegationChain, DirectAuthenticationScheme, HttpRequestBuilder,
    };
    use rand::{CryptoRng, Rng};

    const MAXIMUM_NUMBER_OF_DELEGATIONS: usize = 20; // !changing this number might be breaking!//
    const CURRENT_TIME: Time = GENESIS;

    //TODO CRP-1944: add positive test for delegation chain of length 0

    #[test]
    fn should_allow_delegation_chains_of_length_up_to_20() {
        let mut rng = reproducible_rng();
        let mut chain_builder = DelegationChain::rooted_at(random_user_key_pair(&mut rng));
        for number_of_delegations in 1..=20 {
            chain_builder = chain_builder.delegate_to(random_user_key_pair(&mut rng), CURRENT_TIME);
            let chain = chain_builder.clone().build();
            assert_eq!(chain.len(), number_of_delegations);

            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(chain.clone()))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(
                result,
                Ok(()),
                "verification of delegation chain {:?} of length {} failed",
                chain,
                number_of_delegations
            );
        }
    }

    #[test]
    fn should_fail_when_delegation_chain_length_just_above_boundary() {
        let mut rng = reproducible_rng();
        let request = HttpRequestBuilder::default()
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_authentication(AuthenticationScheme::Delegation(
                delegation_chain_of_length(
                    MAXIMUM_NUMBER_OF_DELEGATIONS + 1,
                    CURRENT_TIME,
                    &mut rng,
                ),
            ))
            .build();

        let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

        assert_matches!(result, Err(InvalidDelegation(_)))
    }

    #[test]
    fn should_fail_when_delegation_chain_too_long() {
        let mut rng = reproducible_rng();
        let number_of_delegations =
            rng.gen_range(MAXIMUM_NUMBER_OF_DELEGATIONS + 2..=2 * MAXIMUM_NUMBER_OF_DELEGATIONS);
        let request = HttpRequestBuilder::default()
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_authentication(AuthenticationScheme::Delegation(
                delegation_chain_of_length(number_of_delegations, CURRENT_TIME, &mut rng),
            ))
            .build();

        let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

        assert_matches!(result, Err(InvalidDelegation(_)))
    }

    fn delegation_chain_of_length<R: Rng + CryptoRng>(
        number_of_delegations: usize,
        delegation_expiration: Time,
        rng: &mut R,
    ) -> DelegationChain {
        assert!(
            number_of_delegations > 0,
            "expected a positive number of delegations"
        );
        let mut chain_builder = DelegationChain::rooted_at(random_user_key_pair(rng));
        for _ in 0..number_of_delegations {
            chain_builder =
                chain_builder.delegate_to(random_user_key_pair(rng), delegation_expiration);
        }
        let chain = chain_builder.build();
        assert_eq!(chain.len(), number_of_delegations);
        chain
    }

    fn random_user_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> DirectAuthenticationScheme {
        UserKeyPair(Ed25519KeyPair::generate(rng))
    }

    fn verifier_at_time(current_time: Time) -> IngressMessageVerifier {
        IngressMessageVerifier::builder()
            .with_time_provider(TimeProvider::Constant(current_time))
            .build()
    }
}
