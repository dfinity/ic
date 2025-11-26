use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_registry_client_helpers::node_operator::PrincipalId;
use ic_types::CanisterId;
use ic_types::messages::Blob;
use ic_types::messages::HttpRequestContent;
use ic_types::{Time, UserId};
use ic_validator_http_request_test_utils::DirectAuthenticationScheme::{
    CanisterSignature, UserKeyPair,
};
use ic_validator_http_request_test_utils::{
    AuthenticationScheme, CANISTER_ID_SIGNER, CANISTER_SIGNATURE_SEED, CURRENT_TIME,
    CanisterSigner, DirectAuthenticationScheme, HttpRequestBuilder, HttpRequestEnvelopeContent,
    RootOfTrust, all_authentication_schemes, all_authentication_schemes_except, canister_signature,
    hard_coded_root_of_trust, random_user_key_pair,
};
use ic_validator_ingress_message::AuthenticationError;
use ic_validator_ingress_message::AuthenticationError::DelegationContainsCyclesError;
use ic_validator_ingress_message::AuthenticationError::DelegationTargetError;
use ic_validator_ingress_message::AuthenticationError::InvalidBasicSignature;
use ic_validator_ingress_message::AuthenticationError::InvalidCanisterSignature;
use ic_validator_ingress_message::RequestValidationError::MissingSignature;
use ic_validator_ingress_message::TimeProvider;
use ic_validator_ingress_message::{HttpRequestVerifier, RequestValidationError};
use ic_validator_ingress_message::{IngressMessageVerifier, IngressMessageVerifierBuilder};
use rand::{CryptoRng, Rng};
use std::fmt::Debug;
use std::str::FromStr;

const CANISTER_ID_WRONG_SIGNER: CanisterId = CanisterId::from_u64(1186);

trait EnvelopeContent<C>: HttpRequestEnvelopeContent<HttpRequestContentType = C> + Debug {}

impl<R, T: HttpRequestEnvelopeContent<HttpRequestContentType = R> + Debug> EnvelopeContent<R>
    for T
{
}

mod request_nonce {
    use super::*;
    use crate::RequestValidationError::NonceTooBigError;
    use rand::RngCore;

    #[test]
    fn should_check_request_nonce() {
        let rng = &mut ReproducibleRng::new();
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();
        let reasonable_nonce = {
            let random_bytes = rng.r#gen::<[u8; 32]>();
            let nonce_size = rng.random_range(0..=32);
            random_bytes[..nonce_size].to_vec()
        };
        let unreasonable_nonce = {
            let nonce_size = rng.random_range(33..100);
            let mut random_bytes = [0_u8; 100];
            rng.fill_bytes(&mut random_bytes);
            random_bytes[..nonce_size].to_vec()
        };
        let expected_error = Err(NonceTooBigError {
            num_bytes: unreasonable_nonce.len(),
            maximum: 32,
        });

        for scheme in all_authentication_schemes(rng) {
            test(
                &verifier,
                HttpRequestBuilder::new_update_call(),
                scheme.clone(),
                reasonable_nonce.clone(),
                Ok(()),
            );
            test(
                &verifier,
                HttpRequestBuilder::new_query(),
                scheme.clone(),
                reasonable_nonce.clone(),
                Ok(()),
            );
            test(
                &verifier,
                HttpRequestBuilder::new_read_state(),
                scheme.clone(),
                reasonable_nonce.clone(),
                Ok(()),
            );
            test(
                &verifier,
                HttpRequestBuilder::new_update_call(),
                scheme.clone(),
                unreasonable_nonce.clone(),
                expected_error.clone(),
            );
            test(
                &verifier,
                HttpRequestBuilder::new_query(),
                scheme.clone(),
                unreasonable_nonce.clone(),
                expected_error.clone(),
            );
            test(
                &verifier,
                HttpRequestBuilder::new_read_state(),
                scheme,
                unreasonable_nonce.clone(),
                expected_error.clone(),
            );
        }

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            scheme: AuthenticationScheme,
            nonce: Vec<u8>,
            expected_result: Result<(), RequestValidationError>,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(scheme)
                .with_ingress_expiry_at(max_ingress_expiry_at(CURRENT_TIME))
                .with_nonce(nonce)
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(expected_result, result, "Test with {builder_info} failed",);
        }
    }
}

mod ingress_expiry {
    use super::*;
    use crate::RequestValidationError::InvalidIngressExpiry;
    use ic_validator_http_request_test_utils::{AuthenticationScheme, HttpRequestBuilder};
    use std::time::Duration;

    #[test]
    fn should_error_when_request_expired() {
        let rng = &mut ReproducibleRng::new();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        for scheme in all_authentication_schemes(rng) {
            test(
                &verifier,
                HttpRequestBuilder::new_update_call(),
                scheme.clone(),
            );
        }
        for scheme in all_authentication_schemes_except(AuthenticationScheme::Anonymous, rng) {
            test(&verifier, HttpRequestBuilder::new_query(), scheme.clone());
            test(&verifier, HttpRequestBuilder::new_read_state(), scheme);
        }

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            scheme: AuthenticationScheme,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(scheme)
                .with_ingress_expiry_at(CURRENT_TIME.saturating_sub(Duration::from_nanos(1)))
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(InvalidIngressExpiry(_)),
                "Test with {builder_info} failed",
            );
        }
    }

    #[test]
    fn should_error_when_request_expiry_too_far_in_future() {
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let rng = &mut ReproducibleRng::new();
        for scheme in all_authentication_schemes(rng) {
            test(
                &verifier,
                HttpRequestBuilder::new_update_call(),
                scheme.clone(),
            );
        }
        for scheme in all_authentication_schemes_except(AuthenticationScheme::Anonymous, rng) {
            test(&verifier, HttpRequestBuilder::new_query(), scheme.clone());
            test(&verifier, HttpRequestBuilder::new_read_state(), scheme);
        }

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            scheme: AuthenticationScheme,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(scheme)
                .with_ingress_expiry_at(
                    max_ingress_expiry_at(CURRENT_TIME) + Duration::from_nanos(1),
                )
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(InvalidIngressExpiry(_)),
                "Test with {builder_info} failed",
            );
        }
    }

    #[test]
    fn should_accept_request_when_expiry_within_acceptable_bounds() {
        let rng = &mut ReproducibleRng::new();
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();
        let acceptable_expiry = Time::from_nanos_since_unix_epoch(rng.random_range(
            CURRENT_TIME.as_nanos_since_unix_epoch()
                ..=max_ingress_expiry_at(CURRENT_TIME).as_nanos_since_unix_epoch(),
        ));

        for scheme in all_authentication_schemes(rng) {
            test(
                &verifier,
                HttpRequestBuilder::new_update_call(),
                scheme.clone(),
                acceptable_expiry,
            );
            test(
                &verifier,
                HttpRequestBuilder::new_query(),
                scheme.clone(),
                acceptable_expiry,
            );
            test(
                &verifier,
                HttpRequestBuilder::new_read_state(),
                scheme,
                acceptable_expiry,
            );
        }

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            scheme: AuthenticationScheme,
            acceptable_expiry: Time,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(scheme)
                .with_ingress_expiry_at(acceptable_expiry)
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_not_error_when_anonymous_read_state_request_expired() {
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let request = HttpRequestBuilder::new_read_state()
            .with_authentication(AuthenticationScheme::Anonymous)
            .with_ingress_expiry_at(CURRENT_TIME.saturating_sub(Duration::from_nanos(1)))
            .build();

        let result = verifier.validate_request(&request);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_not_error_when_system_query_expired() {
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let request = HttpRequestBuilder::new_query()
            .with_authentication(AuthenticationScheme::Anonymous)
            .with_ingress_expiry_at(CURRENT_TIME.saturating_sub(Duration::from_nanos(1)))
            .build();

        let result = verifier.validate_request(&request);

        assert_matches!(result, Ok(()));
    }
}

mod read_state_request {
    use super::*;
    use crate::RequestValidationError::{PathTooLongError, TooManyPathsError};
    use ic_crypto_tree_hash::{Label, Path};
    use rand::prelude::SliceRandom;
    use std::ops::RangeInclusive;

    const MAXIMUM_NUMBER_OF_PATHS: usize = 1_000; // !changing this number might be breaking!
    const MAXIMUM_NUMBER_OF_LABELS_PER_PATH: usize = 127; // !changing this number might be breaking!

    #[test]
    fn should_validate_read_state_requests_with_allowed_width_and_depth_of_paths() {
        let rng = &mut reproducible_rng();
        let paths = random_paths(
            rng,
            0..=MAXIMUM_NUMBER_OF_PATHS,
            0..=MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
        );
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();

        for scheme in all_authentication_schemes(rng) {
            let request = HttpRequestBuilder::new_read_state()
                .with_authentication(scheme)
                .with_ingress_expiry_at(max_ingress_expiry_at(CURRENT_TIME))
                .with_paths(paths.clone())
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_validate_read_state_request_with_paths_width_and_depth_at_boundaries() {
        let rng = &mut reproducible_rng();
        let paths_to_test: Vec<Vec<Path>> = vec![
            vec![],
            random_paths(
                rng,
                MAXIMUM_NUMBER_OF_PATHS..=MAXIMUM_NUMBER_OF_PATHS,
                MAXIMUM_NUMBER_OF_LABELS_PER_PATH..=MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
            ),
        ];
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();

        for paths in paths_to_test {
            for scheme in all_authentication_schemes(rng) {
                let request = HttpRequestBuilder::new_read_state()
                    .with_authentication(scheme)
                    .with_ingress_expiry_at(max_ingress_expiry_at(CURRENT_TIME))
                    .with_paths(paths.clone())
                    .build();

                let result = verifier.validate_request(&request);

                assert_eq!(result, Ok(()));
            }
        }
    }

    #[test]
    fn should_fail_when_single_path_too_deep() {
        let rng = &mut reproducible_rng();
        let (paths_with_one_too_deep, depth) = {
            let mut paths = random_paths(
                rng,
                0..=MAXIMUM_NUMBER_OF_PATHS - 1,
                0..=MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
            );
            let path_too_deep = random_path(
                rng,
                MAXIMUM_NUMBER_OF_LABELS_PER_PATH + 1..=2 * MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
            );
            let depth = path_too_deep.len();
            paths.push(path_too_deep);
            paths.shuffle(rng);
            assert!(paths.len() <= MAXIMUM_NUMBER_OF_PATHS);
            (paths, depth)
        };
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();

        for scheme in all_authentication_schemes(rng) {
            let request = HttpRequestBuilder::new_read_state()
                .with_authentication(scheme)
                .with_ingress_expiry_at(max_ingress_expiry_at(CURRENT_TIME))
                .with_paths(paths_with_one_too_deep.clone())
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(
                result,
                Err(PathTooLongError {
                    length: depth,
                    maximum: MAXIMUM_NUMBER_OF_LABELS_PER_PATH
                })
            );
        }
    }

    #[test]
    fn should_fail_when_too_many_paths() {
        let rng = &mut reproducible_rng();
        let paths = random_paths(
            rng,
            MAXIMUM_NUMBER_OF_PATHS + 1..=2 * MAXIMUM_NUMBER_OF_PATHS,
            0..=MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
        );
        let verifier = default_verifier()
            .with_root_of_trust(hard_coded_root_of_trust().public_key)
            .build();

        for scheme in all_authentication_schemes(rng) {
            let request = HttpRequestBuilder::new_read_state()
                .with_authentication(scheme)
                .with_ingress_expiry_at(max_ingress_expiry_at(CURRENT_TIME))
                .with_paths(paths.clone())
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(
                result,
                Err(TooManyPathsError {
                    length: paths.len(),
                    maximum: MAXIMUM_NUMBER_OF_PATHS
                })
            );
        }
    }

    fn random_paths<R: Rng + CryptoRng>(
        rng: &mut R,
        num_paths_range: RangeInclusive<usize>,
        num_labels_range: RangeInclusive<usize>,
    ) -> Vec<Path> {
        let num_paths = rng.random_range(num_paths_range);
        let mut paths = Vec::with_capacity(num_paths);
        for _ in 0..num_paths {
            paths.push(random_path(rng, num_labels_range.clone()));
        }
        assert_eq!(paths.len(), num_paths);
        paths
    }

    fn random_path<R: Rng + CryptoRng>(
        rng: &mut R,
        num_labels_range: RangeInclusive<usize>,
    ) -> Path {
        let num_labels = rng.random_range(num_labels_range);
        let mut labels = Vec::with_capacity(num_labels);
        for _ in 0..num_labels {
            labels.push(random_label(rng));
        }
        let path = Path::from(labels);
        assert_eq!(path.len(), num_labels);
        path
    }

    fn random_label<R: Rng + CryptoRng>(rng: &mut R) -> Label {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Label::from(bytes)
    }
}

mod anonymous_request {
    use super::*;
    use crate::RequestValidationError::AnonymousSignatureNotAllowed;
    use ic_canister_client_sender::Ed25519KeyPair;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_validator_http_request_test_utils::AuthenticationScheme::{Anonymous, Direct};

    #[test]
    fn should_validate_anonymous_request() {
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call());
        test(&verifier, HttpRequestBuilder::new_query());
        test(&verifier, HttpRequestBuilder::new_read_state());

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(Anonymous)
                .with_ingress_expiry_at(CURRENT_TIME)
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_error_if_sender_not_anonymous_principal_in_unsigned_request() {
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call());
        test(&verifier, HttpRequestBuilder::new_query());
        test(&verifier, HttpRequestBuilder::new_read_state());

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let non_anonymous_user_id =
                UserId::from(PrincipalId::from_str("bfozs-kwa73-7nadi").expect("invalid user id"));
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_authentication(Anonymous)
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication_sender(Blob(non_anonymous_user_id.get().as_slice().to_vec()))
                .build();
            assert_eq!(request.sender(), non_anonymous_user_id);

            let result = verifier.validate_request(&request);

            assert_matches!(
                        result,
                        Err(MissingSignature(user_id)) if user_id == non_anonymous_user_id,
                        "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_error_when_anonymous_request_signed() {
        let rng = &mut ReproducibleRng::new();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(UserKeyPair(Ed25519KeyPair::generate(rng))))
                .with_authentication_sender_being_anonymous()
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(AnonymousSignatureNotAllowed),
                "Test with {builder_info} failed"
            );
        }
    }
}

mod authenticated_requests_direct_ed25519 {
    use super::*;
    use crate::RequestValidationError::InvalidSignature;
    use crate::RequestValidationError::UserIdDoesNotMatchPublicKey;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_validator_http_request_test_utils::AuthenticationScheme::Direct;
    use ic_validator_http_request_test_utils::HttpRequestEnvelopeFactory;

    #[test]
    fn should_validate_signed_request() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(random_user_key_pair(rng)))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_error_when_signature_corrupted() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(random_user_key_pair(rng)))
                .corrupt_authentication_sender_signature()
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(result,
                        Err(InvalidSignature(AuthenticationError::InvalidBasicSignature(e))) if e.contains("Ed25519 signature could not be verified"),
                        "Test with {builder_info} failed")
        }
    }

    #[test]
    fn should_error_when_public_key_does_not_match_sender() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let correct_key_pair = auth_with_random_user_key_pair(rng);
            let other_key_pair = auth_with_random_user_key_pair(rng);
            assert_ne!(correct_key_pair, other_key_pair);
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(correct_key_pair)
                .with_authentication_sender_public_key(other_key_pair.sender_public_key())
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(UserIdDoesNotMatchPublicKey(_, _)),
                "Test with {builder_info} failed"
            )
        }
    }

    #[test]
    fn should_error_when_request_signed_by_other_key_pair() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let correct_key_pair = auth_with_random_user_key_pair(rng);
            let other_key_pair = auth_with_random_user_key_pair(rng);
            assert_ne!(correct_key_pair, other_key_pair);
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(correct_key_pair)
                .with_authentication_sender(other_key_pair.sender())
                .with_authentication_sender_public_key(other_key_pair.sender_public_key())
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(AuthenticationError::InvalidBasicSignature(e)))
                if e.contains("Ed25519 signature could not be verified"),
                "Test with {builder_info} failed"
            )
        }
    }
}

mod authenticated_requests_direct_canister_signature {
    use super::*;
    use crate::RequestValidationError::InvalidSignature;
    use crate::RequestValidationError::UserIdDoesNotMatchPublicKey;
    use ic_validator_http_request_test_utils::AuthenticationScheme::Direct;
    use ic_validator_http_request_test_utils::{HttpRequestEnvelopeFactory, flip_a_bit_mut};

    #[test]
    fn should_validate_request_signed_by_canister_with_nonempty_seed() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");

            let signer_with_nonempty_seed = CanisterSigner {
                seed: b"nonempty_seed".to_vec(),
                canister_id: CANISTER_ID_SIGNER,
                root_public_key: root_of_trust.public_key,
                root_secret_key: root_of_trust.secret_key,
            };
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer_with_nonempty_seed)))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_validate_request_signed_by_canister_with_empty_seed() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let signer_with_empty_seed = CanisterSigner {
                seed: vec![],
                canister_id: CANISTER_ID_SIGNER,
                root_public_key: root_of_trust.public_key,
                root_secret_key: root_of_trust.secret_key,
            };
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer_with_empty_seed)))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_error_when_root_of_trust_wrong() {
        let rng = &mut reproducible_rng();
        let verifier_root_of_trust = RootOfTrust::new_random(rng);
        let request_root_of_trust = RootOfTrust::new_random(rng);
        assert_ne!(
            verifier_root_of_trust.public_key,
            request_root_of_trust.public_key
        );
        let verifier = default_verifier()
            .with_root_of_trust(verifier_root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            request_root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            request_root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            request_root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(canister_signature(root_of_trust)))
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(InvalidSignature(InvalidCanisterSignature(_))),
                "Test with {builder_info} failed"
            );
        }
    }

    #[test]
    fn should_error_when_signature_corrupted() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(canister_signature(root_of_trust)))
                .corrupt_authentication_sender_signature()
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(InvalidSignature(InvalidCanisterSignature(_))),
                "Test with {builder_info} failed"
            );
        }
    }

    #[test]
    fn should_error_when_public_key_does_not_match_sender_because_seed_corrupted() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let signer = CanisterSigner {
                seed: CANISTER_SIGNATURE_SEED.to_vec(),
                canister_id: CANISTER_ID_SIGNER,
                root_public_key: root_of_trust.public_key,
                root_secret_key: root_of_trust.secret_key,
            };
            let signer_with_different_seed = {
                let mut other = signer.clone();
                flip_a_bit_mut(&mut other.seed);
                other
            };
            assert_ne!(signer, signer_with_different_seed);
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer)))
                .with_authentication_sender_public_key(
                    Direct(CanisterSignature(signer_with_different_seed)).sender_public_key(),
                )
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(UserIdDoesNotMatchPublicKey(_, _)),
                "Test with {builder_info} failed"
            );
        }
    }

    #[test]
    fn should_error_when_public_key_does_not_match_sender_because_canister_id_corrupted() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            root_of_trust.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_read_state(),
            root_of_trust,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            root_of_trust: RootOfTrust,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let signer = CanisterSigner {
                seed: CANISTER_SIGNATURE_SEED.to_vec(),
                canister_id: CANISTER_ID_SIGNER,
                root_public_key: root_of_trust.public_key,
                root_secret_key: root_of_trust.secret_key,
            };
            let signer_with_different_canister_id = {
                let mut other = signer.clone();
                other.canister_id = CANISTER_ID_WRONG_SIGNER;
                other
            };
            assert_ne!(signer, signer_with_different_canister_id);
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer)))
                .with_authentication_sender_public_key(
                    Direct(CanisterSignature(signer_with_different_canister_id))
                        .sender_public_key(),
                )
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(UserIdDoesNotMatchPublicKey(_, _)),
                "Test with {builder_info} failed"
            );
        }
    }
}

mod authenticated_requests_delegations {
    use super::*;
    use crate::RequestValidationError::InvalidDelegation;
    use crate::RequestValidationError::InvalidDelegationExpiry;
    use crate::RequestValidationError::{CanisterNotInDelegationTargets, InvalidSignature};
    use crate::{HttpRequestVerifier, RequestValidationError};
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::messages::{HttpRequest, Query, ReadState, SignedIngressContent};
    use ic_types::{CanisterId, Time};
    use ic_validator_http_request_test_utils::{
        AuthenticationScheme, DelegationChain, DelegationChainBuilder,
        HttpRequestEnvelopeContentWithCanisterId,
    };
    use rand::{CryptoRng, Rng};
    use std::time::Duration;

    const MAXIMUM_NUMBER_OF_DELEGATIONS: usize = 20; // !changing this number might be breaking!
    const MAXIMUM_NUMBER_OF_TARGETS: usize = 1_000; // !changing this number might be breaking!

    #[test]
    fn should_validate_empty_delegations() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        test(&verifier, HttpRequestBuilder::new_update_call(), rng);
        test(&verifier, HttpRequestBuilder::new_query(), rng);
        test(&verifier, HttpRequestBuilder::new_read_state(), rng);

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            rng: &mut ReproducibleRng,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent>,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(auth_with_random_user_key_pair(rng))
                .with_authentication_sender_delegations(Some(Vec::new()))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_validate_delegation_chains_of_length_up_to_20() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let mut chain_builder = DelegationChain::rooted_at(random_user_key_pair(rng));
        for number_of_delegations in 1..=MAXIMUM_NUMBER_OF_DELEGATIONS {
            chain_builder = chain_builder.delegate_to(random_user_key_pair(rng), CURRENT_TIME);
            let chain = chain_builder.clone().build();
            assert_eq!(chain.len(), number_of_delegations);

            test_all_request_types_with_delegation_chain(
                &verifier,
                chain.clone(),
                |result, builder_info| {
                    assert_eq!(
                        result,
                        Ok(()),
                        "verification of delegation chain {chain:?} for request builder {builder_info} failed"
                    );
                },
            );
        }
    }

    #[test]
    fn should_validate_delegation_chains_of_length_up_to_20_containing_a_canister_signature() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();
        for number_of_delegations in 1..=MAXIMUM_NUMBER_OF_DELEGATIONS {
            let delegation_chain = delegation_chain_with_a_canister_signature(
                number_of_delegations,
                CURRENT_TIME,
                &root_of_trust,
                rng,
            )
            .build();

            test_all_request_types_with_delegation_chain(
                &verifier,
                delegation_chain.clone(),
                |result, builder_info| {
                    assert_eq!(
                        result,
                        Ok(()),
                        "verification of delegation chain {delegation_chain:?} for request builder {builder_info} failed"
                    );
                },
            );
        }
    }

    #[test]
    fn should_validate_delegation_chains_of_length_up_to_20_rooted_at_a_canister_signature() {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let verifier = default_verifier()
            .with_root_of_trust(root_of_trust.public_key)
            .build();
        let mut chain_builder = DelegationChain::rooted_at(canister_signature(root_of_trust));
        for number_of_delegations in 1..=MAXIMUM_NUMBER_OF_DELEGATIONS {
            chain_builder = chain_builder.delegate_to(random_user_key_pair(rng), CURRENT_TIME);
            let chain = chain_builder.clone().build();
            assert_eq!(chain.len(), number_of_delegations);

            test_all_request_types_with_delegation_chain(
                &verifier,
                chain.clone(),
                |result, builder_info| {
                    assert_eq!(
                        result,
                        Ok(()),
                        "verification of delegation chain {chain:?} for request builder {builder_info} failed"
                    );
                },
            );
        }
    }

    #[test]
    fn should_fail_when_delegation_chain_length_just_above_boundary() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let delegation_chain =
            delegation_chain_of_length(MAXIMUM_NUMBER_OF_DELEGATIONS + 1, CURRENT_TIME, rng)
                .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(_)),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_delegation_chain_too_long() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let number_of_delegations =
            rng.random_range(MAXIMUM_NUMBER_OF_DELEGATIONS + 2..=2 * MAXIMUM_NUMBER_OF_DELEGATIONS);
        let delegation_chain =
            delegation_chain_of_length(number_of_delegations, CURRENT_TIME, rng).build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(_)),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_a_single_delegation_expired() {
        let rng1 = &mut reproducible_rng();
        let rng2 = &mut rng1.fork();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let expired_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
        let one_ns = Duration::from_nanos(1);
        let expired = CURRENT_TIME.saturating_sub(one_ns);
        let not_expired = CURRENT_TIME;
        let delegation_chain = grow_delegation_chain(
            DelegationChain::rooted_at(random_user_key_pair(rng1)),
            MAXIMUM_NUMBER_OF_DELEGATIONS,
            |index| index == expired_delegation_index,
            |builder| builder.delegate_to(random_user_key_pair(rng1), expired),
            |builder| builder.delegate_to(random_user_key_pair(rng2), not_expired),
        )
        .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegationExpiry(msg)) if msg.contains(&format!("{expired}")),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_validate_non_expiring_delegation() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let never_expire = Time::from_nanos_since_unix_epoch(u64::MAX);
        let delegation_chain = DelegationChain::rooted_at(random_user_key_pair(rng))
            .delegate_to(random_user_key_pair(rng), never_expire)
            .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Ok(()),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_single_delegation_signature_corrupted() {
        let rng1 = &mut reproducible_rng();
        let rng2 = &mut rng1.fork();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let corrupted_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
        let mut key_pair_whose_signature_is_corrupted = None;
        let delegation_chain = grow_delegation_chain(
            DelegationChain::rooted_at(random_user_key_pair(rng1)),
            MAXIMUM_NUMBER_OF_DELEGATIONS,
            |index| index == corrupted_delegation_index,
            |builder| {
                key_pair_whose_signature_is_corrupted = Some(builder.current_end().clone());
                builder
                    .delegate_to(random_user_key_pair(rng1), CURRENT_TIME) // produce a statement signed by the secret key of `key_pair_whose_signature_is_corrupted`
                    .change_last_delegation(|delegation| delegation.corrupt_signature())
                // corrupt signature produced by secret key of `key_pair_whose_signature_is_corrupted`
            },
            |builder| builder.delegate_to(random_user_key_pair(rng2), CURRENT_TIME),
        )
        .build();
        let corrupted_public_key_hex = hex::encode(
            key_pair_whose_signature_is_corrupted
                .expect("one delegation was corrupted")
                .public_key_raw(),
        );

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                        result,
                        Err(InvalidDelegation(InvalidBasicSignature(msg)))
                        if msg.contains(&format!("Ed25519 signature could not be verified: public key {corrupted_public_key_hex}")),
                        "verification of delegation chain {:?} for request builder {} failed",
                        delegation_chain,
                        builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_delegations_do_not_form_a_chain() {
        let rng1 = &mut reproducible_rng();
        let rng2 = &mut rng1.fork();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let wrong_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
        let other_key_pair = random_user_key_pair(rng1);
        let delegation_chain = grow_delegation_chain(
            DelegationChain::rooted_at(random_user_key_pair(rng1)),
            MAXIMUM_NUMBER_OF_DELEGATIONS,
            |index| index == wrong_delegation_index,
            |builder| {
                builder
                    .delegate_to(random_user_key_pair(rng1), CURRENT_TIME)
                    .change_last_delegation(|last_delegation| {
                        last_delegation.with_public_key(other_key_pair.public_key_der())
                    })
            },
            |builder| builder.delegate_to(random_user_key_pair(rng2), CURRENT_TIME),
        )
        .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(InvalidBasicSignature(_))),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_with_invalid_delegation_when_intermediate_delegation_is_an_unverifiable_canister_signature()
     {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let other_root_of_trust = RootOfTrust::new_random(rng);
        assert_ne!(root_of_trust.public_key, other_root_of_trust.public_key);
        let verifier = default_verifier()
            .with_root_of_trust(other_root_of_trust.public_key)
            .build();
        let delegation_chain = delegation_chain_with_a_canister_signature(
            MAXIMUM_NUMBER_OF_DELEGATIONS - 1,
            CURRENT_TIME,
            &root_of_trust,
            rng,
        )
        .delegate_to(random_user_key_pair(rng), CURRENT_TIME)
        .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(InvalidCanisterSignature(_))),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_with_invalid_signature_when_last_delegation_is_an_unverifiable_canister_signature()
     {
        let rng = &mut reproducible_rng();
        let root_of_trust = RootOfTrust::new_random(rng);
        let other_root_of_trust = RootOfTrust::new_random(rng);
        assert_ne!(root_of_trust.public_key, other_root_of_trust.public_key);
        let verifier = default_verifier()
            .with_root_of_trust(other_root_of_trust.public_key)
            .build();
        let delegation_chain =
            delegation_chain_of_length(MAXIMUM_NUMBER_OF_DELEGATIONS - 1, CURRENT_TIME, rng)
                .delegate_to(canister_signature(root_of_trust), CURRENT_TIME)
                .build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            delegation_chain.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidSignature(InvalidCanisterSignature(_))),
                    "verification of delegation chain {:?} for request builder {} failed",
                    delegation_chain,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_validate_request_when_canister_id_among_all_targets() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let requested_canister_id = CanisterId::from(42);
        let delegation_chain = DelegationChain::rooted_at(random_user_key_pair(rng))
            .delegate_to_with_targets(
                random_user_key_pair(rng),
                CURRENT_TIME,
                vec![
                    CanisterId::from(41),
                    requested_canister_id,
                    CanisterId::from(43),
                ],
            )
            .delegate_to(random_user_key_pair(rng), CURRENT_TIME)
            .delegate_to_with_targets(
                random_user_key_pair(rng),
                CURRENT_TIME,
                vec![requested_canister_id, CanisterId::from(43)],
            )
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            requested_canister_id,
            delegation_chain.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            requested_canister_id,
            delegation_chain,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            requested_canister_id: CanisterId,
            delegation_chain: DelegationChain,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent> + HttpRequestEnvelopeContentWithCanisterId,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_fail_when_requested_canister_id_not_among_all_targets() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let requested_canister_id = CanisterId::from(42);
        let delegation_chain = DelegationChain::rooted_at(random_user_key_pair(rng))
            .delegate_to_with_targets(
                random_user_key_pair(rng),
                CURRENT_TIME,
                vec![CanisterId::from(41), CanisterId::from(43)],
            )
            .delegate_to(random_user_key_pair(rng), CURRENT_TIME)
            .delegate_to_with_targets(
                random_user_key_pair(rng),
                CURRENT_TIME,
                vec![
                    CanisterId::from(41),
                    requested_canister_id,
                    CanisterId::from(43),
                ],
            )
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            requested_canister_id,
            delegation_chain.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            requested_canister_id,
            delegation_chain,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            requested_canister_id: CanisterId,
            delegation_chain: DelegationChain,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent> + HttpRequestEnvelopeContentWithCanisterId,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(CanisterNotInDelegationTargets(id)) if id == requested_canister_id,
                "Test with {builder_info} failed"
            );
        }
    }

    #[test]
    fn should_fail_when_targets_empty() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let requested_canister_id = CanisterId::from(42);
        let delegation_chain = DelegationChain::rooted_at(random_user_key_pair(rng))
            .delegate_to_with_targets(random_user_key_pair(rng), CURRENT_TIME, vec![])
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            requested_canister_id,
            delegation_chain.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            requested_canister_id,
            delegation_chain,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            requested_canister_id: CanisterId,
            delegation_chain: DelegationChain,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent> + HttpRequestEnvelopeContentWithCanisterId,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
                .build();

            let result = verifier.validate_request(&request);

            assert_matches!(
                result,
                Err(CanisterNotInDelegationTargets(id)) if id == requested_canister_id,
                "Test with {builder_info} failed"
            );
        }
    }

    #[test]
    fn should_accept_repeating_target() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let requested_canister_id = CanisterId::from(42);
        let delegation_chain = DelegationChain::rooted_at(random_user_key_pair(rng))
            .delegate_to_with_targets(
                random_user_key_pair(rng),
                CURRENT_TIME,
                vec![
                    CanisterId::from(41),
                    requested_canister_id,
                    requested_canister_id,
                    requested_canister_id,
                    CanisterId::from(43),
                    requested_canister_id,
                ],
            )
            .build();

        test(
            &verifier,
            HttpRequestBuilder::new_update_call(),
            requested_canister_id,
            delegation_chain.clone(),
        );
        test(
            &verifier,
            HttpRequestBuilder::new_query(),
            requested_canister_id,
            delegation_chain,
        );

        fn test<ReqContent, EnvContent, Verifier>(
            verifier: &Verifier,
            builder: HttpRequestBuilder<EnvContent>,
            requested_canister_id: CanisterId,
            delegation_chain: DelegationChain,
        ) where
            ReqContent: HttpRequestContent,
            EnvContent: EnvelopeContent<ReqContent> + HttpRequestEnvelopeContentWithCanisterId,
            Verifier: HttpRequestVerifier<ReqContent>,
        {
            let builder_info = format!("{builder:?}");
            let request = builder
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
                .build();

            let result = verifier.validate_request(&request);

            assert_eq!(result, Ok(()), "Test with {builder_info} failed");
        }
    }

    #[test]
    fn should_fail_when_delegations_self_signed() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let mut key_pairs = random_user_key_pairs(3, rng);
        let duplicated_key_pair = key_pairs[1].clone();
        key_pairs.insert(1, duplicated_key_pair.clone());
        let chain_with_self_signed_delegations =
            DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            chain_with_self_signed_delegations.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
                    if public_key == duplicated_key_pair.public_key_der(),
                    "verification of delegation chain {:?} for request builder {} failed",
                    chain_with_self_signed_delegations,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_start_of_delegations_self_signed() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let mut key_pairs = random_user_key_pairs(2, rng);
        let duplicated_key_pair = key_pairs[0].clone();
        key_pairs.insert(0, duplicated_key_pair.clone());
        let chain_with_self_signed_delegations =
            DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            chain_with_self_signed_delegations.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
                    if public_key == duplicated_key_pair.public_key_der(),
                    "verification of delegation chain {:?} for request builder {} failed",
                    chain_with_self_signed_delegations,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_delegation_chain_contains_a_cycle_with_start_of_chain() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let mut key_pairs = random_user_key_pairs(2, rng);
        let duplicated_key_pair = key_pairs[0].clone();
        key_pairs.push(duplicated_key_pair.clone());
        let chain_with_cycle = DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            chain_with_cycle.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
                    if public_key == duplicated_key_pair.public_key_der(),
                    "verification of delegation chain {:?} for request builder {} failed",
                    chain_with_cycle,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_delegation_chain_contains_a_cycle() {
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();
        let mut key_pairs = random_user_key_pairs(3, rng);
        let duplicated_key_pair = key_pairs[1].clone();
        key_pairs.push(duplicated_key_pair.clone());
        let chain_with_cycle = DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();

        test_all_request_types_with_delegation_chain(
            &verifier,
            chain_with_cycle.clone(),
            |result, builder_info| {
                assert_matches!(
                    result,
                    Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
                    if public_key == duplicated_key_pair.public_key_der(),
                    "verification of delegation chain {:?} for request builder {} failed",
                    chain_with_cycle,
                    builder_info
                );
            },
        );
    }

    #[test]
    fn should_fail_when_too_many_distinct_targets_in_delegation() {
        let mut targets = Vec::with_capacity(MAXIMUM_NUMBER_OF_TARGETS + 1);
        for i in 0..MAXIMUM_NUMBER_OF_TARGETS + 1 {
            targets.push(CanisterId::from_u64(i as u64))
        }
        let rng = &mut reproducible_rng();
        let verifier = verifier_at_time(CURRENT_TIME).build();

        let update_request = request_authenticated_by_delegation_with_targets(
            HttpRequestBuilder::new_update_call(),
            targets.clone(),
            rng,
        );
        let result = verifier.validate_request(&update_request);
        assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"));

        let query_request = request_authenticated_by_delegation_with_targets(
            HttpRequestBuilder::new_query(),
            targets,
            rng,
        );
        let result = verifier.validate_request(&query_request);
        assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"))
    }

    #[test]
    fn should_fail_when_too_many_same_targets_in_delegation() {
        let mut targets = Vec::with_capacity(MAXIMUM_NUMBER_OF_TARGETS + 1);
        for _ in 0..MAXIMUM_NUMBER_OF_TARGETS + 1 {
            targets.push(CanisterId::from_u64(0_u64))
        }
        let rng = &mut reproducible_rng();

        let update_request = request_authenticated_by_delegation_with_targets(
            HttpRequestBuilder::new_update_call(),
            targets.clone(),
            rng,
        );
        let result = verifier_at_time(CURRENT_TIME)
            .build()
            .validate_request(&update_request);
        assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"));

        let query_request = request_authenticated_by_delegation_with_targets(
            HttpRequestBuilder::new_query(),
            targets,
            rng,
        );
        let result = verifier_at_time(CURRENT_TIME)
            .build()
            .validate_request(&query_request);
        assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"))
    }

    fn request_authenticated_by_delegation_with_targets<ReqContent, EnvContent, R>(
        builder: HttpRequestBuilder<EnvContent>,
        targets: Vec<CanisterId>,
        rng: &mut R,
    ) -> HttpRequest<ReqContent>
    where
        ReqContent: HttpRequestContent,
        EnvContent: EnvelopeContent<ReqContent> + HttpRequestEnvelopeContentWithCanisterId,
        R: Rng + CryptoRng,
    {
        assert!(!targets.is_empty());
        builder
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_canister_id(Blob(targets[0].get().to_vec()))
            .with_authentication(AuthenticationScheme::Delegation(
                DelegationChain::rooted_at(random_user_key_pair(rng))
                    .delegate_to_with_targets(random_user_key_pair(rng), CURRENT_TIME, targets)
                    .build(),
            ))
            .build()
    }

    fn delegation_chain_of_length<R: Rng + CryptoRng>(
        number_of_delegations: usize,
        delegation_expiration: Time,
        rng: &mut R,
    ) -> DelegationChainBuilder {
        grow_delegation_chain(
            DelegationChain::rooted_at(random_user_key_pair(rng)),
            number_of_delegations,
            |_i| true,
            |builder| builder.delegate_to(random_user_key_pair(rng), delegation_expiration),
            |_builder| panic!("should not be called because predicate always true"),
        )
    }

    fn delegation_chain_with_a_canister_signature<R: Rng + CryptoRng>(
        number_of_delegations: usize,
        delegation_expiration: Time,
        root_of_trust: &RootOfTrust,
        rng: &mut R,
    ) -> DelegationChainBuilder {
        let canister_delegation_index = rng.random_range(1..=number_of_delegations);
        grow_delegation_chain(
            DelegationChain::rooted_at(random_user_key_pair(rng)),
            number_of_delegations,
            |index| index == canister_delegation_index,
            |builder| {
                builder.delegate_to(
                    canister_signature(root_of_trust.clone()),
                    delegation_expiration,
                )
            },
            |builder| builder.delegate_to(random_user_key_pair(rng), delegation_expiration),
        )
    }

    /// Grow a chain of delegations in two different manners depending
    /// on the index of the added delegations in the chain, starting at 1.
    fn grow_delegation_chain<
        Predicate: Fn(usize) -> bool,
        BuilderWhenTrue: FnMut(DelegationChainBuilder) -> DelegationChainBuilder,
        BuilderWhenFalse: FnMut(DelegationChainBuilder) -> DelegationChainBuilder,
    >(
        start: DelegationChainBuilder,
        number_of_delegations_to_add: usize,
        predicate: Predicate,
        mut delegation_when_true: BuilderWhenTrue,
        mut delegation_when_false: BuilderWhenFalse,
    ) -> DelegationChainBuilder {
        assert!(
            number_of_delegations_to_add > 0,
            "expected a positive number of delegations to add"
        );
        let mut chain_builder = start;
        let length_at_start = chain_builder.number_of_signed_delegations();
        for i in 1..=number_of_delegations_to_add {
            chain_builder = if predicate(i) {
                delegation_when_true(chain_builder)
            } else {
                delegation_when_false(chain_builder)
            }
        }
        let length_at_end = chain_builder.number_of_signed_delegations();
        assert_eq!(
            length_at_end - length_at_start,
            number_of_delegations_to_add
        );
        chain_builder
    }

    fn test_all_request_types_with_delegation_chain<
        Verifier: HttpRequestVerifier<SignedIngressContent>
            + HttpRequestVerifier<ReadState>
            + HttpRequestVerifier<Query>,
        F: FnMut(Result<(), RequestValidationError>, String),
    >(
        verifier: &Verifier,
        delegation_chain: DelegationChain,
        mut expect: F,
    ) {
        let builder = HttpRequestBuilder::new_update_call();
        let builder_info = format!("{builder:?}");
        let request = builder
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_authentication(AuthenticationScheme::Delegation(delegation_chain.clone()))
            .build();
        let result = verifier.validate_request(&request);
        expect(result, builder_info);

        let builder = HttpRequestBuilder::new_query();
        let builder_info = format!("{builder:?}");
        let request = builder
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_authentication(AuthenticationScheme::Delegation(delegation_chain.clone()))
            .build();
        let result = verifier.validate_request(&request);
        expect(result, builder_info);

        let builder = HttpRequestBuilder::new_read_state();
        let builder_info = format!("{builder:?}");
        let request = builder
            .with_ingress_expiry_at(CURRENT_TIME)
            .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
            .build();
        let result = verifier.validate_request(&request);
        expect(result, builder_info);
    }
}

fn auth_with_random_user_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> AuthenticationScheme {
    AuthenticationScheme::Direct(random_user_key_pair(rng))
}

fn random_user_key_pairs<R: Rng + CryptoRng>(
    number_of_kay_pairs: usize,
    rng: &mut R,
) -> Vec<DirectAuthenticationScheme> {
    assert!(number_of_kay_pairs > 0);
    let mut key_pairs = Vec::with_capacity(number_of_kay_pairs);
    for _ in 0..number_of_kay_pairs {
        key_pairs.push(random_user_key_pair(rng));
    }
    key_pairs
}

fn max_ingress_expiry_at(current_time: Time) -> Time {
    use ic_limits::{MAX_INGRESS_TTL, PERMITTED_DRIFT_AT_VALIDATOR};
    current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR
}

fn default_verifier() -> IngressMessageVerifierBuilder {
    IngressMessageVerifier::builder().with_time_provider(TimeProvider::Constant(CURRENT_TIME))
}

fn verifier_at_time(current_time: Time) -> IngressMessageVerifierBuilder {
    default_verifier().with_time_provider(TimeProvider::Constant(current_time))
}
