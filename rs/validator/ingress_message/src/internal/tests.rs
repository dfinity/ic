use assert_matches::assert_matches;

mod validate_request {
    use super::*;
    use crate::internal::IngressMessageVerifierBuilder;
    use crate::RequestValidationError::MissingSignature;
    use crate::{HttpRequestVerifier, IngressMessageVerifier, TimeProvider};
    use ic_canister_client_sender::Ed25519KeyPair;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_registry_client_helpers::node_operator::PrincipalId;
    use ic_types::messages::Blob;
    use ic_types::time::GENESIS;
    use ic_types::CanisterId;
    use ic_types::{Time, UserId};
    use ic_validator_http_request_test_utils::DirectAuthenticationScheme::{
        CanisterSignature, UserKeyPair,
    };
    use ic_validator_http_request_test_utils::{
        hard_coded_root_of_trust, AuthenticationScheme, CanisterSigner, DirectAuthenticationScheme,
        HttpRequestBuilder, RootOfTrust,
    };
    use rand::{CryptoRng, Rng};
    use std::str::FromStr;

    const CURRENT_TIME: Time = GENESIS;
    const CANISTER_SIGNATURE_SEED: [u8; 1] = [42];
    const CANISTER_ID_SIGNER: CanisterId = CanisterId::from_u64(1185);
    const CANISTER_ID_WRONG_SIGNER: CanisterId = CanisterId::from_u64(1186);

    mod ingress_expiry {
        use super::*;
        use crate::RequestValidationError::InvalidIngressExpiry;
        use ic_validator_http_request_test_utils::{AuthenticationScheme, DelegationChain};
        use std::time::Duration;

        #[test]
        fn should_error_when_request_expired() {
            let mut rng = ReproducibleRng::new();
            for scheme in all_authentication_schemes(&mut rng) {
                let request = HttpRequestBuilder::default()
                    .with_authentication(scheme.clone())
                    .with_ingress_expiry_at(
                        CURRENT_TIME.saturating_sub_duration(Duration::from_nanos(1)),
                    )
                    .build();

                let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

                assert_matches!(
                    result,
                    Err(InvalidIngressExpiry(_)),
                    "Test with authentication {:?} failed",
                    scheme
                );
            }
        }

        #[test]
        fn should_error_when_request_expiry_too_far_in_future() {
            let mut rng = ReproducibleRng::new();
            for scheme in all_authentication_schemes(&mut rng) {
                let request = HttpRequestBuilder::default()
                    .with_authentication(scheme.clone())
                    .with_ingress_expiry_at(
                        max_ingress_expiry_at(CURRENT_TIME) + Duration::from_nanos(1),
                    )
                    .build();

                let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

                assert_matches!(
                    result,
                    Err(InvalidIngressExpiry(_)),
                    "Test with authentication {:?} failed",
                    scheme
                );
            }
        }

        #[test]
        fn should_accept_request_when_expiry_within_acceptable_bounds() {
            let mut rng = ReproducibleRng::new();
            let acceptable_expiry = Time::from_nanos_since_unix_epoch(rng.gen_range(
                CURRENT_TIME.as_nanos_since_unix_epoch()
                    ..=max_ingress_expiry_at(CURRENT_TIME).as_nanos_since_unix_epoch(),
            ));
            for scheme in all_authentication_schemes(&mut rng) {
                let request = HttpRequestBuilder::default()
                    .with_authentication(scheme.clone())
                    .with_ingress_expiry_at(acceptable_expiry)
                    .build();

                let result = default_verifier()
                    .with_root_of_trust(hard_coded_root_of_trust().public_key)
                    .build()
                    .validate_request(&request);

                assert_matches!(
                    result,
                    Ok(()),
                    "Test with authentication {:?} failed",
                    scheme
                );
            }
        }

        fn all_authentication_schemes<R: Rng + CryptoRng>(
            rng: &mut R,
        ) -> Vec<AuthenticationScheme> {
            use strum::EnumCount;

            let schemes = vec![
                AuthenticationScheme::Anonymous,
                AuthenticationScheme::Direct(random_user_key_pair(rng)),
                AuthenticationScheme::Direct(canister_signature_with_hard_coded_root_of_trust()),
                AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(rng))
                        .delegate_to(random_user_key_pair(rng), CURRENT_TIME)
                        .build(),
                ),
            ];
            assert_eq!(schemes.len(), AuthenticationScheme::COUNT + 1);
            schemes
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
            let request = HttpRequestBuilder::default()
                .with_authentication(Anonymous)
                .with_ingress_expiry_at(CURRENT_TIME)
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()));
        }

        #[test]
        fn should_error_if_sender_not_anonymous_principal_in_unsigned_request() {
            let non_anonymous_user_id =
                UserId::from(PrincipalId::from_str("bfozs-kwa73-7nadi").expect("invalid user id"));
            let request = HttpRequestBuilder::default()
                .with_authentication(Anonymous)
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication_sender(Blob(non_anonymous_user_id.get().as_slice().to_vec()))
                .build();
            assert_eq!(request.sender(), non_anonymous_user_id);

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(MissingSignature(user_id)) if user_id == non_anonymous_user_id);
        }

        #[test]
        fn should_error_when_anonymous_request_signed() {
            let mut rng = ReproducibleRng::new();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(UserKeyPair(Ed25519KeyPair::generate(&mut rng))))
                .with_authentication_sender_being_anonymous()
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(AnonymousSignatureNotAllowed));
        }
    }

    mod authenticated_requests_direct_ed25519 {
        use super::*;
        use crate::AuthenticationError;
        use crate::RequestValidationError::InvalidSignature;
        use crate::RequestValidationError::UserIdDoesNotMatchPublicKey;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use ic_validator_http_request_test_utils::AuthenticationScheme::Direct;
        use ic_validator_http_request_test_utils::HttpRequestEnvelopeFactory;

        #[test]
        fn should_validate_signed_request() {
            let mut rng = reproducible_rng();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(random_user_key_pair(&mut rng)))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()));
        }

        #[test]
        fn should_error_when_signature_corrupted() {
            let mut rng = reproducible_rng();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(random_user_key_pair(&mut rng)))
                .corrupt_authentication_sender_signature()
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(AuthenticationError::InvalidBasicSignature(e)))
                if e.contains("Ed25519 signature could not be verified"))
        }

        #[test]
        fn should_error_when_public_key_does_not_match_sender() {
            let mut rng = reproducible_rng();
            let correct_key_pair = auth_with_random_user_key_pair(&mut rng);
            let other_key_pair = auth_with_random_user_key_pair(&mut rng);
            assert_ne!(correct_key_pair, other_key_pair);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(correct_key_pair)
                .with_authentication_sender_public_key(other_key_pair.sender_public_key())
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(UserIdDoesNotMatchPublicKey(_, _)))
        }

        #[test]
        fn should_error_when_request_signed_by_other_key_pair() {
            let mut rng = reproducible_rng();
            let correct_key_pair = auth_with_random_user_key_pair(&mut rng);
            let other_key_pair = auth_with_random_user_key_pair(&mut rng);
            assert_ne!(correct_key_pair, other_key_pair);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(correct_key_pair)
                .with_authentication_sender(other_key_pair.sender())
                .with_authentication_sender_public_key(other_key_pair.sender_public_key())
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(AuthenticationError::InvalidBasicSignature(e)))
                if e.contains("Ed25519 signature could not be verified"))
        }
    }

    mod authenticated_requests_direct_canister_signature {
        use super::*;
        use crate::AuthenticationError::InvalidCanisterSignature;
        use crate::RequestValidationError::InvalidSignature;
        use crate::RequestValidationError::UserIdDoesNotMatchPublicKey;
        use ic_validator_http_request_test_utils::AuthenticationScheme::Direct;
        use ic_validator_http_request_test_utils::{flip_a_bit_mut, HttpRequestEnvelopeFactory};

        #[test]
        fn should_validate_request_signed_by_canister() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(canister_signature(root_of_trust.clone())))
                .build();

            let result = default_verifier()
                .with_root_of_trust(root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_eq!(result, Ok(()));
        }

        #[test]
        fn should_error_when_root_of_trust_wrong() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let another_root_of_trust = RootOfTrust::new_random(&mut rng);
            assert_ne!(root_of_trust.public_key, another_root_of_trust.public_key);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(canister_signature(root_of_trust)))
                .build();

            let result = default_verifier()
                .with_root_of_trust(another_root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(InvalidCanisterSignature(_))));
        }

        #[test]
        fn should_error_when_signature_corrupted() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(canister_signature(root_of_trust.clone())))
                .corrupt_authentication_sender_signature()
                .build();

            let result = default_verifier()
                .with_root_of_trust(root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(InvalidCanisterSignature(_))));
        }

        #[test]
        fn should_error_when_public_key_does_not_match_sender_because_seed_corrupted() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
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
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer)))
                .with_authentication_sender_public_key(
                    Direct(CanisterSignature(signer_with_different_seed)).sender_public_key(),
                )
                .build();

            let result = default_verifier()
                .with_root_of_trust(root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(UserIdDoesNotMatchPublicKey(_, _)));
        }

        #[test]
        fn should_error_when_public_key_does_not_match_sender_because_canister_id_corrupted() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
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
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(Direct(CanisterSignature(signer)))
                .with_authentication_sender_public_key(
                    Direct(CanisterSignature(signer_with_different_canister_id))
                        .sender_public_key(),
                )
                .build();

            let result = default_verifier()
                .with_root_of_trust(root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(UserIdDoesNotMatchPublicKey(_, _)));
        }
    }

    mod authenticated_requests_delegations {
        use super::*;
        use crate::AuthenticationError::DelegationContainsCyclesError;
        use crate::AuthenticationError::DelegationTargetError;
        use crate::AuthenticationError::InvalidBasicSignature;
        use crate::AuthenticationError::InvalidCanisterSignature;
        use crate::HttpRequestVerifier;
        use crate::RequestValidationError::InvalidDelegation;
        use crate::RequestValidationError::InvalidDelegationExpiry;
        use crate::RequestValidationError::{CanisterNotInDelegationTargets, InvalidSignature};
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
        use ic_types::messages::{HttpRequest, SignedIngressContent};
        use ic_types::time::GENESIS;
        use ic_types::{CanisterId, Time};
        use ic_validator_http_request_test_utils::{
            AuthenticationScheme, DelegationChain, DelegationChainBuilder, HttpRequestBuilder,
        };
        use rand::{CryptoRng, Rng};
        use std::time::Duration;

        const MAXIMUM_NUMBER_OF_DELEGATIONS: usize = 20; // !changing this number might be breaking!//
        const MAXIMUM_NUMBER_OF_TARGETS: usize = 1_000; // !changing this number might be breaking!//
        const CURRENT_TIME: Time = GENESIS;

        #[test]
        fn should_validate_empty_delegations() {
            let mut rng = reproducible_rng();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(auth_with_random_user_key_pair(&mut rng))
                .with_authentication_sender_delegations(Some(Vec::new()))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()))
        }

        #[test]
        fn should_validate_delegation_chains_of_length_up_to_20() {
            let mut rng = reproducible_rng();
            let mut chain_builder = DelegationChain::rooted_at(random_user_key_pair(&mut rng));
            for number_of_delegations in 1..=20 {
                chain_builder =
                    chain_builder.delegate_to(random_user_key_pair(&mut rng), CURRENT_TIME);
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
        fn should_validate_delegation_chains_of_length_up_to_20_containing_a_canister_signature() {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let delegation_chain = delegation_chain_with_a_canister_signature(
                MAXIMUM_NUMBER_OF_DELEGATIONS,
                CURRENT_TIME,
                root_of_trust.clone(),
                &mut rng,
            );
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain.build()))
                .build();

            let result = default_verifier()
                .with_root_of_trust(root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_eq!(result, Ok(()));
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
                    )
                    .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(_)))
        }

        #[test]
        fn should_fail_when_delegation_chain_too_long() {
            let mut rng = reproducible_rng();
            let number_of_delegations = rng
                .gen_range(MAXIMUM_NUMBER_OF_DELEGATIONS + 2..=2 * MAXIMUM_NUMBER_OF_DELEGATIONS);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(
                    delegation_chain_of_length(number_of_delegations, CURRENT_TIME, &mut rng)
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(_)))
        }

        #[test]
        fn should_fail_when_a_single_delegation_expired() {
            let mut rng1 = reproducible_rng();
            let mut rng2 = rng1.fork();
            let expired_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
            let one_ns = Duration::from_nanos(1);
            let expired = CURRENT_TIME.saturating_sub_duration(one_ns);
            let not_expired = CURRENT_TIME;
            let delegation_chain = grow_delegation_chain(
                DelegationChain::rooted_at(random_user_key_pair(&mut rng1)),
                MAXIMUM_NUMBER_OF_DELEGATIONS,
                |index| index == expired_delegation_index,
                |builder| builder.delegate_to(random_user_key_pair(&mut rng1), expired),
                |builder| builder.delegate_to(random_user_key_pair(&mut rng2), not_expired),
            );
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain.build()))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegationExpiry(msg)) if msg.contains(&format!("{expired}")))
        }

        #[test]
        fn should_validate_non_expiring_delegation() {
            let mut rng = reproducible_rng();
            let never_expire = Time::from_nanos_since_unix_epoch(u64::MAX);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(&mut rng))
                        .delegate_to(random_user_key_pair(&mut rng), never_expire)
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()));
        }

        #[test]
        fn should_fail_when_single_delegation_signature_corrupted() {
            let mut rng1 = reproducible_rng();
            let mut rng2 = rng1.fork();
            let corrupted_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
            let mut key_pair_whose_signature_is_corrupted = None;
            let delegation_chain = grow_delegation_chain(
                DelegationChain::rooted_at(random_user_key_pair(&mut rng1)),
                MAXIMUM_NUMBER_OF_DELEGATIONS,
                |index| index == corrupted_delegation_index,
                |builder| {
                    key_pair_whose_signature_is_corrupted = Some(builder.current_end().clone());
                    builder
                        .delegate_to(random_user_key_pair(&mut rng1), CURRENT_TIME) // produce a statement signed by the secret key of `key_pair_whose_signature_is_corrupted`
                        .change_last_delegation(|delegation| delegation.corrupt_signature())
                    // corrupt signature produced by secret key of `key_pair_whose_signature_is_corrupted`
                },
                |builder| builder.delegate_to(random_user_key_pair(&mut rng2), CURRENT_TIME),
            );
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain.build()))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(InvalidBasicSignature(msg)))
                    if msg.contains(&format!("Ed25519 signature could not be verified: public key {}",
                        hex::encode(key_pair_whose_signature_is_corrupted
                        .expect("no delegation was corrupted")
                        .public_key_raw()))))
        }

        #[test]
        fn should_fail_when_delegations_do_not_form_a_chain() {
            let mut rng1 = reproducible_rng();
            let mut rng2 = rng1.fork();
            let wrong_delegation_index = rng1.gen_range(1..=MAXIMUM_NUMBER_OF_DELEGATIONS);
            let other_key_pair = random_user_key_pair(&mut rng1);
            let delegation_chain = grow_delegation_chain(
                DelegationChain::rooted_at(random_user_key_pair(&mut rng1)),
                MAXIMUM_NUMBER_OF_DELEGATIONS,
                |index| index == wrong_delegation_index,
                |builder| {
                    builder
                        .delegate_to(random_user_key_pair(&mut rng1), CURRENT_TIME)
                        .change_last_delegation(|last_delegation| {
                            last_delegation.with_public_key(other_key_pair.public_key_der())
                        })
                },
                |builder| builder.delegate_to(random_user_key_pair(&mut rng2), CURRENT_TIME),
            );
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain.build()))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(InvalidBasicSignature(_))));
        }

        #[test]
        fn should_fail_with_invalid_delegation_when_intermediate_delegation_is_an_unverifiable_canister_signature(
        ) {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let other_root_of_trust = RootOfTrust::new_random(&mut rng);
            assert_ne!(root_of_trust.public_key, other_root_of_trust.public_key);
            let delegation_chain = delegation_chain_with_a_canister_signature(
                MAXIMUM_NUMBER_OF_DELEGATIONS - 1,
                CURRENT_TIME,
                root_of_trust,
                &mut rng,
            )
            .delegate_to(random_user_key_pair(&mut rng), CURRENT_TIME);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain.build()))
                .build();

            let result = default_verifier()
                .with_root_of_trust(other_root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(InvalidCanisterSignature(_))));
        }

        #[test]
        fn should_fail_with_invalid_signature_when_last_delegation_is_an_unverifiable_canister_signature(
        ) {
            let mut rng = reproducible_rng();
            let root_of_trust = RootOfTrust::new_random(&mut rng);
            let other_root_of_trust = RootOfTrust::new_random(&mut rng);
            assert_ne!(root_of_trust.public_key, other_root_of_trust.public_key);
            let delegation_chain = delegation_chain_of_length(
                MAXIMUM_NUMBER_OF_DELEGATIONS - 1,
                CURRENT_TIME,
                &mut rng,
            )
            .delegate_to(canister_signature(root_of_trust), CURRENT_TIME)
            .build();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(delegation_chain))
                .build();

            let result = default_verifier()
                .with_root_of_trust(other_root_of_trust.public_key)
                .build()
                .validate_request(&request);

            assert_matches!(result, Err(InvalidSignature(InvalidCanisterSignature(_))));
        }

        #[test]
        fn should_validate_request_when_canister_id_among_all_targets() {
            let mut rng = reproducible_rng();
            let requested_canister_id = CanisterId::from(42);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(&mut rng))
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
                            CURRENT_TIME,
                            vec![
                                CanisterId::from(41),
                                requested_canister_id,
                                CanisterId::from(43),
                            ],
                        )
                        .delegate_to(random_user_key_pair(&mut rng), CURRENT_TIME)
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
                            CURRENT_TIME,
                            vec![requested_canister_id, CanisterId::from(43)],
                        )
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()))
        }

        #[test]
        fn should_fail_when_requested_canister_id_not_among_all_targets() {
            let mut rng = reproducible_rng();
            let requested_canister_id = CanisterId::from(42);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(&mut rng))
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
                            CURRENT_TIME,
                            vec![CanisterId::from(41), CanisterId::from(43)],
                        )
                        .delegate_to(random_user_key_pair(&mut rng), CURRENT_TIME)
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
                            CURRENT_TIME,
                            vec![
                                CanisterId::from(41),
                                requested_canister_id,
                                CanisterId::from(43),
                            ],
                        )
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(CanisterNotInDelegationTargets(id)) if id == requested_canister_id);
        }

        #[test]
        fn should_fail_when_targets_empty() {
            let mut rng = reproducible_rng();
            let requested_canister_id = CanisterId::from(42);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(&mut rng))
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
                            CURRENT_TIME,
                            vec![],
                        )
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(CanisterNotInDelegationTargets(id)) if id == requested_canister_id);
        }

        #[test]
        fn should_accept_repeating_target() {
            let mut rng = reproducible_rng();
            let requested_canister_id = CanisterId::from(42);
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_canister_id(Blob(requested_canister_id.get().to_vec()))
                .with_authentication(AuthenticationScheme::Delegation(
                    DelegationChain::rooted_at(random_user_key_pair(&mut rng))
                        .delegate_to_with_targets(
                            random_user_key_pair(&mut rng),
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
                        .build(),
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_eq!(result, Ok(()))
        }

        #[test]
        fn should_fail_when_delegations_self_signed() {
            let mut rng = reproducible_rng();
            let mut key_pairs = random_user_key_pairs(3, &mut rng);
            let duplicated_key_pair = key_pairs[1].clone();
            key_pairs.insert(1, duplicated_key_pair.clone());
            let chain_with_self_signed_delegations =
                DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(
                    chain_with_self_signed_delegations,
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
            if public_key == duplicated_key_pair.public_key_der())
        }

        #[test]
        fn should_fail_when_start_of_delegations_self_signed() {
            let mut rng = reproducible_rng();
            let mut key_pairs = random_user_key_pairs(2, &mut rng);
            let duplicated_key_pair = key_pairs[0].clone();
            key_pairs.insert(0, duplicated_key_pair.clone());
            let chain_with_self_signed_delegations =
                DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(
                    chain_with_self_signed_delegations,
                ))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationContainsCyclesError{public_key}))
                if public_key == duplicated_key_pair.public_key_der())
        }

        #[test]
        fn should_fail_when_delegation_chain_contains_a_cycle_with_start_of_chain() {
            let mut rng = reproducible_rng();
            let mut key_pairs = random_user_key_pairs(2, &mut rng);
            let duplicated_key_pair = key_pairs[0].clone();
            key_pairs.push(duplicated_key_pair.clone());
            let chain_with_cycle = DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(chain_with_cycle))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationContainsCyclesError {public_key}))
                if public_key == duplicated_key_pair.public_key_der())
        }

        #[test]
        fn should_fail_when_delegation_chain_contains_a_cycle() {
            let mut rng = reproducible_rng();
            let mut key_pairs = random_user_key_pairs(3, &mut rng);
            let duplicated_key_pair = key_pairs[1].clone();
            key_pairs.push(duplicated_key_pair.clone());
            let chain_with_cycle = DelegationChainBuilder::from((key_pairs, CURRENT_TIME)).build();
            let request = HttpRequestBuilder::default()
                .with_ingress_expiry_at(CURRENT_TIME)
                .with_authentication(AuthenticationScheme::Delegation(chain_with_cycle))
                .build();

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationContainsCyclesError {public_key}))
                if public_key == duplicated_key_pair.public_key_der())
        }

        #[test]
        fn should_fail_when_too_many_distinct_targets_in_delegation() {
            let mut targets = Vec::with_capacity(MAXIMUM_NUMBER_OF_TARGETS + 1);
            for i in 0..MAXIMUM_NUMBER_OF_TARGETS + 1 {
                targets.push(CanisterId::from_u64(i as u64))
            }
            let mut rng = reproducible_rng();
            let request = request_authenticated_by_delegation_with_targets(targets, &mut rng);

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"))
        }

        #[test]
        fn should_fail_when_too_many_same_targets_in_delegation() {
            let mut targets = Vec::with_capacity(MAXIMUM_NUMBER_OF_TARGETS + 1);
            for _ in 0..MAXIMUM_NUMBER_OF_TARGETS + 1 {
                targets.push(CanisterId::from_u64(0_u64))
            }
            let mut rng = reproducible_rng();
            let request = request_authenticated_by_delegation_with_targets(targets, &mut rng);

            let result = verifier_at_time(CURRENT_TIME).validate_request(&request);

            assert_matches!(result, Err(InvalidDelegation(DelegationTargetError(e))) if e.contains("expected at most 1000 targets"))
        }

        fn request_authenticated_by_delegation_with_targets<R: Rng + CryptoRng>(
            targets: Vec<CanisterId>,
            rng: &mut R,
        ) -> HttpRequest<SignedIngressContent> {
            assert!(!targets.is_empty());
            HttpRequestBuilder::default()
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
            root_of_trust: RootOfTrust,
            rng: &mut R,
        ) -> DelegationChainBuilder {
            let canister_delegation_index = rng.gen_range(1..=number_of_delegations);
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
    }

    fn auth_with_random_user_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> AuthenticationScheme {
        AuthenticationScheme::Direct(random_user_key_pair(rng))
    }

    fn random_user_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> DirectAuthenticationScheme {
        UserKeyPair(Ed25519KeyPair::generate(rng))
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

    fn canister_signature_with_hard_coded_root_of_trust() -> DirectAuthenticationScheme {
        canister_signature(hard_coded_root_of_trust())
    }

    fn canister_signature(root_of_trust: RootOfTrust) -> DirectAuthenticationScheme {
        CanisterSignature(CanisterSigner {
            seed: CANISTER_SIGNATURE_SEED.to_vec(),
            canister_id: CANISTER_ID_SIGNER,
            root_public_key: root_of_trust.public_key,
            root_secret_key: root_of_trust.secret_key,
        })
    }

    fn max_ingress_expiry_at(current_time: Time) -> Time {
        use ic_constants::{MAX_INGRESS_TTL, PERMITTED_DRIFT_AT_VALIDATOR};
        current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR
    }

    fn default_verifier() -> IngressMessageVerifierBuilder {
        IngressMessageVerifier::builder().with_time_provider(TimeProvider::Constant(CURRENT_TIME))
    }

    fn verifier_at_time(current_time: Time) -> IngressMessageVerifier {
        default_verifier()
            .with_time_provider(TimeProvider::Constant(current_time))
            .build()
    }
}

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

mod root_of_trust {
    use crate::internal::{nns_root_public_key, ConstantRootOfTrustProvider};
    use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider};

    #[test]
    fn should_retrieve_root_of_trust() {
        let root_of_trust = nns_root_public_key();
        let provider = ConstantRootOfTrustProvider::new(root_of_trust);

        let result = provider.root_of_trust();

        assert_eq!(result, Ok(IcRootOfTrust::from(root_of_trust)));
    }
}
