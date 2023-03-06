mod delegation_chain {
    use crate::AuthenticationScheme::Delegation;
    use crate::DirectAuthenticationScheme::UserKeyPair;
    use crate::{DelegationChain, HttpRequestBuilder};
    use assert_matches::assert_matches;
    use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair};
    use ic_crypto_internal_basic_sig_ed25519 as ed25519;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::crypto::Signable;
    use ic_types::messages::{Authentication, MessageId, SignedDelegation, UserSignature};
    use ic_types::{PrincipalId, Time, UserId};

    #[test]
    fn should_produce_a_valid_delegation_chain_of_length_2() {
        let mut rng = reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(&mut rng);
        let second_key_pair = Ed25519KeyPair::generate(&mut rng);
        let third_key_pair = Ed25519KeyPair::generate(&mut rng);
        let first_delegation_expiration = Time::from_nanos_since_unix_epoch(1);
        let second_delegation_expiration = Time::from_nanos_since_unix_epoch(2);

        let chain = DelegationChain::rooted_at(UserKeyPair(first_key_pair))
            .delegate_to(UserKeyPair(second_key_pair), first_delegation_expiration)
            .delegate_to(UserKeyPair(third_key_pair), second_delegation_expiration)
            .build();

        assert_eq!(chain.signed_delegations.len(), 2);

        let first_delegation = &chain.signed_delegations[0];
        verify_signature(
            first_delegation,
            &ed25519::types::PublicKeyBytes(first_key_pair.public_key),
        );
        assert_eq!(
            first_delegation.delegation().pubkey(),
            &ed25519_public_key_to_der(second_key_pair.public_key.to_vec())
        );
        assert_eq!(
            first_delegation.delegation().expiration(),
            first_delegation_expiration
        );

        let second_delegation = &chain.signed_delegations[1];
        verify_signature(
            second_delegation,
            &ed25519::types::PublicKeyBytes(second_key_pair.public_key),
        );
        assert_eq!(
            second_delegation.delegation().pubkey(),
            &ed25519_public_key_to_der(third_key_pair.public_key.to_vec())
        );
        assert_eq!(
            second_delegation.delegation().expiration(),
            second_delegation_expiration
        );
    }

    #[test]
    fn should_produce_http_request_with_start_of_chain_as_sender_and_signer_pubkey() {
        let mut rng = reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(&mut rng);
        let second_key_pair = Ed25519KeyPair::generate(&mut rng);
        let expected_sender = UserId::from(PrincipalId::new_self_authenticating(
            &ed25519_public_key_to_der(first_key_pair.public_key.to_vec()),
        ));
        let request = HttpRequestBuilder::default()
            .with_authentication(Delegation(
                DelegationChain::rooted_at(UserKeyPair(first_key_pair))
                    .delegate_to(
                        UserKeyPair(second_key_pair),
                        Time::from_nanos_since_unix_epoch(1),
                    )
                    .build(),
            ))
            .build();

        assert_eq!(request.sender(), expected_sender);
        assert_matches!(request.authentication(), Authentication::Authenticated(user_signature)
            if user_signature.signer_pubkey == ed25519_public_key_to_der(first_key_pair.public_key.to_vec()))
    }

    #[test]
    fn should_produce_http_request_signed_by_end_of_chain() {
        let mut rng = reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(&mut rng);
        let second_key_pair = Ed25519KeyPair::generate(&mut rng);

        let request = HttpRequestBuilder::default()
            .with_authentication(Delegation(
                DelegationChain::rooted_at(UserKeyPair(first_key_pair))
                    .delegate_to(
                        UserKeyPair(second_key_pair),
                        Time::from_nanos_since_unix_epoch(1),
                    )
                    .build(),
            ))
            .build();

        assert_matches!(request.authentication(), Authentication::Authenticated(user_signature)
        if is_request_signature_correct(user_signature, &request.id(), &ed25519::types::PublicKeyBytes(second_key_pair.public_key)))
    }

    fn is_request_signature_correct(
        signature: &UserSignature,
        message_id: &MessageId,
        public_key: &ed25519::types::PublicKeyBytes,
    ) -> bool {
        ed25519::verify(
            &ed25519::types::SignatureBytes(
                signature
                    .signature
                    .clone()
                    .try_into()
                    .expect("invalid signature"),
            ),
            &message_id.as_signed_bytes(),
            public_key,
        )
        .is_ok()
    }

    fn verify_signature(
        delegation: &SignedDelegation,
        public_key: &ed25519::types::PublicKeyBytes,
    ) {
        assert_matches!(
            ed25519::verify(
                &ed25519::types::SignatureBytes(
                    delegation
                        .signature()
                        .0
                        .clone()
                        .try_into()
                        .expect("invalid signature")
                ),
                &delegation.delegation().as_signed_bytes(),
                public_key,
            ),
            Ok(())
        );
    }
}
