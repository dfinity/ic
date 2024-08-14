use crate::DirectAuthenticationScheme::UserKeyPair;
use assert_matches::assert_matches;
use ic_canister_client_sender::Ed25519KeyPair;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::Signable;
use ic_types::messages::{Authentication, MessageId, SignedDelegation, UserSignature};

mod delegation_chain {
    use super::*;
    use crate::AuthenticationScheme::Delegation;
    use crate::{DelegationChain, HttpRequestBuilder};
    use ic_canister_client_sender::ed25519_public_key_to_der;
    use ic_types::{PrincipalId, Time, UserId};

    #[test]
    fn should_produce_a_valid_delegation_chain_of_length_2() {
        let rng = &mut reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(rng);
        let second_key_pair = Ed25519KeyPair::generate(rng);
        let third_key_pair = Ed25519KeyPair::generate(rng);
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
        let rng = &mut reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(rng);
        let second_key_pair = Ed25519KeyPair::generate(rng);
        let expected_sender = UserId::from(PrincipalId::new_self_authenticating(
            &ed25519_public_key_to_der(first_key_pair.public_key.to_vec()),
        ));
        let request = HttpRequestBuilder::new_update_call()
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
            if user_signature.signer_pubkey == ed25519_public_key_to_der(first_key_pair.public_key.to_vec())
        )
    }

    #[test]
    fn should_produce_http_request_signed_by_end_of_chain() {
        let rng = &mut reproducible_rng();
        let first_key_pair = Ed25519KeyPair::generate(rng);
        let second_key_pair = Ed25519KeyPair::generate(rng);

        let request = HttpRequestBuilder::new_update_call()
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
            if is_request_signature_correct(user_signature, &request.id(), &ed25519::types::PublicKeyBytes(second_key_pair.public_key))
        )
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

mod change_authentication {
    use super::*;
    use crate::DirectAuthenticationScheme::UserKeyPair;
    use crate::{AuthenticationScheme, HttpRequestBuilder};
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_types::messages::Blob;

    #[test]
    fn should_change_sender_while_having_correct_signature() {
        let rng = &mut reproducible_rng();
        let key_pair = Ed25519KeyPair::generate(rng);
        let new_sender = vec![42];

        let request = HttpRequestBuilder::new_update_call()
            .with_authentication(AuthenticationScheme::Direct(UserKeyPair(key_pair)))
            .with_authentication_sender(Blob(new_sender.clone()))
            .build();

        assert_eq!(request.sender().get().0.as_slice(), &new_sender);
        assert_matches!(request.authentication(), Authentication::Authenticated(user_signature)
            if is_request_signature_correct(user_signature, &request.id(), &ed25519::types::PublicKeyBytes(key_pair.public_key))
        );
    }

    #[test]
    fn should_change_sender_public_key_while_having_correct_signature() {
        let rng = &mut reproducible_rng();
        let key_pair = Ed25519KeyPair::generate(rng);
        let other_key_pair = Ed25519KeyPair::generate(rng);
        let other_public_key = UserKeyPair(other_key_pair).public_key_der();
        assert_ne!(key_pair, other_key_pair);

        let request = HttpRequestBuilder::new_update_call()
            .with_authentication(AuthenticationScheme::Direct(UserKeyPair(key_pair)))
            .with_authentication_sender_public_key(Some(Blob(other_public_key.clone())))
            .build();

        assert_matches!(request.authentication(), Authentication::Authenticated(user_signature)
        if user_signature.signer_pubkey == other_public_key &&
            is_request_signature_correct(user_signature, &request.id(), &ed25519::types::PublicKeyBytes(key_pair.public_key))
        );
    }

    #[test]
    fn should_corrupt_signature() {
        let rng = &mut reproducible_rng();
        let key_pair = Ed25519KeyPair::generate(rng);

        let valid_request = HttpRequestBuilder::new_update_call()
            .with_authentication(AuthenticationScheme::Direct(UserKeyPair(key_pair)))
            .build();
        let corrupted_request = HttpRequestBuilder::new_update_call()
            .with_authentication(AuthenticationScheme::Direct(UserKeyPair(key_pair)))
            .corrupt_authentication_sender_signature()
            .build();

        assert_matches!((valid_request.authentication(), corrupted_request.authentication()),
            (Authentication::Authenticated(valid_signature), Authentication::Authenticated(corrupted_signature))
            if valid_signature.signature != corrupted_signature.signature &&
                valid_signature.signer_pubkey == corrupted_signature.signer_pubkey &&
                is_request_signature_correct(valid_signature, &valid_request.id(), &ed25519::types::PublicKeyBytes(key_pair.public_key)) &&
                !is_request_signature_correct(corrupted_signature, &corrupted_request.id(), &ed25519::types::PublicKeyBytes(key_pair.public_key))
        )
    }
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
