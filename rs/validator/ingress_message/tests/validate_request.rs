use assert_matches::assert_matches;
use ic_canister_client_sender::Ed25519KeyPair;
use ic_certification_test_utils::generate_root_of_trust;
use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
use ic_types::time::GENESIS;
use ic_types::CanisterId;
use ic_validator_http_request_test_utils::DirectAuthenticationScheme::{
    CanisterSignature, UserKeyPair,
};
use ic_validator_http_request_test_utils::{
    AuthenticationScheme, CanisterSigner, DelegationChain, HttpRequestBuilder,
};
use ic_validator_ingress_message::IngressMessageVerifier;
use ic_validator_ingress_message::TimeProvider;
use ic_validator_ingress_message::{HttpRequestVerifier, RequestValidationError};

const CANISTER_SIGNATURE_SEED: [u8; 1] = [42];
const CANISTER_ID_SIGNER: CanisterId = CanisterId::from_u64(1185);

#[test]
fn should_reject_request_when_expired_with_default_verifier() {
    let verifier = IngressMessageVerifier::default();
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(GENESIS)
        .with_authentication(AuthenticationScheme::Anonymous)
        .build();

    let result = verifier.validate_request(&request);

    assert_matches!(result, Err(RequestValidationError::InvalidIngressExpiry(_)))
}

#[test]
fn should_validate_anonymous_request() {
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(current_time)
        .with_authentication(AuthenticationScheme::Anonymous)
        .build();

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_without_delegation() {
    let mut rng = ReproducibleRng::new();
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let keypair = Ed25519KeyPair::generate(&mut rng);
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(current_time)
        .with_authentication(AuthenticationScheme::Direct(UserKeyPair(keypair)))
        .build();

    let result = verifier.validate_request(&request);

    assert_matches!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_with_delegation() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(current_time)
        .with_authentication(AuthenticationScheme::Delegation(
            DelegationChain::rooted_at(UserKeyPair(Ed25519KeyPair::generate(&mut rng)))
                .delegate_to(
                    UserKeyPair(Ed25519KeyPair::generate(&mut rng)),
                    current_time,
                )
                .delegate_to(
                    UserKeyPair(Ed25519KeyPair::generate(&mut rng)),
                    current_time,
                )
                .build(),
        ))
        .build();

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_from_canister() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let (root_public_key, root_secret_key) = generate_root_of_trust(&mut rng);
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .with_root_of_trust(root_public_key)
        .build();
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(current_time)
        .with_authentication(AuthenticationScheme::Direct(CanisterSignature(
            CanisterSigner {
                seed: CANISTER_SIGNATURE_SEED.to_vec(),
                canister_id: CANISTER_ID_SIGNER,
                root_public_key,
                root_secret_key,
            },
        )))
        .build();

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_with_delegation_from_canister() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let (root_public_key, root_secret_key) = generate_root_of_trust(&mut rng);
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .with_root_of_trust(root_public_key)
        .build();
    let request = HttpRequestBuilder::new_update_call()
        .with_ingress_expiry_at(current_time)
        .with_authentication(AuthenticationScheme::Delegation(
            DelegationChain::rooted_at(CanisterSignature(CanisterSigner {
                seed: CANISTER_SIGNATURE_SEED.to_vec(),
                canister_id: CANISTER_ID_SIGNER,
                root_public_key,
                root_secret_key,
            }))
            .delegate_to(
                UserKeyPair(Ed25519KeyPair::generate(&mut rng)),
                current_time,
            )
            .build(),
        ))
        .build();

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
}
