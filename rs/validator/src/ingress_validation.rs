use crate::webauthn::validate_webauthn_sig;
use ic_crypto::{user_public_key_from_bytes, KeyBytesContentType};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_types::crypto::{CanisterSig, CanisterSigOf};
use ic_types::{
    crypto::{AlgorithmId, BasicSig, BasicSigOf, CryptoError, UserPublicKey},
    ingress::MAX_INGRESS_TTL,
    malicious_flags::MaliciousFlags,
    messages::{
        Authentication, Delegation, HasCanisterId, HttpRequest, HttpRequestContent, MessageId,
        SignedDelegation, UserSignature, WebAuthnSignature,
    },
    CanisterId, PrincipalId, RegistryVersion, Time, UserId,
};
use std::{collections::BTreeSet, convert::TryFrom, fmt};

/// Validates the `request` and that the sender is authorized to send
/// a message to the receiving canister.
///
/// See notes on request validity in the crate docs.
pub fn validate_request<C: HttpRequestContent + HasCanisterId>(
    request: &HttpRequest<C>,
    ingress_signature_verifier: &dyn IngressSigVerifier,
    current_time: Time,
    registry_version: RegistryVersion,
    malicious_flags: &MaliciousFlags,
) -> Result<(), RequestValidationError> {
    #[cfg(feature = "malicious_code")]
    {
        if malicious_flags.maliciously_disable_ingress_validation {
            return Ok(());
        }
    }

    get_authorized_canisters(
        request,
        ingress_signature_verifier,
        current_time,
        registry_version,
        malicious_flags,
    )
    .and_then(|targets| {
        if targets.contains(&request.content().canister_id()) {
            Ok(())
        } else {
            Err(CanisterNotInDelegationTargets(
                request.content().canister_id(),
            ))
        }
    })
}

/// Returns the set of canisters that the request is authorized to act on.
///
/// The request must be valid for this call to be successful. See notes on
/// request validity in the crate docs.
pub fn get_authorized_canisters<C: HttpRequestContent>(
    request: &HttpRequest<C>,
    ingress_signature_verifier: &dyn IngressSigVerifier,
    current_time: Time,
    registry_version: RegistryVersion,
    #[allow(unused_variables)] malicious_flags: &MaliciousFlags,
) -> Result<CanisterIdSet, RequestValidationError> {
    #[cfg(feature = "malicious_code")]
    {
        if malicious_flags.maliciously_disable_ingress_validation {
            return Ok(CanisterIdSet::All);
        }
    }

    validate_ingress_expiry(request, current_time)?;
    validate_user_id_and_signature(
        ingress_signature_verifier,
        &request.sender(),
        &request.id(),
        match request.authentication() {
            Authentication::Anonymous => None,
            Authentication::Authenticated(signature) => Some(signature),
        },
        current_time,
        registry_version,
    )
}

/// Error in validating an [HttpRequest].
#[derive(Debug)]
pub enum RequestValidationError {
    InvalidIngressExpiry(String),
    InvalidDelegationExpiry(String),
    UserIdDoesNotMatchPublicKey(UserId, Vec<u8>),
    InvalidSignature(AuthenticationError),
    InvalidDelegation(AuthenticationError),
    MissingSignature(UserId),
    AnonymousSignatureNotAllowed,
    CanisterNotInDelegationTargets(CanisterId),
}

impl fmt::Display for RequestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidIngressExpiry(msg) => write!(f, "{}", msg),
            InvalidDelegationExpiry(msg) => write!(f, "{}", msg),
            UserIdDoesNotMatchPublicKey(user_id, pubkey) => write!(
                f,
                "The user id {} does not match the public key {}",
                user_id,
                hex::encode(pubkey)
            ),
            InvalidSignature(err) => write!(f, "Invalid signature: {}", err),
            InvalidDelegation(err) => write!(f, "Invalid delegation: {}", err),
            MissingSignature(user_id) => write!(f, "Missing signature from user: {}", user_id),
            AnonymousSignatureNotAllowed => {
                write!(f, "Signature is not allowed for the anonymous user")
            }
            CanisterNotInDelegationTargets(canister_id) => write!(
                f,
                "Canister {} is not one of the delegation targets",
                canister_id
            ),
        }
    }
}

/// Error in verifying the signature or authentication part of a request.
#[derive(Debug)]
pub enum AuthenticationError {
    InvalidBasicSignature(CryptoError),
    InvalidCanisterSignature(CryptoError),
    InvalidPublicKey(CryptoError),
    WebAuthnError(String),
    DelegationTargetError(String),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidBasicSignature(err) => write!(f, "Invalid basic signature: {}", err),
            InvalidCanisterSignature(err) => write!(f, "Invalid canister signature: {}", err),
            InvalidPublicKey(err) => write!(f, "Invalid public key: {}", err),
            WebAuthnError(msg) => write!(f, "{}", msg),
            DelegationTargetError(msg) => write!(f, "{}", msg),
        }
    }
}

use AuthenticationError::*;
use RequestValidationError::*;

/// An enum representing a set of canister IDs.
#[derive(Debug, Eq, PartialEq)]
pub enum CanisterIdSet {
    /// The entire domain of canister IDs.
    All,
    /// A subet of canister IDs.
    Some(BTreeSet<CanisterId>),
}

impl CanisterIdSet {
    pub fn contains(&self, canister_id: &CanisterId) -> bool {
        match self {
            Self::All => true,
            Self::Some(c) => c.contains(canister_id),
        }
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::All, other) => other,
            (me, Self::All) => me,
            (Self::Some(c1), Self::Some(c2)) => Self::Some(c1.intersection(&c2).cloned().collect()),
        }
    }
}

// Check if ingress_expiry is within a proper range with respect to the given
// time, i.e., it is not expired yet and is not too far in the future.
fn validate_ingress_expiry<C: HttpRequestContent>(
    request: &HttpRequest<C>,
    current_time: Time,
) -> Result<(), RequestValidationError> {
    let ingress_expiry = request.ingress_expiry();
    let provided_expiry = Time::from_nanos_since_unix_epoch(ingress_expiry);
    let min_allowed_expiry = current_time;
    let max_allowed_expiry = min_allowed_expiry + MAX_INGRESS_TTL;
    if !(min_allowed_expiry <= provided_expiry && provided_expiry <= max_allowed_expiry) {
        let msg = format!(
            "Specified ingress_expiry not within expected range:\n\
             Minimum allowed expiry: {}\n\
             Maximum allowed expiry: {}\n\
             Provided expiry:        {}\n\
             Local replica time:     {}",
            min_allowed_expiry,
            max_allowed_expiry,
            provided_expiry,
            chrono::Utc::now(),
        );
        return Err(InvalidIngressExpiry(msg));
    }
    Ok(())
}

// Check if any of the sender delegation has expired with respect to the
// `current_time`, and return an error if so.
fn validate_sender_delegation_expiry(
    sender_delegation: &Option<Vec<SignedDelegation>>,
    current_time: Time,
) -> Result<(), RequestValidationError> {
    if let Some(delegations) = &sender_delegation {
        for delegation in delegations.iter() {
            let expiry = delegation.delegation().expiration();
            if delegation.delegation().expiration() < current_time {
                return Err(InvalidDelegationExpiry(format!(
                    "Specified sender delegation has expired:\n\
                     Provided expiry:    {}\n\
                     Local replica time: {}",
                    expiry, current_time,
                )));
            }
        }
    }
    Ok(())
}

// Verifies that the user id matches the public key.  Returns an error if not.
fn validate_user_id(sender_pubkey: &[u8], id: &UserId) -> Result<(), RequestValidationError> {
    if id.get_ref() == &PrincipalId::new_self_authenticating(sender_pubkey) {
        Ok(())
    } else {
        Err(UserIdDoesNotMatchPublicKey(*id, sender_pubkey.to_vec()))
    }
}

// Verifies that the message is properly signed.
fn validate_signature(
    validator: &dyn IngressSigVerifier,
    message_id: &MessageId,
    signature: &UserSignature,
    current_time: Time,
    registry_version: RegistryVersion,
) -> Result<CanisterIdSet, RequestValidationError> {
    validate_sender_delegation_expiry(&signature.sender_delegation, current_time)?;
    let empty_vec = Vec::new();
    let signed_delegations = match &signature.sender_delegation {
        None => &empty_vec,
        Some(delegations) => delegations,
    };

    let (pubkey, targets) = validate_delegations(
        validator,
        signed_delegations.as_slice(),
        signature.signer_pubkey.clone(),
        registry_version,
    )?;

    let (pk, pk_type) = public_key_from_bytes(&pubkey).map_err(InvalidSignature)?;

    match pk_type {
        KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose
        | KeyBytesContentType::RsaSha256PublicKeyDerWrappedCose => {
            let webauthn_sig = WebAuthnSignature::try_from(signature.signature.as_slice())
                .map_err(WebAuthnError)
                .map_err(InvalidSignature)?;
            validate_webauthn_sig(validator, &webauthn_sig, message_id, &pk)
                .map_err(WebAuthnError)
                .map_err(InvalidSignature)?;
            Ok(targets)
        }
        KeyBytesContentType::Ed25519PublicKeyDer
        | KeyBytesContentType::EcdsaP256PublicKeyDer
        | KeyBytesContentType::EcdsaSecp256k1PublicKeyDer => {
            let basic_sig = BasicSigOf::from(BasicSig(signature.signature.clone()));
            validate_signature_plain(validator, message_id, &basic_sig, &pk)
                .map_err(InvalidSignature)?;
            Ok(targets)
        }
        KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer => {
            let canister_sig = CanisterSigOf::from(CanisterSig(signature.signature.clone()));
            validator
                .verify_canister_sig(&canister_sig, message_id, &pk, registry_version)
                .map_err(InvalidCanisterSignature)
                .map_err(InvalidSignature)?;
            Ok(targets)
        }
        KeyBytesContentType::RsaSha256PublicKeyDer => {
            Err(RequestValidationError::InvalidSignature(
                AuthenticationError::InvalidBasicSignature(CryptoError::AlgorithmNotSupported {
                    algorithm: AlgorithmId::RsaSha256,
                    reason: "RSA signatures are not allowed except in webauthn context".to_owned(),
                }),
            ))
        }
    }
}

fn validate_signature_plain(
    validator: &dyn IngressSigVerifier,
    message_id: &MessageId,
    signature: &BasicSigOf<MessageId>,
    pubkey: &UserPublicKey,
) -> Result<(), AuthenticationError> {
    validator
        .verify_basic_sig_by_public_key(signature, message_id, pubkey)
        .map_err(InvalidBasicSignature)
}

// Validate a chain of delegations.
// See https://sdk.dfinity.org/docs/interface-spec/index.html#_envelope_authentication
//
// If the delegations are valid, returns the public key used to sign the
// request as well as the set of canister IDs that the public key is valid for.
fn validate_delegations(
    validator: &dyn IngressSigVerifier,
    signed_delegations: &[SignedDelegation],
    mut pubkey: Vec<u8>,
    registry_version: RegistryVersion,
) -> Result<(Vec<u8>, CanisterIdSet), RequestValidationError> {
    // Initially, assume that the delegations target all possible canister IDs.
    let mut targets = CanisterIdSet::All;

    for sd in signed_delegations {
        let delegation = sd.delegation();
        let signature = sd.signature();

        let new_targets =
            validate_delegation(validator, signature, delegation, &pubkey, registry_version)
                .map_err(InvalidDelegation)?;
        // Restrict the canister targets to the ones specified in the delegation.
        targets = targets.intersect(new_targets);
        pubkey = delegation.pubkey().to_vec();
    }

    Ok((pubkey, targets))
}

fn validate_delegation(
    validator: &dyn IngressSigVerifier,
    signature: &[u8],
    delegation: &Delegation,
    pubkey: &[u8],
    registry_version: RegistryVersion,
) -> Result<CanisterIdSet, AuthenticationError> {
    let (pk, pk_type) = public_key_from_bytes(pubkey)?;

    match pk_type {
        KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose
        | KeyBytesContentType::RsaSha256PublicKeyDerWrappedCose => {
            let webauthn_sig = WebAuthnSignature::try_from(signature).map_err(WebAuthnError)?;
            validate_webauthn_sig(validator, &webauthn_sig, delegation, &pk)
                .map_err(WebAuthnError)?;
        }
        KeyBytesContentType::Ed25519PublicKeyDer
        | KeyBytesContentType::EcdsaP256PublicKeyDer
        | KeyBytesContentType::EcdsaSecp256k1PublicKeyDer
        | KeyBytesContentType::RsaSha256PublicKeyDer => {
            let basic_sig = BasicSigOf::from(BasicSig(signature.to_vec()));
            validator
                .verify_basic_sig_by_public_key(&basic_sig, delegation, &pk)
                .map_err(InvalidBasicSignature)?;
        }
        KeyBytesContentType::IcCanisterSignatureAlgPublicKeyDer => {
            let canister_sig = CanisterSigOf::from(CanisterSig(signature.to_vec()));
            validator
                .verify_canister_sig(&canister_sig, delegation, &pk, registry_version)
                .map_err(InvalidCanisterSignature)?;
        }
    }

    // Validation succeeded. Return the targets of this delegation.
    Ok(match delegation.targets().map_err(DelegationTargetError)? {
        None => CanisterIdSet::All,
        Some(targets) => CanisterIdSet::Some(targets),
    })
}

// Verifies correct user and signature.
fn validate_user_id_and_signature(
    ingress_signature_verifier: &dyn IngressSigVerifier,
    sender: &UserId,
    message_id: &MessageId,
    signature: Option<&UserSignature>,
    current_time: Time,
    registry_version: RegistryVersion,
) -> Result<CanisterIdSet, RequestValidationError> {
    match signature {
        None => {
            if sender.get().is_anonymous() {
                return Ok(CanisterIdSet::All);
            }
            Err(MissingSignature(*sender))
        }
        Some(signature) => {
            if sender.get().is_anonymous() {
                Err(AnonymousSignatureNotAllowed)
            } else {
                let sender_pubkey = &signature.signer_pubkey;
                validate_user_id(sender_pubkey, sender).and_then(|()| {
                    validate_signature(
                        ingress_signature_verifier,
                        message_id,
                        signature,
                        current_time,
                        registry_version,
                    )
                })
            }
        }
    }
}

fn public_key_from_bytes(
    pubkey: &[u8],
) -> Result<(UserPublicKey, KeyBytesContentType), AuthenticationError> {
    user_public_key_from_bytes(pubkey).map_err(InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_crypto::ed25519_public_key_to_der;
    use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
    use ic_test_utilities::types::ids::{canister_test_id, message_test_id, node_test_id};
    use ic_types::{
        messages::{Delegation, SignedDelegation, UserSignature},
        time::UNIX_EPOCH,
    };
    use maplit::btreeset;
    use std::time::Duration;

    fn mock_registry_version() -> RegistryVersion {
        RegistryVersion::from(0)
    }

    #[test]
    fn plain_authentication_correct_signature_passes() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";

        // Signed the message ID with the corresponding secret key:
        // LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
        let signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

        let user_signature = UserSignature {
            signature: base64::decode(signature).unwrap(),
            signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap())
                .unwrap(),
            sender_delegation: None,
        };

        assert!(validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            mock_registry_version()
        )
        .is_ok());

        // Same signature as above with empty delegations specified. Should also pass.
        let user_signature = UserSignature {
            signature: base64::decode(signature).unwrap(),
            signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap())
                .unwrap(),
            sender_delegation: Some(Vec::new()),
        };

        assert!(validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            mock_registry_version()
        )
        .is_ok());
    }

    #[test]
    fn plain_authentication_incorrect_signature_passes() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";

        // Incorrect signature. Correct signature should be:
        // "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";
        let signature =
        "nWfuICAf29zspOaoGUcn/xIFUtnUiZRsbhxgZywz6OzRTHKoY32sU78uE0z8UFcbInkzwDtw+4PP2JQrnwHtCw==";

        let user_signature = UserSignature {
            signature: base64::decode(signature).unwrap(),
            signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap())
                .unwrap(),
            sender_delegation: None,
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Err(InvalidSignature(InvalidBasicSignature(_)))
        );
    }

    #[test]
    fn plain_authentication_with_one_delegation() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        // In this scenario we have two keypairs:
        //
        // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
        // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
        //
        // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
        // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
        //
        // Keypair 1 delegates to keypair 2.

        let pk1 = ed25519_public_key_to_der(
            base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
        )
        .unwrap();
        let pk2 = ed25519_public_key_to_der(
            base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
        )
        .unwrap();
        let delegation = Delegation::new(pk2, UNIX_EPOCH);

        // Signature of sk1 for the delegation above.
        let delegation_signature = base64::decode(
        "QhNcIhRQalYnRK4WJ3KWIrfqMIC1RAiehoGU/rqDbfzvz4trSBH0THxJY+P7J7dJ63HPXiBa1vYnSfVjbpoCCg==",
    )
    .unwrap();

        // Signature of sk2 of the message id.
        let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

        let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

        let user_signature = UserSignature {
            signature: base64::decode(message_id_signature).unwrap(),
            signer_pubkey: pk1,
            sender_delegation: Some(vec![signed_delegation]),
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Ok(CanisterIdSet::All)
        );

        // Try verifying the signature in the future. It should fail because the
        // delegation would've expired.
        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH + Duration::from_secs(1),
                mock_registry_version()
            ),
            Err(RequestValidationError::InvalidDelegationExpiry(_))
        );
    }

    #[test]
    fn plain_authentication_with_one_scoped_delegation() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        // In this scenario we have two keypairs:
        //
        // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
        // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
        //
        // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
        // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
        //
        // Keypair 1 delegates to keypair 2.

        let pk1 = ed25519_public_key_to_der(
            base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
        )
        .unwrap();
        let pk2 = ed25519_public_key_to_der(
            base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
        )
        .unwrap();
        let delegation = Delegation::new_with_targets(pk2, UNIX_EPOCH, vec![canister_test_id(1)]);

        // Signature of sk1 for the delegation above.
        let delegation_signature = base64::decode(
        "yULx4bstJpKWTcymC3T9kQUVC0fD04pxuHtMSOH2c9NkM5AqplrRmJgeb92p583nuexafMS6SXWfmWszSo14CA==",
    )
    .unwrap();

        // Signature of sk2 of the message id.
        let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

        let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

        let user_signature = UserSignature {
            signature: base64::decode(message_id_signature).unwrap(),
            signer_pubkey: pk1,
            sender_delegation: Some(vec![signed_delegation]),
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Ok(CanisterIdSet::Some(set)) if set == btreeset! {canister_test_id(1)}
        );
    }

    #[test]
    fn plain_authentication_with_multiple_delegations() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        // In this scenario we have four keypairs:
        //
        // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
        // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
        //
        // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
        // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
        //
        // SK3: 0bQjDi/upCIujouLLPQOn2ePrvoVkMgG2SA8R3NQH4U=
        // PK3: 02aktrssfFxcxrf18Fx6nENqaxgVLC+e+x3Y3tunQPs=
        //
        // SK4: tgkM2ZIh4NE23/E6UgDhoUaxT+3FR8PiMxdSsC4yWR4=
        // PK4: b9k9ldofRsdXBrcfHoInQGhhtzbGCVBb9Kpcw2ij2Ck=
        //
        // Each keypair delegates to the one below it.
        let pk1 = ed25519_public_key_to_der(
            base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
        )
        .unwrap();
        let pk2 = ed25519_public_key_to_der(
            base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
        )
        .unwrap();
        let pk3 = ed25519_public_key_to_der(
            base64::decode("02aktrssfFxcxrf18Fx6nENqaxgVLC+e+x3Y3tunQPs=").unwrap(),
        )
        .unwrap();
        let pk4 = ed25519_public_key_to_der(
            base64::decode("b9k9ldofRsdXBrcfHoInQGhhtzbGCVBb9Kpcw2ij2Ck=").unwrap(),
        )
        .unwrap();

        // KP1 delegating to KP2.
        let delegation = Delegation::new_with_targets(
            pk2,
            UNIX_EPOCH + Duration::new(4, 0),
            vec![canister_test_id(1), canister_test_id(2)],
        );

        // Signature of SK1 for `delegation` above.
        let delegation_signature = base64::decode(
        "R1LC9wYXfuWn1BjTJHWF8ANyxyTVqEJzhybvOMxgn9gERpqdQoh+BhsLue3byTp7X1uEtc44QYKLIH1adajHCg==",
    )
    .unwrap();

        // KP2 delegating to KP3.
        let delegation_2 = Delegation::new(pk3, UNIX_EPOCH + Duration::new(2, 0));
        // Signature of SK2 for delegation_2
        let delegation_2_signature = base64::decode(
        "rP1xtpEK9ypS+I4JU5rywZNQjYMa0JsVXR+a2DkmShbXQ08s0PmUh6KaGmP56YJtI1hIz3ZELlYKvw+M/jAcCA==",
    )
    .unwrap();

        // KP3 delegating to KP4.
        let delegation_3 = Delegation::new_with_targets(
            pk4,
            UNIX_EPOCH + Duration::new(3, 0),
            vec![canister_test_id(1)],
        );
        // Signature of SK3 for delegation_3
        let delegation_3_signature = base64::decode(
        "a/hTCL8yOijzFIcHdcE0uvt2dj3WQdTiMLPX+xI8mWC0wRt+CYlMoFTc6JlfBopEJDrDwdEBz1n6/S8R2A/CCQ==",
    )
    .unwrap();

        // Message ID signature by SK4
        let message_id_signature =
        "UwmzxUzil6smPQ9hxab03AdSDUUbM76nx6yYPsMKzP59XlbjPxHJqyk7/n93I8a3oWkkJsxZNcFxMdnVx1L4CA==";

        let signed_delegation = SignedDelegation::new(delegation, delegation_signature);
        let signed_delegation_2 = SignedDelegation::new(delegation_2, delegation_2_signature);
        let signed_delegation_3 = SignedDelegation::new(delegation_3, delegation_3_signature);

        let user_signature = UserSignature {
            signature: base64::decode(message_id_signature).unwrap(),
            signer_pubkey: pk1,
            sender_delegation: Some(vec![
                signed_delegation,
                signed_delegation_2,
                signed_delegation_3,
            ]),
        };

        // Should pass at time 0.
        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Ok(CanisterIdSet::Some(set)) if set == btreeset! {canister_test_id(1)}
        );
        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH + Duration::from_secs(2),
                mock_registry_version()
            ),
            Ok(_)
        );

        // Should expire after > 2 seconds
        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH + Duration::from_secs(3),
                mock_registry_version()
            ),
            Err(RequestValidationError::InvalidDelegationExpiry(_))
        );
    }

    #[test]
    fn plain_authentication_with_malformed_delegation() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";
        let signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

        let user_signature = UserSignature {
            signature: base64::decode(signature).unwrap(),
            signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap())
                .unwrap(),
            // Add a malformed delegation.
            sender_delegation: Some(vec![SignedDelegation::new(
                Delegation::new(
                    vec![1, 2, 3], // malformed key
                    UNIX_EPOCH,
                ),
                vec![], // malformed signature
            )]),
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Err(InvalidDelegation(InvalidBasicSignature(_)))
        );
    }

    #[test]
    fn plain_authentication_with_invalid_delegation() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(1);

        // In this scenario we have two keypairs:
        //
        // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
        // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
        //
        // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
        // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=

        let pk1 = base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap();
        let pk2 = base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap();

        // KP1 delegating to KP2.
        let delegation = Delegation::new(pk2, UNIX_EPOCH + Duration::new(4, 0));
        // Faulty delegation signature. The correct one should be:
        // f5uiR36pRe4VL1k2VTwSvZGmViFTUZxZoh/IeYA183DgK1lhDLRpln57+2Ik2Mkqs5H/
        // G8jwx1+FQ/RZFaX1Dw==
        let delegation_signature = base64::decode(
        "HnM9ZfEg1E/+KPFBf6JGMS/TwtbjWVIm9PwG8vxbb74p0NBT98kDwtaT4TU0rSxm7WcWLNf7GnPu4b+0VroNBw==",
    )
    .unwrap();

        // Message ID signature by SK2
        let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

        let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

        let user_signature = UserSignature {
            signature: base64::decode(message_id_signature).unwrap(),
            signer_pubkey: pk1,
            sender_delegation: Some(vec![signed_delegation]),
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Err(InvalidDelegation(InvalidPublicKey(_)))
        );
    }

    #[test]
    fn validate_signature_webauthn() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(13);

        let pubkey_hex = "305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e";

        // Webauthn signature for the message ID above.
        let signature_hex = "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58847b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022436d6c6a4c584a6c6358566c6333514e414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100e4029fcf1cec44e0e2a33b2b2b981411376d89f90bec9ee7d4e20ca33ce8f088022070e95aa9dd3f0cf0d6f97f306d52211288482d565012202b349b2a2d80852635";

        let user_signature = UserSignature {
            signature: hex::decode(signature_hex).unwrap(),
            signer_pubkey: hex::decode(pubkey_hex).unwrap(),
            sender_delegation: None,
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Ok(CanisterIdSet::All)
        );
    }

    #[test]
    fn validate_signature_webauthn_with_delegations() {
        let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(13);

        // PK with the following corresponding secret key:
        // 2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3235362d4342432c41433946384133414541424132363345423345313041313939344441333131340a0a724f635a55306465685335623532437055795334427455393832796d4c36772b4e485576766137727a72373266613432526f68767459766b74432f70496242390a646861466a72666a6c493668754e53437a62464132484e4f4d447772516e4d74324d4550536e553439434a68514c4e2b4c353353526646324e78386a473352690a76416f2f63706e38763067784b787a394b336b2f4b3258514643416a6248696a2f67374a593351324141513d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a
        let pk1 = hex::decode("305e300c060a2b0601040183b8430101034e00a5010203262001215820aaf7276b278cf9c9a084e64f09db7255400705bee18145dfdff7c388e9a548e8225820eab7d1dc480ec1df9be1e4c73b28659d11a6c15b1786fd1c115fade01373fe53").unwrap();

        // PK with the following corresponding secret key:
        // 2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3235362d4342432c46433546313634394446324639333942414538343836333739383043394137440a0a475130706359302f744e6b6f566673534c632b635261324578426332763436724643376c596f4f63466d71656d4c73756952494f346f444b63715a68423962700a6b6248665374586e7168357557464b62674266776c617650377535625477396e61684e7553316a6c7653312b66492b79416255316f674e76423078514f4c41640a343864596333656f4877416b676848386e73426e796d3044574a386b59526b424b6136724e6f4e367154633d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a
        let pk2 = hex::decode("305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e").unwrap();
        let delegation = Delegation::new(pk2, UNIX_EPOCH);

        let delegation_sig = hex::decode("d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58997b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022476d6c6a4c584a6c6358566c63335174595856306143316b5a57786c5a32463061573975495f415149773979624b754a36593634394e6f6b715335575f6f37324777416b3057664d7535786f336c73222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100edf3fc39b51734da0aac5284b381308816f77bbccae7fbc8fd563c956c33121a0220280af63c8d01588e3242ac12f9c6f234f89c940df166ba53b07e5f7b1f67e360").unwrap();

        // Webauthn signature by pk2 for the message ID.
        let message_sig = hex::decode("d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58847b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022436d6c6a4c584a6c6358566c6333514e414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100e4029fcf1cec44e0e2a33b2b2b981411376d89f90bec9ee7d4e20ca33ce8f088022070e95aa9dd3f0cf0d6f97f306d52211288482d565012202b349b2a2d80852635").unwrap();

        let user_signature = UserSignature {
            signature: message_sig,
            signer_pubkey: pk1,
            sender_delegation: Some(vec![SignedDelegation::new(delegation, delegation_sig)]),
        };

        assert_matches!(
            validate_signature(
                &sig_verifier,
                &message_id,
                &user_signature,
                UNIX_EPOCH,
                mock_registry_version()
            ),
            Ok(CanisterIdSet::All)
        );
    }
}
