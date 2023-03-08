use crate::webauthn::validate_webauthn_sig;
use ic_constants::{MAX_INGRESS_TTL, PERMITTED_DRIFT_AT_VALIDATOR};
use ic_crypto::{user_public_key_from_bytes, KeyBytesContentType};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_types::crypto::{CanisterSig, CanisterSigOf};
use ic_types::{
    crypto::{AlgorithmId, BasicSig, BasicSigOf, CryptoError, UserPublicKey},
    malicious_flags::MaliciousFlags,
    messages::{
        Authentication, Delegation, HasCanisterId, HttpRequest, HttpRequestContent, MessageId,
        SignedDelegation, UserSignature, WebAuthnSignature,
    },
    CanisterId, PrincipalId, RegistryVersion, Time, UserId,
};
use std::{collections::BTreeSet, convert::TryFrom, fmt};

#[cfg(test)]
mod tests;

/// Maximum number of delegations allowed in an `HttpRequest`.
/// Requests having more delegations will be declared invalid without further verifying whether
/// the delegation chain is correctly signed.
/// **Note**: this limit is currently more generous than the one in the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication),
/// which specifies a maximum of 4 delegations, in order to prevent potentially breaking already deployed applications
/// since this limit was before (wrongly) not enforced.
/// This limit will be tightened up once the number of delegations can be observed (via metrics or logs),
/// see CRP-1961.
const MAXIMUM_NUMBER_OF_DELEGATIONS: usize = 20;

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
    DelegationTooLongError { length: usize, maximum: usize },
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidBasicSignature(err) => write!(f, "Invalid basic signature: {}", err),
            InvalidCanisterSignature(err) => write!(f, "Invalid canister signature: {}", err),
            InvalidPublicKey(err) => write!(f, "Invalid public key: {}", err),
            WebAuthnError(msg) => write!(f, "{}", msg),
            DelegationTargetError(msg) => write!(f, "{}", msg),
            DelegationTooLongError { length, maximum } => write!(
                f,
                "Chain of delegations is too long: got {} delegations, but at most {} are allowed",
                length, maximum
            ),
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
    // We need to account for time drift and be more forgiving at rejecting ingress
    // messages due to their expiry being too far in the future.
    let max_expiry_diff = MAX_INGRESS_TTL
        .checked_add(PERMITTED_DRIFT_AT_VALIDATOR)
        .ok_or_else(|| {
            InvalidIngressExpiry(format!(
                "Addition of MAX_INGRESS_TTL {MAX_INGRESS_TTL:?} with \
                PERMITTED_DRIFT_AT_VALIDATOR {PERMITTED_DRIFT_AT_VALIDATOR:?} overflows",
            ))
        })?;
    let max_allowed_expiry = min_allowed_expiry
        .checked_add_duration(max_expiry_diff)
        .ok_or_else(|| {
            InvalidIngressExpiry(format!(
                "Addition of min_allowed_expiry {min_allowed_expiry:?} \
                with max_expiry_diff {max_expiry_diff:?} overflows",
            ))
        })?;
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

fn validate_sender_delegation_length(
    sender_delegation: &Option<Vec<SignedDelegation>>,
) -> Result<(), RequestValidationError> {
    match sender_delegation
        .as_ref()
        .map(|delegations| delegations.len())
    {
        Some(number_of_delegations) if number_of_delegations > MAXIMUM_NUMBER_OF_DELEGATIONS => {
            Err(InvalidDelegation(DelegationTooLongError {
                length: number_of_delegations,
                maximum: MAXIMUM_NUMBER_OF_DELEGATIONS,
            }))
        }
        _ => Ok(()),
    }
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
    validate_sender_delegation_length(&signature.sender_delegation)?;
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
