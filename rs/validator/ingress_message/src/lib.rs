//! A standalone crate for validating an [`HttpRequest`] according to the
//! [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-interface).
use ic_types::messages::HttpRequest;
use ic_types::{CanisterId, UserId};
use std::fmt::{Display, Formatter};

mod internal;

pub use internal::IngressMessageVerifier;
pub use internal::IngressMessageVerifierBuilder;
pub use internal::StandaloneIngressSigVerifier;
pub use internal::TimeProvider;

/// Validate an incoming HTTP request according to the
/// [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication).
///
/// To be considered valid, the `request` must fulfill *all* following conditions:
///  * The request hasn't expired relative to the current time.
///  * If the request is not anonymous:
///      * The delegations (if any) are valid:
///          * none of the delegations have expired relative to the current time
///          * the delegations form a valid chain of trust rooted at `sender_pubkey`
///      * The request signature (`sender_sig`) can be verified by either the public key in `sender_pubkey`
///        or by the public key specified in the last delegation.
///
/// # Examples
/// * For a default instantiation suitable in production see [`IngressMessageVerifier::default`].
/// * If you need to overwrite any chosen defaults, e.g., for testing purposes,
///   see [`IngressMessageVerifier::builder`].
///
/// # Errors
/// * [`RequestValidationError::InvalidIngressExpiry`]:
///   if the request expired or its provided expiry is too far off in the future.
/// * [`RequestValidationError::InvalidDelegationExpiry`]: if any of the delegations expired.
/// * [`RequestValidationError::UserIdDoesNotMatchPublicKey`]: if the ID of the issuer
///   sending the request (`sender`) does not match the public key (`sender_pubkey`).
/// * [`RequestValidationError::InvalidSignature`]: if the request signature cannot be verified
///   by using the public key in `sender_pubkey` if there are no delegations; or, by using the
///   public key specified in the last delegation.
/// * [`RequestValidationError::InvalidDelegation`]: if the delegations do not form a valid
///   chain of trust rooted at `sender_pubkey`.
/// * [`RequestValidationError::MissingSignature`]: if the sender is not anonymous but
///   no signature was provided.
/// * [`RequestValidationError::AnonymousSignatureNotAllowed`]: if the sender is anonymous
///   but a signature was provided.
/// * [`RequestValidationError::CanisterNotInDelegationTargets`]: if the request targets a canister
///   that is not authorized in one of the delegations.
pub trait HttpRequestVerifier<C> {
    fn validate_request(&self, request: &HttpRequest<C>) -> Result<(), RequestValidationError>;
}
/// Top-level error that occur when verifying an HTTP request
/// with [`HttpRequestVerifier::validate_request`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestValidationError {
    InvalidIngressExpiry(String),
    InvalidDelegationExpiry(String),
    UserIdDoesNotMatchPublicKey(UserId, Vec<u8>),
    InvalidSignature(AuthenticationError),
    InvalidDelegation(AuthenticationError),
    MissingSignature(UserId),
    AnonymousSignatureNotAllowed,
    CanisterNotInDelegationTargets(CanisterId),
    TooManyPathsError { length: usize, maximum: usize },
    PathTooLongError { length: usize, maximum: usize },
    NonceTooBigError { num_bytes: usize, maximum: usize },
}

impl Display for RequestValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestValidationError::InvalidIngressExpiry(msg) => write!(f, "{}", msg),
            RequestValidationError::InvalidDelegationExpiry(msg) => write!(f, "{}", msg),
            RequestValidationError::UserIdDoesNotMatchPublicKey(user_id, pubkey) => write!(
                f,
                "The user id {} does not match the public key {}",
                user_id,
                hex::encode(pubkey)
            ),
            RequestValidationError::InvalidSignature(err) => {
                write!(f, "Invalid signature: {}", err)
            }
            RequestValidationError::InvalidDelegation(err) => {
                write!(f, "Invalid delegation: {}", err)
            }
            RequestValidationError::MissingSignature(user_id) => {
                write!(f, "Missing signature from user: {}", user_id)
            }
            RequestValidationError::AnonymousSignatureNotAllowed => {
                write!(f, "Signature is not allowed for the anonymous user")
            }
            RequestValidationError::CanisterNotInDelegationTargets(canister_id) => write!(
                f,
                "Canister {} is not one of the delegation targets",
                canister_id
            ),
            RequestValidationError::TooManyPathsError { length, maximum } => write!(
                f,
                "Too many paths in read state request: got {} paths, but at most {} are allowed",
                length, maximum
            ),
            RequestValidationError::PathTooLongError { length, maximum } => write!(
                f,
                "At least one path in read state request is too deep: got {} labels, but at most {} are allowed",
                length, maximum
            ),
            RequestValidationError::NonceTooBigError { num_bytes: length, maximum } => write!(
                f,
                "Nonce in request is too big: got {} bytes, but at most {} are allowed",
                length, maximum
            ),
        }
    }
}

/// Authentication-related error that can occur when verifying an HTTP request
/// with [`HttpRequestVerifier::validate_request`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthenticationError {
    /// The signature is invalid and cannot be verified.
    InvalidBasicSignature(String),

    /// The canister signature is invalid and cannot be verified.
    InvalidCanisterSignature(String),

    /// The public key is somehow malformed.
    InvalidPublicKey(String),

    /// A signature provided by WebAuthn is invalid and cannot be verified.
    WebAuthnError(String),

    /// Canister ID provided in delegation target is invalid and cannot be parsed.
    DelegationTargetError(String),

    /// Delegation chain is too long.
    DelegationTooLongError { length: usize, maximum: usize },

    /// Delegation chain contains at least one cycle, meaning that a public key delegates to a public key,
    /// which was already encountered before in the chain of delegations.
    /// Note that if both keys are equal, then this delegation is self-signed, which is also forbidden.
    DelegationContainsCyclesError { public_key: Vec<u8> },
}

impl Display for AuthenticationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationError::InvalidBasicSignature(err) => {
                write!(f, "Invalid basic signature: {}", err)
            }
            AuthenticationError::InvalidCanisterSignature(err) => {
                write!(f, "Invalid canister signature: {}", err)
            }
            AuthenticationError::InvalidPublicKey(err) => write!(f, "Invalid public key: {}", err),
            AuthenticationError::WebAuthnError(msg) => write!(f, "{}", msg),
            AuthenticationError::DelegationTargetError(msg) => write!(f, "{}", msg),
            AuthenticationError::DelegationTooLongError { length, maximum } => write!(
                f,
                "Chain of delegations is too long: got {} delegations, but at most {} are allowed",
                length, maximum
            ),
            AuthenticationError::DelegationContainsCyclesError { public_key } => write!(
                f,
                "Chain of delegations contains at least one cycle: first repeating public key encountered {}",
                hex::encode(public_key)
            ),
        }
    }
}
