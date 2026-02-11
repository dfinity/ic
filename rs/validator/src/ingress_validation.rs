use crate::webauthn::validate_webauthn_sig;
use AuthenticationError::*;
use RequestValidationError::*;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_standalone_sig_verifier::{KeyBytesContentType, user_public_key_from_bytes};
use ic_crypto_tree_hash::Path;
use ic_limits::{MAX_INGRESS_TTL, PERMITTED_DRIFT_AT_VALIDATOR};
use ic_types::{
    CanisterId, PrincipalId, Time, UserId,
    crypto::{
        AlgorithmId, BasicSig, BasicSigOf, CanisterSig, CanisterSigOf, CryptoError, UserPublicKey,
        threshold_sig::RootOfTrustProvider,
    },
    messages::{
        Authentication, Delegation, HasCanisterId, HttpRequest, HttpRequestContent, MessageId,
        Query, ReadState, SignedDelegation, SignedIngressContent, UserSignature, WebAuthnSignature,
    },
};
use std::{
    collections::{BTreeSet, HashSet},
    convert::TryFrom,
    sync::Arc,
};
use thiserror::Error;

#[cfg(test)]
mod tests;

/// Maximum number of delegations allowed in an `HttpRequest`.
/// Requests having more delegations will be declared invalid without further verifying whether
/// the delegation chain is correctly signed.
/// **Note**: this limit is part of the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication)
/// and so changing this value might be breaking or result in a deviation from the specification.
const MAXIMUM_NUMBER_OF_DELEGATIONS: usize = 20;

/// Maximum number of targets (collection of `CanisterId`s) that can be specified in a
/// single delegation. Requests having a single delegation with more targets will be declared
/// invalid without any further verification.
/// **Note**: this limit is part of the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication)
/// and so changing this value might be breaking or result in a deviation from the specification.
const MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION: usize = 1_000;

/// Maximum number of bytes allowed for the nonce in an `HttpRequest`.
/// Requests having a bigger nonce will be declared invalid without any further validation.
/// **Note**: this limit is part of the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication)
/// and so changing this value might be breaking or result in a deviation from the specification.
const MAXIMUM_NUMBER_OF_BYTES_IN_NONCE: usize = 32;

/// Maximum number of paths that can be specified in a read state request. Requests having more paths
/// will be declared invalid without any further verification.
/// **Note**: this limit is part of the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state)
/// and so changing this value might be breaking or result in a deviation from the specification.
const MAXIMUM_NUMBER_OF_PATHS: usize = 1_000;

/// Maximum number of labels than can be specified in a single path inside a read state request.
/// Requests having a single path with more labels will be declared invalid without any further verification.
/// **Note**: this limit is part of the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state)
/// and so changing this value might be breaking or result in a deviation from the specification.
const MAXIMUM_NUMBER_OF_LABELS_PER_PATH: usize = 127;

/// A trait for validating an `HttpRequest` with content `C`.
pub trait HttpRequestVerifier<C, R>: Send + Sync {
    /// Validates the given request.
    /// If valid, returns the set of canister IDs that are *common* to all delegations.
    /// Otherwise, returns an error.
    ///
    /// The given `request` is valid iff
    /// * The request hasn't expired relative to `current_time`.
    /// * The delegations (if any) are valid:
    ///     * There are at most `MAXIMUM_NUMBER_OF_DELEGATIONS` delegations.
    ///     * There are at most `MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION` targets for each delegation.
    ///     * The delegations haven't expired relative to `current_time`.
    ///     * The delegations form a chain of certificates that are correctly signed and do not contain any cycle.
    /// * The request's signature (if any) is correct.
    /// * If the request specifies a `CanisterId` (see `HasCanisterId`),
    ///   then it must be among the set of canister IDs that are common to all delegations.
    ///
    /// The following signatures (for signing the request or any delegation) are supported
    /// (see the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#signatures)):
    /// * Ed25519
    /// * ECDSA secp256r1 (aka P-256)
    /// * ECDSA secp256k1
    /// * RSA SHA256
    /// * Canister signature, where the signature will be verified with respect to the root of trust given by the `root_of_trust_provider`.
    ///   If no canister signatures are involved, the `root_of_trust_provider` will not be queried.
    fn validate_request(
        &self,
        request: &HttpRequest<C>,
        current_time: Time,
        root_of_trust_provider: &R,
    ) -> Result<CanisterIdSet, RequestValidationError>;
}

pub struct HttpRequestVerifierImpl {
    validator: Arc<dyn IngressSigVerifier>,
}

impl HttpRequestVerifierImpl {
    pub fn new(validator: Arc<dyn IngressSigVerifier>) -> Self {
        Self { validator }
    }
}

impl<R> HttpRequestVerifier<SignedIngressContent, R> for HttpRequestVerifierImpl
where
    R: RootOfTrustProvider,
    R::Error: std::error::Error,
{
    fn validate_request(
        &self,
        request: &HttpRequest<SignedIngressContent>,
        current_time: Time,
        root_of_trust_provider: &R,
    ) -> Result<CanisterIdSet, RequestValidationError> {
        validate_ingress_expiry(request, current_time)?;
        let delegation_targets = validate_request_content(
            request,
            self.validator.as_ref(),
            current_time,
            root_of_trust_provider,
        )?;
        validate_request_target(request, &delegation_targets)?;
        Ok(delegation_targets)
    }
}

impl<R> HttpRequestVerifier<Query, R> for HttpRequestVerifierImpl
where
    R: RootOfTrustProvider,
    R::Error: std::error::Error,
{
    fn validate_request(
        &self,
        request: &HttpRequest<Query>,
        current_time: Time,
        root_of_trust_provider: &R,
    ) -> Result<CanisterIdSet, RequestValidationError> {
        if !request.sender().get().is_anonymous() {
            validate_ingress_expiry(request, current_time)?;
        }
        let delegation_targets = validate_request_content(
            request,
            self.validator.as_ref(),
            current_time,
            root_of_trust_provider,
        )?;
        validate_request_target(request, &delegation_targets)?;
        Ok(delegation_targets)
    }
}

impl<R> HttpRequestVerifier<ReadState, R> for HttpRequestVerifierImpl
where
    R: RootOfTrustProvider,
    R::Error: std::error::Error,
{
    fn validate_request(
        &self,
        request: &HttpRequest<ReadState>,
        current_time: Time,
        root_of_trust_provider: &R,
    ) -> Result<CanisterIdSet, RequestValidationError> {
        validate_paths_width_and_depth(&request.content().paths)?;
        if !request.sender().get().is_anonymous() {
            validate_ingress_expiry(request, current_time)?;
        }
        validate_request_content(
            request,
            self.validator.as_ref(),
            current_time,
            root_of_trust_provider,
        )
    }
}

fn validate_paths_width_and_depth(paths: &[Path]) -> Result<(), RequestValidationError> {
    if paths.len() > MAXIMUM_NUMBER_OF_PATHS {
        return Err(TooManyPaths {
            maximum: MAXIMUM_NUMBER_OF_PATHS,
            length: paths.len(),
        });
    }
    for path in paths {
        if path.len() > MAXIMUM_NUMBER_OF_LABELS_PER_PATH {
            return Err(PathTooLong {
                maximum: MAXIMUM_NUMBER_OF_LABELS_PER_PATH,
                length: path.len(),
            });
        }
    }
    Ok(())
}

fn validate_request_content<C: HttpRequestContent, R: RootOfTrustProvider>(
    request: &HttpRequest<C>,
    ingress_signature_verifier: &dyn IngressSigVerifier,
    current_time: Time,
    root_of_trust_provider: &R,
) -> Result<CanisterIdSet, RequestValidationError>
where
    R::Error: std::error::Error,
{
    validate_nonce(request)?;
    validate_user_id_and_signature(
        ingress_signature_verifier,
        &request.sender(),
        &request.id(),
        match request.authentication() {
            Authentication::Anonymous => None,
            Authentication::Authenticated(signature) => Some(signature),
        },
        current_time,
        root_of_trust_provider,
    )
}

fn validate_request_target<C: HasCanisterId>(
    request: &HttpRequest<C>,
    targets: &CanisterIdSet,
) -> Result<(), RequestValidationError> {
    if targets.contains(&request.content().canister_id()) {
        Ok(())
    } else {
        Err(CanisterNotInDelegationTargets(
            request.content().canister_id(),
        ))
    }
}

/// Error in validating an [HttpRequest].
#[derive(PartialEq, Debug, Error)]
pub enum RequestValidationError {
    #[error("Invalid request expiry: {0}")]
    InvalidRequestExpiry(String),
    #[error("Invalid delegation expiry: {0}")]
    InvalidDelegationExpiry(String),
    #[error("The user id '{0}' does not match the public key '{n}'", n=hex::encode(.1))]
    UserIdDoesNotMatchPublicKey(UserId, Vec<u8>),
    #[error("Invalid signature: {0}")]
    InvalidSignature(AuthenticationError),
    #[error("Invalid delegation: {0}")]
    InvalidDelegation(AuthenticationError),
    #[error("Missing signature from user: {0}")]
    MissingSignature(UserId),
    #[error("Signature is not allowed for the anonymous user.")]
    AnonymousSignatureNotAllowed,
    #[error("Canister '{0}' is not one of the delegation targets.")]
    CanisterNotInDelegationTargets(CanisterId),
    #[error(
        "Too many paths in read state request: got {length} paths, but at most {maximum} are allowed."
    )]
    TooManyPaths { length: usize, maximum: usize },
    #[error(
        "At least one path in read state request is too deep: got {length} labels, but at most {maximum} are allowed."
    )]
    PathTooLong { length: usize, maximum: usize },
    #[error(
        "Nonce in request is too big: got {num_bytes} bytes, but at most {maximum} are allowed."
    )]
    NonceTooBig { num_bytes: usize, maximum: usize },
}

/// Error in verifying the signature or authentication part of a request.
#[derive(PartialEq, Debug, Error)]
pub enum AuthenticationError {
    #[error("Invalid basic signature: {0}")]
    InvalidBasicSignature(CryptoError),
    #[error("Invalid canister signature: {0}")]
    InvalidCanisterSignature(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(CryptoError),
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
    #[error("Delegation target error: {0}")]
    DelegationTargetError(String),
    #[error{"Chain of delegations is too long: got {length} delegations, but at most {maximum} are allowed."}]
    DelegationTooLongError { length: usize, maximum: usize },
    #[error("Chain of delegations contains at least one cycle: first repeating public key encountered {}", hex::encode(.public_key))]
    DelegationContainsCyclesError { public_key: Vec<u8> },
}

/// Set of canister IDs.
///
/// It is guaranteed that the set contains at most `MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION`
/// elements.
/// Use [`CanisterIdSet::all`] to instantiate a set containing the entire domain of canister IDs
/// or [`CanisterIdSet::try_from_iter`] to instantiate a specific subset.
///
/// # Examples
///
/// ```
/// # use ic_types::CanisterId;
/// # use ic_validator::CanisterIdSet;
/// let all_canister_ids = CanisterIdSet::all();
/// assert!(all_canister_ids.contains(&CanisterId::from_u64(0)));
/// assert!(all_canister_ids.contains(&CanisterId::from_u64(1)));
/// assert!(all_canister_ids.contains(&CanisterId::from_u64(2)));
/// // ...
///
/// let subset_canister_ids = CanisterIdSet::try_from_iter(vec![
///   CanisterId::from_u64(0),
///   CanisterId::from_u64(1),
/// ]).expect("too many elements");
/// assert!(subset_canister_ids.contains(&CanisterId::from_u64(0)));
/// assert!(subset_canister_ids.contains(&CanisterId::from_u64(1)));
/// assert!(!subset_canister_ids.contains(&CanisterId::from_u64(2)));
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CanisterIdSet {
    ids: internal::CanisterIdSet,
}

mod internal {
    use super::*;
    /// An enum representing a mutable set of canister IDs.
    /// Contrary to `super::CanisterIdSet`, the number of canister IDs is not restricted.
    #[derive(Clone, Eq, PartialEq, Hash, Debug)]
    pub(super) enum CanisterIdSet {
        /// The entire domain of canister IDs.
        All,
        /// A subset of canister IDs.
        Some(BTreeSet<CanisterId>),
    }
}

impl CanisterIdSet {
    pub fn all() -> Self {
        CanisterIdSet {
            ids: internal::CanisterIdSet::All,
        }
    }

    /// Constructs a specific subset of canister IDs from any collection that
    /// can be iterated over.
    ///
    /// Duplicated elements in the input collection will be ignored.
    ///
    /// # Errors
    ///
    /// - [`CanisterIdSetInstantiationError::TooManyElements`] if the given iterator contains too many *distinct* elements
    ///
    /// # Examples
    ///
    /// ```
    /// # use ic_types::CanisterId;
    /// # use ic_validator::{CanisterIdSet, CanisterIdSetInstantiationError};
    /// let empty_set = CanisterIdSet::try_from_iter(vec![]).expect("too many elements");
    /// let singleton = CanisterIdSet::try_from_iter(vec![CanisterId::from_u64(0)]).expect("too many elements");
    ///
    /// let mut duplicated_ids = Vec::with_capacity(1001);
    /// let mut distinct_ids = Vec::with_capacity(1001);
    /// for i in 0..1001 {
    ///   duplicated_ids.push(CanisterId::from_u64(0));
    ///   distinct_ids.push(CanisterId::from_u64(i));
    /// }
    ///
    /// assert_eq!(Ok(singleton), CanisterIdSet::try_from_iter(duplicated_ids));
    /// assert_eq!(Err(CanisterIdSetInstantiationError::TooManyElements(1001)), CanisterIdSet::try_from_iter(distinct_ids));
    /// ```
    pub fn try_from_iter<I: IntoIterator<Item = CanisterId>>(
        iter: I,
    ) -> Result<Self, CanisterIdSetInstantiationError> {
        let ids: BTreeSet<CanisterId> = iter.into_iter().collect();
        match ids.len() {
            n if n > MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION => {
                Err(CanisterIdSetInstantiationError::TooManyElements(n))
            }
            _ => Ok(CanisterIdSet {
                ids: internal::CanisterIdSet::Some(ids),
            }),
        }
    }

    pub fn contains(&self, canister_id: &CanisterId) -> bool {
        match &self.ids {
            internal::CanisterIdSet::All => true,
            internal::CanisterIdSet::Some(set) => set.contains(canister_id),
        }
    }

    fn intersect(self, other: Self) -> Self {
        CanisterIdSet {
            //the result of set intersection cannot contain
            //more elements than the involved sets,
            //so controlling the cardinality of the result is not needed
            ids: match (self.ids, other.ids) {
                (internal::CanisterIdSet::All, other) => other,
                (me, internal::CanisterIdSet::All) => me,
                (internal::CanisterIdSet::Some(set1), internal::CanisterIdSet::Some(set2)) => {
                    internal::CanisterIdSet::Some(set1.intersection(&set2).cloned().collect())
                }
            },
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        match &self.ids {
            internal::CanisterIdSet::All => false,
            internal::CanisterIdSet::Some(set) => set.is_empty(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
pub enum CanisterIdSetInstantiationError {
    #[error(
        "Expected at most {n} elements but got {0}",
        n=MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION
    )]
    TooManyElements(usize),
}

fn validate_nonce<C: HttpRequestContent>(
    request: &HttpRequest<C>,
) -> Result<(), RequestValidationError> {
    match request.nonce() {
        Some(nonce) if nonce.len() > MAXIMUM_NUMBER_OF_BYTES_IN_NONCE => Err(NonceTooBig {
            num_bytes: nonce.len(),
            maximum: MAXIMUM_NUMBER_OF_BYTES_IN_NONCE,
        }),
        _ => Ok(()),
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
    // If this logic changes, then the migration canister in `//rs/migration_canister`
    // must be updated, too.
    let max_expiry_diff = MAX_INGRESS_TTL
        .checked_add(PERMITTED_DRIFT_AT_VALIDATOR)
        .ok_or_else(|| {
            InvalidRequestExpiry(format!(
                "Addition of MAX_INGRESS_TTL {MAX_INGRESS_TTL:?} with \
                PERMITTED_DRIFT_AT_VALIDATOR {PERMITTED_DRIFT_AT_VALIDATOR:?} overflows",
            ))
        })?;
    let max_allowed_expiry = min_allowed_expiry
        .checked_add(max_expiry_diff)
        .ok_or_else(|| {
            InvalidRequestExpiry(format!(
                "Addition of min_allowed_expiry {min_allowed_expiry:?} \
                with max_expiry_diff {max_expiry_diff:?} overflows",
            ))
        })?;
    if !(min_allowed_expiry <= provided_expiry && provided_expiry <= max_allowed_expiry) {
        let msg = format!(
            "Specified ingress_expiry not within expected range: \
             Minimum allowed expiry: {min_allowed_expiry}, \
             Maximum allowed expiry: {max_allowed_expiry}, \
             Provided expiry:        {provided_expiry}"
        );
        return Err(InvalidRequestExpiry(msg));
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
                     Provided expiry:    {expiry}\n\
                     Local replica time: {current_time}",
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
fn validate_signature<R: RootOfTrustProvider>(
    validator: &dyn IngressSigVerifier,
    message_id: &MessageId,
    signature: &UserSignature,
    current_time: Time,
    root_of_trust_provider: &R,
) -> Result<CanisterIdSet, RequestValidationError>
where
    R::Error: std::error::Error,
{
    validate_sender_delegation_length(&signature.sender_delegation)?;
    validate_sender_delegation_expiry(&signature.sender_delegation, current_time)?;
    let empty_vec = Vec::new();
    let signed_delegations = signature.sender_delegation.as_ref().unwrap_or(&empty_vec);

    let (pubkey, targets) = validate_delegations(
        validator,
        signed_delegations.as_slice(),
        signature.signer_pubkey.clone(),
        root_of_trust_provider,
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
            let root_of_trust = root_of_trust_provider
                .root_of_trust()
                .map_err(|e| InvalidCanisterSignature(e.to_string()))
                .map_err(InvalidSignature)?;
            validator
                .verify_canister_sig(&canister_sig, message_id, &pk, &root_of_trust)
                .map_err(|e| InvalidCanisterSignature(e.to_string()))
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
// See https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication
//
// If the delegations are valid, returns the public key used to sign the
// request as well as the set of canister IDs that the public key is valid for.
fn validate_delegations<R: RootOfTrustProvider>(
    validator: &dyn IngressSigVerifier,
    signed_delegations: &[SignedDelegation],
    mut pubkey: Vec<u8>,
    root_of_trust_provider: &R,
) -> Result<(Vec<u8>, CanisterIdSet), RequestValidationError>
where
    R::Error: std::error::Error,
{
    ensure_delegations_does_not_contain_cycles(&pubkey, signed_delegations)?;
    ensure_delegations_does_not_contain_too_many_targets(signed_delegations)?;
    // Initially, assume that the delegations target all possible canister IDs.
    let mut targets = CanisterIdSet::all();

    for sd in signed_delegations {
        let delegation = sd.delegation();
        let signature = sd.signature();

        let new_targets = validate_delegation(
            validator,
            signature,
            delegation,
            &pubkey,
            root_of_trust_provider,
        )
        .map_err(InvalidDelegation)?;
        // Restrict the canister targets to the ones specified in the delegation.
        targets = targets.intersect(new_targets);
        pubkey = delegation.pubkey().to_vec();
    }

    Ok((pubkey, targets))
}

fn ensure_delegations_does_not_contain_cycles(
    sender_public_key: &[u8],
    signed_delegations: &[SignedDelegation],
) -> Result<(), RequestValidationError> {
    let mut observed_public_keys = HashSet::with_capacity(signed_delegations.len() + 1);
    observed_public_keys.insert(sender_public_key);
    for delegation in signed_delegations {
        let current_public_key = delegation.delegation().pubkey();
        if !observed_public_keys.insert(current_public_key) {
            return Err(InvalidDelegation(DelegationContainsCyclesError {
                public_key: current_public_key.clone(),
            }));
        }
    }
    Ok(())
}

fn ensure_delegations_does_not_contain_too_many_targets(
    signed_delegations: &[SignedDelegation],
) -> Result<(), RequestValidationError> {
    for delegation in signed_delegations {
        match delegation.delegation().number_of_targets() {
            Some(number_of_targets)
                if number_of_targets > MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION =>
            {
                Err(InvalidDelegation(DelegationTargetError(format!(
                    "expected at most {MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION} targets per delegation, but got {number_of_targets}"
                ))))
            }
            _ => Ok(()),
        }?
    }
    Ok(())
}

fn validate_delegation<R: RootOfTrustProvider>(
    validator: &dyn IngressSigVerifier,
    signature: &[u8],
    delegation: &Delegation,
    pubkey: &[u8],
    root_of_trust_provider: &R,
) -> Result<CanisterIdSet, AuthenticationError>
where
    R::Error: std::error::Error,
{
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
            let root_of_trust = root_of_trust_provider
                .root_of_trust()
                .map_err(|e| InvalidCanisterSignature(e.to_string()))?;
            validator
                .verify_canister_sig(&canister_sig, delegation, &pk, &root_of_trust)
                .map_err(|e| InvalidCanisterSignature(e.to_string()))?;
        }
    }

    // Validation succeeded. Return the targets of this delegation.
    Ok(match delegation.targets().map_err(DelegationTargetError)? {
        None => CanisterIdSet::all(),
        Some(targets) => CanisterIdSet::try_from_iter(targets)
            .map_err(|e| DelegationTargetError(format!("{e}")))?,
    })
}

// Verifies correct user and signature.
fn validate_user_id_and_signature<R: RootOfTrustProvider>(
    ingress_signature_verifier: &dyn IngressSigVerifier,
    sender: &UserId,
    message_id: &MessageId,
    signature: Option<&UserSignature>,
    current_time: Time,
    root_of_trust_provider: &R,
) -> Result<CanisterIdSet, RequestValidationError>
where
    R::Error: std::error::Error,
{
    match signature {
        None => {
            if sender.get().is_anonymous() {
                return Ok(CanisterIdSet::all());
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
                        root_of_trust_provider,
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
