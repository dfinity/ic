use crate::{AuthenticationError, HttpRequestVerifier, RequestValidationError};
use ic_crypto_interfaces_sig_verification::{BasicSigVerifierByPublicKey, CanisterSigVerifier};
use ic_types::Time;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider};
use ic_types::crypto::{BasicSigOf, CanisterSigOf, CryptoResult, Signable, UserPublicKey};
use ic_types::messages::{HttpRequest, HttpRequestContent};
use std::convert::Infallible;
use std::sync::Arc;

#[cfg(test)]
mod tests;

// NNS root public key DER encoded in base 64
const IC_NNS_ROOT_PUBLIC_KEY_BASE64: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;

/// An implementation of [`HttpRequestVerifier`] to verify ingress messages.
pub struct IngressMessageVerifier<P: RootOfTrustProvider> {
    root_of_trust_provider: P,
    time_source: TimeProvider,
    validator: ic_validator::HttpRequestVerifierImpl,
}

impl Default for IngressMessageVerifier<ConstantRootOfTrustProvider> {
    /// Default verifier for ingress messages that is suitable for production.
    ///
    /// It uses the following defaults:
    /// * the root of trust is hard-coded to be the NNS root public key
    /// * the system time is used to derive the current time
    ///
    /// If other defaults are needed see [`IngressMessageVerifier::builder`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use ic_types::messages::{HttpCallContent, HttpRequest, SignedIngressContent};
    /// # use ic_types::Time;
    /// # use ic_validator_ingress_message::{RequestValidationError, HttpRequestVerifier, IngressMessageVerifier, TimeProvider};
    /// # fn anonymous_http_request_with_ingress_expiry(
    /// #     ingress_expiry: u64,
    /// # ) -> HttpRequest<SignedIngressContent> {
    /// #     use ic_types::messages::Blob;
    /// #     use ic_types::messages::HttpCanisterUpdate;
    /// #     use ic_types::messages::HttpRequestEnvelope;
    /// #     HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
    /// #         content: HttpCallContent::Call {
    /// #             update: HttpCanisterUpdate {
    /// #                 canister_id: Blob(vec![42; 8]),
    /// #                 method_name: "some_method".to_string(),
    /// #                 arg: Blob(b"".to_vec()),
    /// #                 sender: Blob(vec![0x04]),
    /// #                 nonce: None,
    /// #                 ingress_expiry,
    /// #             },
    /// #         },
    /// #         sender_pubkey: None,
    /// #         sender_sig: None,
    /// #         sender_delegation: None,
    /// #     })
    /// #         .expect("invalid http envelope")
    /// # }
    /// let current_time = Time::from_nanos_since_unix_epoch(1_000);
    /// let request = anonymous_http_request_with_ingress_expiry(current_time.as_nanos_since_unix_epoch());
    /// let verifier = IngressMessageVerifier::default();
    ///
    /// let result = verifier.validate_request(&request);
    ///
    /// match result {
    ///     Err(RequestValidationError::InvalidIngressExpiry(_)) => {}
    ///     _ => panic!("unexpected result type {:?}", result)
    /// }
    /// ```
    fn default() -> Self {
        IngressMessageVerifier::<ConstantRootOfTrustProvider>::builder()
            .with_root_of_trust(nns_root_public_key())
            .with_time_provider(TimeProvider::SystemTime)
            .build()
    }
}

impl IngressMessageVerifier<ConstantRootOfTrustProvider> {
    fn new_internal<T: Into<IcRootOfTrust>>(root_of_trust: T, time_source: TimeProvider) -> Self {
        IngressMessageVerifier {
            root_of_trust_provider: ConstantRootOfTrustProvider::new(root_of_trust),
            time_source,
            validator: ic_validator::HttpRequestVerifierImpl::new(Arc::new(
                StandaloneIngressSigVerifier,
            )),
        }
    }

    /// Builder pattern used to instantiate a verifier for ingress messages
    /// that can be configured differently than the default one (see [`IngressMessageVerifier::default`]).
    ///
    /// This is in particular useful for testing purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    /// # use ic_types::messages::{HttpCallContent, HttpRequest, SignedIngressContent};
    /// # use ic_types::Time;
    /// # use ic_validator_ingress_message::{RequestValidationError, HttpRequestVerifier, IngressMessageVerifier, TimeProvider};
    /// # fn anonymous_http_request_with_ingress_expiry(
    /// #     ingress_expiry: u64,
    /// # ) -> HttpRequest<SignedIngressContent> {
    /// #     use ic_types::messages::Blob;
    /// #     use ic_types::messages::HttpCanisterUpdate;
    /// #     use ic_types::messages::HttpRequestEnvelope;
    /// #     HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
    /// #         content: HttpCallContent::Call {
    /// #             update: HttpCanisterUpdate {
    /// #                 canister_id: Blob(vec![42; 8]),
    /// #                 method_name: "some_method".to_string(),
    /// #                 arg: Blob(b"".to_vec()),
    /// #                 sender: Blob(vec![0x04]),
    /// #                 nonce: None,
    /// #                 ingress_expiry,
    /// #             },
    /// #         },
    /// #         sender_pubkey: None,
    /// #         sender_sig: None,
    /// #         sender_delegation: None,
    /// #     })
    /// #         .expect("invalid http envelope")
    /// # }
    /// let current_time = Time::from_nanos_since_unix_epoch(1_000);
    /// let other_root_of_trust = parse_threshold_sig_key_from_der(&hex::decode("308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100923A67B791270CD8F5320212AE224377CF407D3A8A2F44F11FED5915A97EE67AD0E90BC382A44A3F14C363AD2006640417B4BBB3A304B97088EC6B4FC87A25558494FC239B47E129260232F79973945253F5036FD520DDABD1E2DE57ABFB40CB").unwrap()).unwrap();
    /// let request = anonymous_http_request_with_ingress_expiry(current_time.as_nanos_since_unix_epoch());
    ///
    /// let verifier = IngressMessageVerifier::builder()
    /// .with_time_provider(TimeProvider::Constant(current_time))
    /// .with_root_of_trust(other_root_of_trust)
    /// .build();
    ///
    /// let result = verifier.validate_request(&request);
    ///
    /// assert_eq!(result, Ok(()));
    /// ```
    pub fn builder() -> IngressMessageVerifierBuilder {
        IngressMessageVerifierBuilder::default()
    }
}

fn nns_root_public_key() -> IcRootOfTrust {
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    let decoded_nns_mainnet_key = base64::decode(IC_NNS_ROOT_PUBLIC_KEY_BASE64)
        .expect("Failed to decode mainnet public key from base64.");
    IcRootOfTrust::from(
        parse_threshold_sig_key_from_der(&decoded_nns_mainnet_key)
            .expect("Failed to decode mainnet public key."),
    )
}

impl<C: HttpRequestContent, P: RootOfTrustProvider> HttpRequestVerifier<C>
    for IngressMessageVerifier<P>
where
    ic_validator::HttpRequestVerifierImpl: ic_validator::HttpRequestVerifier<C, P>,
{
    fn validate_request(&self, request: &HttpRequest<C>) -> Result<(), RequestValidationError> {
        ic_validator::HttpRequestVerifier::validate_request(
            &self.validator,
            request,
            self.time_source.get_relative_time(),
            &self.root_of_trust_provider,
        )
        .map(|_| ())
        .map_err(to_validation_error)
    }
}

fn to_validation_error(error: ic_validator::RequestValidationError) -> RequestValidationError {
    match error {
        ic_validator::RequestValidationError::InvalidRequestExpiry(msg) => {
            RequestValidationError::InvalidIngressExpiry(msg)
        }
        ic_validator::RequestValidationError::InvalidDelegationExpiry(msg) => {
            RequestValidationError::InvalidDelegationExpiry(msg)
        }
        ic_validator::RequestValidationError::UserIdDoesNotMatchPublicKey(user_id, public_key) => {
            RequestValidationError::UserIdDoesNotMatchPublicKey(user_id, public_key)
        }
        ic_validator::RequestValidationError::InvalidSignature(auth_error) => {
            RequestValidationError::InvalidSignature(to_authentication_lib_error(auth_error))
        }
        ic_validator::RequestValidationError::InvalidDelegation(auth_error) => {
            RequestValidationError::InvalidDelegation(to_authentication_lib_error(auth_error))
        }
        ic_validator::RequestValidationError::MissingSignature(user_id) => {
            RequestValidationError::MissingSignature(user_id)
        }
        ic_validator::RequestValidationError::AnonymousSignatureNotAllowed => {
            RequestValidationError::AnonymousSignatureNotAllowed
        }
        ic_validator::RequestValidationError::CanisterNotInDelegationTargets(canister_id) => {
            RequestValidationError::CanisterNotInDelegationTargets(canister_id)
        }
        ic_validator::RequestValidationError::TooManyPaths { length, maximum } => {
            RequestValidationError::TooManyPathsError { length, maximum }
        }
        ic_validator::RequestValidationError::PathTooLong { length, maximum } => {
            RequestValidationError::PathTooLongError { length, maximum }
        }
        ic_validator::RequestValidationError::NonceTooBig { num_bytes, maximum } => {
            RequestValidationError::NonceTooBigError { num_bytes, maximum }
        }
    }
}
fn to_authentication_lib_error(error: ic_validator::AuthenticationError) -> AuthenticationError {
    match error {
        ic_validator::AuthenticationError::InvalidBasicSignature(crypto_error) => {
            AuthenticationError::InvalidBasicSignature(format!("{crypto_error}"))
        }
        ic_validator::AuthenticationError::InvalidCanisterSignature(error) => {
            AuthenticationError::InvalidCanisterSignature(error)
        }
        ic_validator::AuthenticationError::InvalidPublicKey(crypto_error) => {
            AuthenticationError::InvalidPublicKey(format!("{crypto_error}"))
        }
        ic_validator::AuthenticationError::WebAuthnError(msg) => {
            AuthenticationError::WebAuthnError(msg)
        }
        ic_validator::AuthenticationError::DelegationTargetError(msg) => {
            AuthenticationError::DelegationTargetError(msg)
        }
        ic_validator::AuthenticationError::DelegationTooLongError { length, maximum } => {
            AuthenticationError::DelegationTooLongError { length, maximum }
        }
        ic_validator::AuthenticationError::DelegationContainsCyclesError { public_key } => {
            AuthenticationError::DelegationContainsCyclesError { public_key }
        }
    }
}

pub struct IngressMessageVerifierBuilder {
    root_of_trust: IcRootOfTrust,
    time_provider: TimeProvider,
}

impl Default for IngressMessageVerifierBuilder {
    fn default() -> Self {
        IngressMessageVerifierBuilder {
            root_of_trust: nns_root_public_key(),
            time_provider: TimeProvider::SystemTime,
        }
    }
}

impl IngressMessageVerifierBuilder {
    pub fn with_root_of_trust<T: Into<IcRootOfTrust>>(mut self, root_of_trust: T) -> Self {
        self.root_of_trust = root_of_trust.into();
        self
    }

    pub fn with_time_provider(mut self, time_provider: TimeProvider) -> Self {
        self.time_provider = time_provider;
        self
    }

    pub fn build(self) -> IngressMessageVerifier<ConstantRootOfTrustProvider> {
        IngressMessageVerifier::new_internal(self.root_of_trust, self.time_provider)
    }
}

/// Define how current time should be derived.
pub enum TimeProvider {
    /// Current time is always constant and has the given `Time` value. Useful for testing purposes.
    Constant(Time),
    /// Time is derived from the system time as a number of nanoseconds since Epoch.
    SystemTime,
}

impl TimeProvider {
    fn get_relative_time(&self) -> Time {
        match &self {
            TimeProvider::Constant(time) => *time,
            TimeProvider::SystemTime => Time::from_nanos_since_unix_epoch(time()),
        }
    }
}

fn time() -> u64 {
    #[cfg(all(target_family = "wasm", not(feature = "js")))]
    {
        ic_cdk::api::time()
    }
    #[cfg(any(not(target_family = "wasm"), feature = "js"))]
    {
        time::OffsetDateTime::now_utc().unix_timestamp_nanos() as u64
    }
}

pub struct ConstantRootOfTrustProvider {
    root_of_trust: IcRootOfTrust,
}

impl ConstantRootOfTrustProvider {
    fn new<T: Into<IcRootOfTrust>>(root_of_trust: T) -> Self {
        Self {
            root_of_trust: root_of_trust.into(),
        }
    }
}

impl RootOfTrustProvider for ConstantRootOfTrustProvider {
    type Error = Infallible;

    fn root_of_trust(&self) -> Result<IcRootOfTrust, Self::Error> {
        Ok(self.root_of_trust)
    }
}

/// A zero-sized struct that implements the `IngressSigVerifier` trait.
pub struct StandaloneIngressSigVerifier;

impl<S: Signable> BasicSigVerifierByPublicKey<S> for StandaloneIngressSigVerifier {
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key(
            public_key.algorithm_id,
            &signed_bytes.as_signed_bytes(),
            &signature.get_ref().0,
            &public_key.key,
        )
    }
}

impl<S: Signable> CanisterSigVerifier<S> for StandaloneIngressSigVerifier {
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
        root_of_trust: &IcRootOfTrust,
    ) -> CryptoResult<()> {
        use ic_types::crypto::{AlgorithmId, CryptoError};
        if public_key.algorithm_id != AlgorithmId::IcCanisterSignature {
            return Err(CryptoError::AlgorithmNotSupported {
                algorithm: public_key.algorithm_id,
                reason: format!("Expected {:?}", AlgorithmId::IcCanisterSignature),
            });
        }
        ic_crypto_standalone_sig_verifier::verify_canister_sig(
            &signed_bytes.as_signed_bytes(),
            &signature.get_ref().0,
            &public_key.key,
            root_of_trust,
        )
    }
}
