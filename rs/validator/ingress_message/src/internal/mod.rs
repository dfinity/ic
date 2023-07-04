use crate::{AuthenticationError, HttpRequestVerifier, RequestValidationError};
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_interfaces::time_source::TimeSource;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_crypto_threshold_signing_pubkey_key, ROOT_SUBNET_ID_KEY};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider, ThresholdSigPublicKey};
use ic_types::messages::{HttpRequest, HttpRequestContent};
use ic_types::time::UNIX_EPOCH;
use ic_types::{PrincipalId, RegistryVersion, SubnetId, Time};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(test)]
mod tests;

const DUMMY_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
// NNS root public key DER encoded in base 64
const IC_NNS_ROOT_PUBLIC_KEY_BASE64: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;

/// An implementation of [`HttpRequestVerifier`] to verify ingress messages.
pub struct IngressMessageVerifier {
    time_source: Arc<dyn TimeSource>,
    validator: ic_validator::HttpRequestVerifierImpl,
}

impl Default for IngressMessageVerifier {
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
        IngressMessageVerifier::builder()
            .with_root_of_trust(nns_root_public_key())
            .with_time_provider(TimeProvider::SystemTime)
            .build()
    }
}

impl IngressMessageVerifier {
    fn new_internal(
        root_of_trust: ThresholdSigPublicKey,
        time_source: Arc<dyn TimeSource>,
    ) -> Self {
        let (registry_client, registry_data) = registry_with_root_of_trust(root_of_trust);
        IngressMessageVerifier {
            time_source,
            validator: ic_validator::HttpRequestVerifierImpl::new(Arc::new(
                TempCryptoComponent::builder()
                    .with_keys(NodeKeysToGenerate::none())
                    .with_registry_client_and_data(registry_client, registry_data)
                    .build(),
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

fn registry_with_root_of_trust(
    root_of_trust: ThresholdSigPublicKey,
) -> (Arc<FakeRegistryClient>, Arc<ProtoRegistryDataProvider>) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let root_subnet_id_raw = dummy_root_subnet_id();
    let root_subnet_id = SubnetIdProto {
        principal_id: Some(PrincipalIdProto {
            raw: root_subnet_id_raw.get_ref().to_vec(),
        }),
    };
    registry_data
        .add(
            ROOT_SUBNET_ID_KEY,
            DUMMY_REGISTRY_VERSION,
            Some(root_subnet_id),
        )
        .expect("failed to add root subnet ID to registry");

    let root_subnet_pubkey = PublicKey::from(root_of_trust);
    registry_data
        .add(
            &make_crypto_threshold_signing_pubkey_key(root_subnet_id_raw),
            DUMMY_REGISTRY_VERSION,
            Some(root_subnet_pubkey),
        )
        .expect("failed to add root subnet ID to registry");
    registry_client.reload();
    (registry_client, registry_data)
}

fn nns_root_public_key() -> ThresholdSigPublicKey {
    use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
    let decoded_nns_mainnet_key = base64::decode(IC_NNS_ROOT_PUBLIC_KEY_BASE64)
        .expect("Failed to decode mainnet public key from base64.");
    parse_threshold_sig_key_from_der(&decoded_nns_mainnet_key)
        .expect("Failed to decode mainnet public key.")
}

impl<C: HttpRequestContent> HttpRequestVerifier<C> for IngressMessageVerifier
where
    ic_validator::HttpRequestVerifierImpl: ic_validator::HttpRequestVerifier<C>,
{
    fn validate_request(&self, request: &HttpRequest<C>) -> Result<(), RequestValidationError> {
        ic_validator::HttpRequestVerifier::validate_request(
            &self.validator,
            request,
            self.time_source.get_relative_time(),
            DUMMY_REGISTRY_VERSION,
        )
        .map(|_| ())
        .map_err(to_validation_error)
    }
}

fn to_validation_error(error: ic_validator::RequestValidationError) -> RequestValidationError {
    match error {
        ic_validator::RequestValidationError::InvalidIngressExpiry(msg) => {
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
    }
}
fn to_authentication_lib_error(error: ic_validator::AuthenticationError) -> AuthenticationError {
    match error {
        ic_validator::AuthenticationError::InvalidBasicSignature(crypto_error) => {
            AuthenticationError::InvalidBasicSignature(format!("{crypto_error}"))
        }
        ic_validator::AuthenticationError::InvalidCanisterSignature(crypto_error) => {
            AuthenticationError::InvalidCanisterSignature(format!("{crypto_error}"))
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

fn dummy_root_subnet_id() -> SubnetId {
    SubnetId::new(PrincipalId::new(
        10,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ],
    ))
}

pub struct IngressMessageVerifierBuilder {
    root_of_trust: ThresholdSigPublicKey,
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
    pub fn with_root_of_trust(mut self, public_key: ThresholdSigPublicKey) -> Self {
        self.root_of_trust = public_key;
        self
    }

    pub fn with_time_provider(mut self, time_provider: TimeProvider) -> Self {
        self.time_provider = time_provider;
        self
    }

    pub fn build(self) -> IngressMessageVerifier {
        IngressMessageVerifier::new_internal(self.root_of_trust, Arc::new(self.time_provider))
    }
}

/// Define how current time should be derived.
pub enum TimeProvider {
    /// Current time is always constant and has the given `Time` value. Useful for testing purposes.
    Constant(Time),
    /// Time is derived from the system time as a number of nanoseconds since Epoch.
    SystemTime,
}

impl TimeSource for TimeProvider {
    fn get_relative_time(&self) -> Time {
        match &self {
            TimeProvider::Constant(time) => *time,
            TimeProvider::SystemTime => {
                UNIX_EPOCH
                    + SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("SystemTime is before UNIX EPOCH!")
            }
        }
    }
}

pub struct ConstantRootOfTrustProvider {
    root_of_trust: IcRootOfTrust,
}

impl ConstantRootOfTrustProvider {
    #[allow(dead_code)]
    //TODO CRP-2046: use this to instantiate provider
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
