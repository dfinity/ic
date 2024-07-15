//! Module that deals with ingress messages
mod call_v2;
mod call_v3;
pub(crate) mod ingress_watcher;

pub use call_v2::CallServiceV2;
pub use call_v3::CallServiceV3;

use crate::{
    common::{build_validator, validation_error_to_http_error},
    HttpError, IngressFilterService,
};
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_error_types::UserError;
use ic_interfaces::ingress_pool::IngressPoolThrottler;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, replica_logger::no_op_logger, warn, ReplicaLogger};
use ic_registry_client_helpers::{
    crypto::root_of_trust::RegistryRootOfTrustProvider,
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{IngressMessageSettings, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    malicious_flags::MaliciousFlags,
    messages::{
        HttpCallContent, HttpRequestEnvelope, MessageId, SignedIngress, SignedIngressContent,
    },
    time::current_time,
    CanisterId, CountBytes, NodeId, RegistryVersion, SubnetId,
};
use ic_validator::HttpRequestVerifier;
use std::convert::TryInto;
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::UnboundedSender;
use tower::ServiceExt;

pub struct IngressValidatorBuilder {
    log: Option<ReplicaLogger>,
    node_id: NodeId,
    subnet_id: SubnetId,
    malicious_flags: Option<MaliciousFlags>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_filter: Arc<Mutex<IngressFilterService>>,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
}

impl IngressValidatorBuilder {
    pub fn builder(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
        ingress_filter: Arc<Mutex<IngressFilterService>>,
        ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
        ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    ) -> Self {
        Self {
            log: None,
            node_id,
            subnet_id,
            malicious_flags: None,
            ingress_verifier,
            registry_client,
            ingress_filter,
            ingress_throttler,
            ingress_tx,
        }
    }

    pub fn with_logger(mut self, log: ReplicaLogger) -> Self {
        self.log = Some(log);
        self
    }

    pub(crate) fn with_malicious_flags(mut self, malicious_flags: MaliciousFlags) -> Self {
        self.malicious_flags = Some(malicious_flags);
        self
    }

    pub fn build(self) -> IngressValidator {
        let log = self.log.unwrap_or(no_op_logger());
        IngressValidator {
            log: log.clone(),
            node_id: self.node_id,
            subnet_id: self.subnet_id,
            registry_client: self.registry_client.clone(),
            validator: build_validator(self.ingress_verifier, self.malicious_flags),
            ingress_filter: self.ingress_filter,
            ingress_throttler: self.ingress_throttler,
            ingress_tx: self.ingress_tx,
        }
    }
}

pub(crate) enum IngressError {
    HttpError(HttpError),
    UserError(UserError),
}

impl From<HttpError> for IngressError {
    fn from(err: HttpError) -> Self {
        IngressError::HttpError(err)
    }
}

impl From<UserError> for IngressError {
    fn from(err: UserError) -> Self {
        IngressError::UserError(err)
    }
}

fn get_registry_data(
    log: &ReplicaLogger,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
) -> Result<(IngressMessageSettings, ProvisionalWhitelist), HttpError> {
    let settings = match registry_client.get_ingress_message_settings(subnet_id, registry_version) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            let message = format!(
                "No subnet record found for registry_version={:?} and subnet_id={:?}",
                registry_version, subnet_id
            );
            warn!(log, "{}", message);
            return Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message,
            });
        }
        Err(err) => {
            let message = format!(
                "max_ingress_bytes_per_message not found for registry_version={:?} and subnet_id={:?}. {:?}",
                registry_version, subnet_id, err
            );
            error!(log, "{}", message);
            return Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message,
            });
        }
    };

    let provisional_whitelist = match registry_client.get_provisional_whitelist(registry_version) {
        Ok(Some(list)) => list,
        Ok(None) => {
            error!(log, "At registry version {}, get_provisional_whitelist() returned Ok(None). Using empty list.",
                       registry_version);
            ProvisionalWhitelist::new_empty()
        }
        Err(err) => {
            error!(log, "At registry version {}, get_provisional_whitelist() failed with {}.  Using empty list.",
                       registry_version, err);
            ProvisionalWhitelist::new_empty()
        }
    };
    Ok((settings, provisional_whitelist))
}

#[derive(Clone)]
pub struct IngressValidator {
    log: ReplicaLogger,
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    validator: Arc<dyn HttpRequestVerifier<SignedIngressContent, RegistryRootOfTrustProvider>>,
    ingress_filter: Arc<Mutex<IngressFilterService>>,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
}

impl IngressValidator {
    /// Validates that the IC can process the request by checking that:
    /// - The ingress pool is not full.
    /// - Ingress message is valid.
    /// - The canister is willing to accept it.
    pub(crate) async fn validate_ingress_message(
        self,
        request: HttpRequestEnvelope<HttpCallContent>,
        effective_canister_id: CanisterId,
    ) -> Result<IngressMessageSubmitter, IngressError> {
        let Self {
            log,
            node_id,
            subnet_id,
            registry_client,
            validator,
            ingress_filter,
            ingress_throttler,
            ingress_tx,
        } = self;

        // Load shed the request if the ingress pool is full.
        let ingress_pool_is_full = ingress_throttler.read().unwrap().exceeds_threshold();
        if ingress_pool_is_full {
            Err(HttpError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "Service is overloaded, try again later.".to_string(),
            })?;
        }

        let msg: SignedIngress = request.try_into().map_err(|e| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse body as call message: {}", e),
        })?;

        // Reject requests where `canister_id` != `effective_canister_id` for non mgmt canister calls.
        // This needs to be enforced because boundary nodes block access based on the `effective_canister_id`
        // in the url and the replica processes the request based on the `canister_id`.
        // If this is not enforced, a blocked canisters can still be accessed by specifying
        // a non-blocked `effective_canister_id` and a blocked `canister_id`.
        if msg.canister_id() != CanisterId::ic_00() && msg.canister_id() != effective_canister_id {
            Err(HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!(
                    "Specified CanisterId {} does not match effective canister id in URL {}",
                    msg.canister_id(),
                    effective_canister_id
                ),
            })?;
        }

        let message_id = msg.id();
        let registry_version = registry_client.get_latest_version();
        let (ingress_registry_settings, provisional_whitelist) =
            get_registry_data(&log, subnet_id, registry_version, registry_client.as_ref())?;
        if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
            Err(HttpError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: format!(
                "Request {} is too large. Message byte size {} is larger than the max allowed {}.",
                message_id,
                msg.count_bytes(),
                ingress_registry_settings.max_ingress_bytes_per_message
            ),
            })?;
        }

        let root_of_trust_provider =
            RegistryRootOfTrustProvider::new(Arc::clone(&registry_client), registry_version);
        // Since spawn blocking requires 'static we can't use any references
        let request_c = msg.as_ref().clone();

        tokio::task::spawn_blocking(move || {
            validator.validate_request(&request_c, current_time(), &root_of_trust_provider)
        })
        .await
        .map_err(|_| HttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "".into(),
        })?
        .map_err(|validation_error| {
            validation_error_to_http_error(message_id, validation_error, &log)
        })?;

        let ingress_filter = ingress_filter.lock().unwrap().clone();

        match ingress_filter
            .oneshot((provisional_whitelist, msg.content().clone()))
            .await
        {
            Err(_) => panic!("Can't panic on Infallible"),
            Ok(Err(user_error)) => {
                Err(user_error)?;
            }
            Ok(Ok(())) => (),
        }

        Ok(IngressMessageSubmitter {
            ingress_tx,
            node_id,
            message: msg,
        })
    }
}

pub struct IngressMessageSubmitter {
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    node_id: NodeId,
    message: SignedIngress,
}

impl IngressMessageSubmitter {
    /// Returns the message id of the ingress message.
    pub(crate) fn message_id(&self) -> MessageId {
        self.message.id()
    }

    /// Attempts to submit the ingress message to the ingress pool.
    /// An [`HttpError`] is returned if P2P is not running.
    pub(crate) fn try_submit(self) -> Result<(), HttpError> {
        let Self {
            ingress_tx,
            node_id,
            message,
        } = self;

        // Submission will fail if P2P is not running, meaning there is
        // no receiver for the ingress message.
        let send_ingress_to_p2p_failed = ingress_tx
            .send(UnvalidatedArtifactMutation::Insert((message, node_id)))
            .is_err();

        if send_ingress_to_p2p_failed {
            return Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "P2P is not running on this node.".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_types::{
        messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope},
        time::expiry_time_from_now,
    };
    use std::convert::TryFrom;

    #[test]
    fn check_request_id() {
        let expiry_time = expiry_time_from_now();
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request1 = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_sig: Some(Blob(vec![])),
            sender_pubkey: Some(Blob(vec![])),
            sender_delegation: None,
        };

        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request2 = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_sig: Some(Blob(b"yes this is a signature".to_vec())),
            sender_pubkey: Some(Blob(b"yes this is a public key: prove it is not!".to_vec())),
            sender_delegation: None,
        };

        let message_id = SignedIngress::try_from(request1).unwrap().id();
        let message_id_2 = SignedIngress::try_from(request2).unwrap().id();
        assert_eq!(message_id_2, message_id);
    }
}
