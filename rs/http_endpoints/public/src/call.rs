//! Module that deals with requests to /api/v2/canister/.../call

use crate::{
    common::CborUserError, validator_executor::ValidatorExecutor, verify_cbor_content_header,
    HttpError, IngressFilterService,
};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
    Router,
};
use bytes::Bytes;
use http::Request;
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_interfaces::ingress_pool::IngressPoolThrottler;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info_sample, replica_logger::no_op_logger, warn, ReplicaLogger};
use ic_registry_client_helpers::{
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{IngressMessageSettings, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    artifact_kind::IngressArtifact,
    malicious_flags::MaliciousFlags,
    messages::{SignedIngress, SignedIngressContent, SignedRequestBytes},
    CanisterId, CountBytes, NodeId, RegistryVersion, SubnetId,
};
use std::convert::{Infallible, TryInto};
use std::sync::Mutex;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::UnboundedSender;
use tower::{util::BoxCloneService, ServiceBuilder, ServiceExt};

#[derive(Clone)]
pub struct CallService {
    log: ReplicaLogger,
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    validator_executor: ValidatorExecutor<SignedIngressContent>,
    ingress_filter: Arc<Mutex<IngressFilterService>>,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<IngressArtifact>>,
}

impl CallService {
    pub(crate) fn route() -> &'static str {
        "/api/v2/canister/:effective_canister_id/call"
    }
}

pub struct CallServiceBuilder {
    log: Option<ReplicaLogger>,
    node_id: NodeId,
    subnet_id: SubnetId,
    malicious_flags: Option<MaliciousFlags>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_filter: Arc<Mutex<IngressFilterService>>,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<IngressArtifact>>,
}

impl CallServiceBuilder {
    pub fn builder(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
        ingress_filter: IngressFilterService,
        ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
        ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<IngressArtifact>>,
    ) -> Self {
        Self {
            log: None,
            node_id,
            subnet_id,
            malicious_flags: None,
            ingress_verifier,
            registry_client,
            ingress_filter: Arc::new(Mutex::new(ingress_filter)),
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

    pub(crate) fn build_router(self) -> Router {
        let log = self.log.unwrap_or(no_op_logger());
        let state = CallService {
            log: log.clone(),
            node_id: self.node_id,
            subnet_id: self.subnet_id,
            registry_client: self.registry_client.clone(),
            validator_executor: ValidatorExecutor::new(
                self.registry_client,
                self.ingress_verifier,
                &self.malicious_flags.unwrap_or_default(),
                log,
            ),
            ingress_filter: self.ingress_filter,
            ingress_throttler: self.ingress_throttler,
            ingress_tx: self.ingress_tx,
        };
        Router::new().route_service(
            CallService::route(),
            axum::routing::post(call).with_state(state).layer(
                ServiceBuilder::new()
                    .layer(DefaultBodyLimit::disable())
                    .layer(axum::middleware::from_fn(verify_cbor_content_header)),
            ),
        )
    }

    pub fn build_service(self) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = self.build_router();
        BoxCloneService::new(router.into_service())
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

/// Handles a call to /api/v2/canister/../call
pub(crate) async fn call(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(CallService {
        log,
        node_id,
        subnet_id,
        registry_client,
        validator_executor,
        ingress_filter,
        ingress_throttler,
        ingress_tx,
    }): State<CallService>,
    body: Bytes,
) -> impl IntoResponse {
    let msg: SignedIngress = match SignedRequestBytes::from(body.to_vec()).try_into() {
        Ok(msg) => msg,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            let text = format!("Could not parse body as call message: {}", e);
            return (status, text).into_response();
        }
    };

    // Reject requests where `canister_id` != `effective_canister_id` for non mgmt canister calls.
    // This needs to be enforced because boundary nodes block access based on the `effective_canister_id`
    // in the url and the replica processes the request based on the `canister_id`.
    // If this is not enforced, a blocked canisters can still be accessed by specifying
    // a non-blocked `effective_canister_id` and a blocked `canister_id`.
    if msg.canister_id() != CanisterId::ic_00() && msg.canister_id() != effective_canister_id {
        let status = StatusCode::BAD_REQUEST;
        let text = format!(
            "Specified CanisterId {} does not match effective canister id in URL {}",
            msg.canister_id(),
            effective_canister_id
        );
        return (status, text).into_response();
    }

    let message_id = msg.id();
    let registry_version = registry_client.get_latest_version();
    let (ingress_registry_settings, provisional_whitelist) =
        match get_registry_data(&log, subnet_id, registry_version, registry_client.as_ref()) {
            Ok((s, p)) => (s, p),
            Err(HttpError { status, message }) => {
                return (status, message).into_response();
            }
        };
    if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
        let status = StatusCode::PAYLOAD_TOO_LARGE;
        let text = format!(
            "Request {} is too large. Message byte size {} is larger than the max allowed {}.",
            message_id,
            msg.count_bytes(),
            ingress_registry_settings.max_ingress_bytes_per_message
        );
        return (status, text).into_response();
    }

    if let Err(http_err) = validator_executor
        .validate_request(msg.as_ref().clone(), registry_version)
        .await
    {
        return (http_err.status, http_err.message).into_response();
    }

    let ingress_filter = ingress_filter.lock().unwrap().clone();

    match ingress_filter
        .oneshot((provisional_whitelist, msg.content().clone()))
        .await
    {
        Err(_) => panic!("Can't panic on Infallible"),
        Ok(Err(err)) => {
            return CborUserError(err).into_response();
        }
        Ok(Ok(())) => (),
    }

    let ingress_log_entry = msg.log_entry();

    let is_overloaded = ingress_throttler.read().unwrap().exceeds_threshold()
        || ingress_tx
            .send(UnvalidatedArtifactMutation::Insert((msg, node_id)))
            .is_err();

    if is_overloaded {
        let status = StatusCode::TOO_MANY_REQUESTS;
        let text = "Service is overloaded, try again later.".to_string();
        (status, text).into_response()
    } else {
        // We're pretty much done, just need to send the message to ingress and
        // make_response to the client
        info_sample!(
            "message_id" => &message_id,
            log,
            "ingress_message_submit";
            ingress_message => ingress_log_entry
        );
        let status = StatusCode::ACCEPTED;
        (status, "").into_response()
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
