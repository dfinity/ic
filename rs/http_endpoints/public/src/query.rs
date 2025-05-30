//! Module that deals with requests to /api/v2/canister/.../query

use crate::{
    common::{build_validator, validation_error_to_http_error, Cbor, WithTimeout},
    ReplicaHealthStatus,
};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
    Router,
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_error_types::{ErrorCode, RejectCode};
use ic_interfaces::{
    crypto::BasicSigner,
    execution_environment::{QueryExecutionError, QueryExecutionService},
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, ReplicaLogger};
use ic_registry_client_helpers::crypto::root_of_trust::RegistryRootOfTrustProvider;
use ic_types::{
    ingress::WasmResult,
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, CertificateDelegation, HasCanisterId, HttpQueryContent, HttpQueryResponse,
        HttpQueryResponseReply, HttpRequest, HttpRequestEnvelope, HttpSignedQueryResponse,
        NodeSignature, Query, QueryResponseHash,
    },
    CanisterId, NodeId,
};
use ic_validator::HttpRequestVerifier;
use std::sync::Arc;
use std::{
    convert::{Infallible, TryFrom},
    sync::Mutex,
};
use tokio::sync::watch;
use tower::{util::BoxCloneService, ServiceBuilder, ServiceExt};

#[derive(Clone)]
pub struct QueryService {
    log: ReplicaLogger,
    node_id: NodeId,
    signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: watch::Receiver<Option<CertificateDelegation>>,
    time_source: Arc<dyn TimeSource>,
    validator: Arc<dyn HttpRequestVerifier<Query, RegistryRootOfTrustProvider>>,
    registry_client: Arc<dyn RegistryClient>,
    query_execution_service: Arc<Mutex<QueryExecutionService>>,
}

pub struct QueryServiceBuilder {
    log: ReplicaLogger,
    node_id: NodeId,
    signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    malicious_flags: Option<MaliciousFlags>,
    delegation_from_nns: watch::Receiver<Option<CertificateDelegation>>,
    time_source: Option<Arc<dyn TimeSource>>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    query_execution_service: QueryExecutionService,
}

impl QueryService {
    pub(crate) fn route() -> &'static str {
        "/api/v2/canister/{effective_canister_id}/query"
    }
}

impl QueryServiceBuilder {
    pub fn builder(
        log: ReplicaLogger,
        node_id: NodeId,
        signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
        delegation_from_nns: watch::Receiver<Option<CertificateDelegation>>,
        query_execution_service: QueryExecutionService,
    ) -> Self {
        Self {
            log,
            node_id,
            signer,
            health_status: None,
            malicious_flags: None,
            delegation_from_nns,
            time_source: None,
            ingress_verifier,
            registry_client,
            query_execution_service,
        }
    }

    pub(crate) fn with_malicious_flags(mut self, malicious_flags: MaliciousFlags) -> Self {
        self.malicious_flags = Some(malicious_flags);
        self
    }

    pub fn with_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
        self.time_source = Some(time_source);
        self
    }

    pub fn with_health_status(
        mut self,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    ) -> Self {
        self.health_status = Some(health_status);
        self
    }

    pub fn build_router(self) -> Router {
        let log = self.log;
        let state = QueryService {
            log: log.clone(),
            node_id: self.node_id,
            signer: self.signer,
            health_status: self
                .health_status
                .unwrap_or_else(|| Arc::new(AtomicCell::new(ReplicaHealthStatus::Healthy))),
            delegation_from_nns: self.delegation_from_nns,
            time_source: self.time_source.unwrap_or(Arc::new(SysTimeSource::new())),
            validator: build_validator(self.ingress_verifier, self.malicious_flags),
            registry_client: self.registry_client,
            query_execution_service: Arc::new(Mutex::new(self.query_execution_service)),
        };
        Router::new().route_service(
            QueryService::route(),
            axum::routing::post(query)
                .with_state(state)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn build_service(self) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = self.build_router();
        BoxCloneService::new(router.into_service())
    }
}

pub(crate) async fn query(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(QueryService {
        log,
        node_id,
        registry_client,
        time_source,
        validator,
        health_status,
        signer,
        delegation_from_nns,
        query_execution_service,
    }): State<QueryService>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpQueryContent>>>,
) -> impl IntoResponse {
    if health_status.load() != ReplicaHealthStatus::Healthy {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let text = format!(
            "Replica is unhealthy: {:?}. Check the /api/v2/status for more information.",
            health_status.load(),
        );
        return (status, text).into_response();
    }
    let delegation_from_nns = delegation_from_nns.borrow().clone();

    let registry_version = registry_client.get_latest_version();

    // Convert the message to a strongly-typed struct, making structural validations
    // on the way.
    let request = match HttpRequest::<Query>::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            let text = format!("Malformed request: {:?}", e);
            return (status, text).into_response();
        }
    };
    let canister_id = request.content().canister_id();
    if canister_id != CanisterId::ic_00() && canister_id != effective_canister_id {
        let status = StatusCode::BAD_REQUEST;
        let text = format!(
            "Specified CanisterId {} does not match effective canister id in URL {}",
            canister_id, effective_canister_id
        );
        return (status, text).into_response();
    }

    let root_of_trust_provider =
        RegistryRootOfTrustProvider::new(Arc::clone(&registry_client), registry_version);
    // Since spawn blocking requires 'static we can't use any references
    let request_c = request.clone();
    match tokio::task::spawn_blocking(move || {
        validator.validate_request(
            &request_c,
            time_source.get_relative_time(),
            &root_of_trust_provider,
        )
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            let http_err = validation_error_to_http_error(&request, err, &log);
            return (http_err.status, http_err.message).into_response();
        }
        Err(_) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let user_query = request.take_content();

    let query_execution_service = query_execution_service.lock().unwrap().clone();
    let query_execution_response = query_execution_service
        .oneshot((user_query.clone(), delegation_from_nns))
        .await
        .unwrap();

    let (response, timestamp) = match query_execution_response {
        Err(QueryExecutionError::CertifiedStateUnavailable) => {
            let status = StatusCode::SERVICE_UNAVAILABLE;
            let text = "Certified state unavailable. Please try again.".to_string();
            return (status, text).into_response();
        }
        Ok((response, time)) => (response, time),
    };

    let query_response = match response {
        Ok(res) => match res {
            WasmResult::Reply(vec) => HttpQueryResponse::Replied {
                reply: HttpQueryResponseReply { arg: Blob(vec) },
            },
            WasmResult::Reject(message) => HttpQueryResponse::Rejected {
                error_code: ErrorCode::CanisterRejectedMessage.to_string(),
                reject_code: RejectCode::CanisterReject as u64,
                reject_message: message,
            },
        },

        Err(user_error) => HttpQueryResponse::Rejected {
            error_code: user_error.code().to_string(),
            reject_code: user_error.reject_code() as u64,
            reject_message: user_error.description().to_string(),
        },
    };

    let response_hash = QueryResponseHash::new(&query_response, &user_query, timestamp);

    // We wrap `sign_basic` into `spawn_blocking`, otherwise calling `sign_basic` will panic
    // if called from the tokio runtime.
    let signature = tokio::task::spawn_blocking(move || {
        signer.sign_basic(&response_hash, node_id, registry_version)
    })
    .await
    .expect("Panicked while attempting to sign the query response.");

    match signature {
        Ok(signature) => {
            let signature_bytes = signature.get().0;
            let signature_blob = Blob(signature_bytes);

            let node_signature = NodeSignature {
                signature: signature_blob,
                timestamp,
                identity: node_id,
            };

            let signed_query_response = HttpSignedQueryResponse {
                response: query_response,
                node_signature,
            };

            Cbor(signed_query_response).into_response()
        }
        Err(signing_error) => {
            error!(
                log,
                "Failed to sign the Query response: `{:?}`.", signing_error
            );
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            let text = "Failed to sign the Query response.".to_string();
            (status, text).into_response()
        }
    }
}
