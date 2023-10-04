//! Module that deals with requests to /api/v2/canister/.../query

use crate::{
    body::BodyReceiverLayer,
    common::{cbor_response, make_plaintext_response, remove_effective_principal_id},
    metrics::LABEL_UNKNOWN,
    types::ApiReqType,
    validator_executor::ValidatorExecutor,
    EndpointService, HttpHandlerMetrics, ReplicaHealthStatus,
};
use bytes::Bytes;
use crossbeam::atomic::AtomicCell;
use futures_util::FutureExt;
use http::Request;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_interfaces::{
    crypto::BasicSigner,
    execution_environment::{QueryExecutionError, QueryExecutionService},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, ReplicaLogger};
use ic_types::{
    messages::{
        Blob, CertificateDelegation, HasCanisterId, HttpQueryContent, HttpRequest,
        HttpRequestEnvelope, HttpSignedQueryResponse, NodeSignature, QueryResponseHash,
        SignedRequestBytes, UserQuery,
    },
    CanisterId, NodeId,
};
use std::convert::{Infallible, TryFrom};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{limit::GlobalConcurrencyLimitLayer, util::BoxCloneService, Service, ServiceBuilder};

#[derive(Clone)]
pub(crate) struct QueryService {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    node_id: NodeId,
    signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    validator_executor: ValidatorExecutor<UserQuery>,
    registry_client: Arc<dyn RegistryClient>,
    query_execution_service: QueryExecutionService,
}

impl QueryService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_service(
        config: Config,
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
        node_id: NodeId,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        validator_executor: ValidatorExecutor<UserQuery>,
        registry_client: Arc<dyn RegistryClient>,
        query_execution_service: QueryExecutionService,
    ) -> EndpointService {
        let base_service = BoxCloneService::new(
            ServiceBuilder::new()
                .layer(GlobalConcurrencyLimitLayer::new(
                    config.max_query_concurrent_requests,
                ))
                .service(Self {
                    log,
                    metrics,
                    node_id,
                    signer,
                    health_status,
                    delegation_from_nns,
                    validator_executor,
                    registry_client,
                    query_execution_service,
                }),
        );
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(BodyReceiverLayer::new(&config))
                .service(base_service),
        )
    }
}

impl Service<Request<Bytes>> for QueryService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.query_execution_service.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        self.metrics
            .request_body_size_bytes
            .with_label_values(&[ApiReqType::Query.into(), LABEL_UNKNOWN])
            .observe(request.body().len() as f64);
        if self.health_status.load() != ReplicaHealthStatus::Healthy {
            let res = make_plaintext_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Replica is unhealthy: {}. Check the /api/v2/status for more information.",
                    self.health_status.load(),
                ),
            );
            return Box::pin(async move { Ok(res) });
        }
        let delegation_from_nns = self.delegation_from_nns.read().unwrap().clone();

        let (mut parts, body) = request.into_parts();
        let request = match <HttpRequestEnvelope<HttpQueryContent>>::try_from(
            &SignedRequestBytes::from(body.to_vec()),
        ) {
            Ok(request) => request,
            Err(e) => {
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Could not parse body as read request: {}", e),
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        // Convert the message to a strongly-typed struct, making structural validations
        // on the way.
        let request = match HttpRequest::<UserQuery>::try_from(request) {
            Ok(request) => request,
            Err(e) => {
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Malformed request: {:?}", e),
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        let effective_principal_id = match remove_effective_principal_id(&mut parts) {
            Ok(principal_id) => principal_id,
            Err(res) => {
                error!(
                    self.log,
                    "Effective canister ID is not attached to call request. This is a bug."
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        let effective_canister_id = match CanisterId::new(effective_principal_id) {
            Ok(canister_id) => canister_id,
            Err(_) => {
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid canister id: {}", effective_principal_id),
                );
                return Box::pin(async move { Ok(res) });
            }
        };

        // Reject requests where `canister_id` != `effective_canister_id`. In comparison to update
        // requests we don't need to check for the mgmt canister since all mgmt canister calls are updated calls.
        // This needs to be enforced because boundary nodes block access based on the `effective_canister_id`
        // in the url and the replica processes the request based on the `canister_id`.
        // If this is not enforced, a blocked canisters can still be accessed by specifying
        // a non-blocked `effective_canister_id` and a blocked `canister_id`.
        let canister_id = request.content().canister_id();
        if canister_id != effective_canister_id {
            let res = make_plaintext_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "Specified CanisterId {} does not match effective canister id in URL {}",
                    canister_id, effective_canister_id
                ),
            );
            return Box::pin(async move { Ok(res) });
        }

        // In case the inner service has state that's driven to readiness and
        // not tracked by clones (such as `Buffer`), pass the version we have
        // already called `poll_ready` on into the future, and leave its clone
        // behind.
        //
        // The types implementing the Service trait are not necessary thread-safe.
        // So the unless the caller is sure that the service implementation is
        // thread-safe we must make sure 'poll_ready' is always called before 'call'
        // on the same object. Hence if 'poll_ready' is called and not tracked by
        // the 'Clone' implementation the following sequence of events may panic.
        //
        //  s1.call_ready()
        //  s2 = s1.clone()
        //  s2.call()
        //
        // NOTE: Buffer::Clone does not track readiness across clones.

        let new_query_execution_service = self.query_execution_service.clone();
        // Pass old query execution service to future that has already been driven to readiness (called ready() on).
        // Replace query service stored in struct with cloned version of query_service.
        let mut old_query_execution_service = std::mem::replace(
            &mut self.query_execution_service,
            new_query_execution_service,
        );

        let registry_version = self.registry_client.get_latest_version();
        let signer_clone = self.signer.clone();

        let validator_executor = self.validator_executor.clone();
        let response_body_size_bytes_metric = self.metrics.response_body_size_bytes.clone();
        let node_id = self.node_id;
        let logger = self.log.clone();

        async move {
            let get_authorized_canisters_fut =
                validator_executor.validate_request(request.clone(), registry_version);

            match get_authorized_canisters_fut.await {
                Ok(targets) => {
                    if !targets.contains(&request.content().receiver) {
                        let res = make_plaintext_response(StatusCode::FORBIDDEN, "".to_string());
                        return Ok(res);
                    }
                }
                Err(http_err) => {
                    let res = make_plaintext_response(http_err.status, http_err.message);
                    return Ok(res);
                }
            };
            let user_query = request.take_content();

            let query_execution_response = old_query_execution_service
                .call((user_query.clone(), delegation_from_nns))
                .await?;

            let (query_response, timestamp) = match query_execution_response {
                Err(QueryExecutionError::CertifiedStateUnavailable) => {
                    return Ok(make_plaintext_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Certified state unavailable. Please try again.".to_string(),
                    ))
                }
                Ok((response, time)) => (response, time),
            };

            let response_hash = QueryResponseHash::new(&query_response, &user_query, timestamp);

            // We wrap `sign_basic` into `spawn_blocking`, otherwise calling `sign_basic` will panic
            // if called from the tokio runtime.
            let signature = tokio::task::spawn_blocking(move || {
                signer_clone.sign_basic(&response_hash, node_id, registry_version)
            })
            .await
            .expect("Panicked while attempting to sign the query response.");

            let response = match signature {
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

                    let (resp, body_size) = cbor_response(&signed_query_response);
                    response_body_size_bytes_metric
                        .with_label_values(&[ApiReqType::Query.into()])
                        .observe(body_size as f64);
                    resp
                }
                Err(signing_error) => {
                    error!(
                        logger,
                        "Failed to sign the Query response: `{:?}`.", signing_error
                    );
                    make_plaintext_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to sign the Query response.".to_string(),
                    )
                }
            };

            Ok(response)
        }
        .boxed()
    }
}
