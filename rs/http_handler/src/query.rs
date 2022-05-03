//! Module that deals with requests to /api/v2/canister/.../query

use crate::{
    common::{cbor_response, make_plaintext_response, make_response_on_validation_error},
    types::{to_legacy_request_type, ApiReqType},
    HttpHandlerMetrics, ReplicaHealthStatus, UNKNOWN_LABEL,
};
use futures_util::FutureExt;
use hyper::{Body, Response, StatusCode};
use ic_interfaces::{
    crypto::IngressSigVerifier, execution_environment::QueryExecutionService,
    registry::RegistryClient,
};
use ic_logger::{trace, ReplicaLogger};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{
        CertificateDelegation, HttpQueryContent, HttpRequest, HttpRequestEnvelope,
        SignedRequestBytes, UserQuery,
    },
    time::current_time,
};
use ic_validator::get_authorized_canisters;
use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{BoxError, Service};

#[derive(Clone)]
pub(crate) struct QueryService {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    query_execution_service: QueryExecutionService,
    malicious_flags: MaliciousFlags,
}

impl QueryService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        health_status: Arc<RwLock<ReplicaHealthStatus>>,
        delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
        validator: Arc<dyn IngressSigVerifier + Send + Sync>,
        registry_client: Arc<dyn RegistryClient>,
        query_execution_service: QueryExecutionService,
        malicious_flags: MaliciousFlags,
    ) -> QueryService {
        Self {
            log,
            metrics,
            health_status,
            delegation_from_nns,
            validator,
            registry_client,
            query_execution_service,
            malicious_flags,
        }
    }
}

impl Service<Vec<u8>> for QueryService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.query_execution_service.poll_ready(cx)
    }

    fn call(&mut self, body: Vec<u8>) -> Self::Future {
        trace!(self.log, "in handle query");
        self.metrics
            .requests_body_size_bytes
            .with_label_values(&[
                to_legacy_request_type(ApiReqType::Query),
                ApiReqType::Query.into(),
                UNKNOWN_LABEL,
            ])
            .observe(body.len() as f64);
        if *self.health_status.read().unwrap() != ReplicaHealthStatus::Healthy {
            let res = make_plaintext_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Replica is starting. Check the /api/v2/status for more information.".to_string(),
            );
            return Box::pin(async move { Ok(res) });
        }
        let delegation_from_nns = self.delegation_from_nns.read().unwrap().clone();

        let request = match <HttpRequestEnvelope<HttpQueryContent>>::try_from(
            &SignedRequestBytes::from(body),
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
        let query = request.content();

        match get_authorized_canisters(
            &request,
            self.validator.as_ref(),
            current_time(),
            self.registry_client.get_latest_version(),
            &self.malicious_flags,
        ) {
            Ok(targets) => {
                if !targets.contains(&query.receiver) {
                    let res = make_plaintext_response(StatusCode::FORBIDDEN, "".to_string());
                    return Box::pin(async move { Ok(res) });
                }
            }
            Err(err) => {
                let res = make_response_on_validation_error(request.id(), err, &self.log);
                return Box::pin(async move { Ok(res) });
            }
        };

        Box::pin(
            self.query_execution_service
                .call((query.clone(), delegation_from_nns))
                .map(|result| {
                    let v = result?;
                    Ok(cbor_response(&v))
                }),
        )
    }
}
