//! Module that deals with requests to /api/v2/canister/.../query

use crate::{
    common::{cbor_response, make_plaintext_response},
    types::{to_legacy_request_type, ApiReqType},
    validator_executor::ValidatorExecutor,
    HttpHandlerMetrics, ReplicaHealthStatus, UNKNOWN_LABEL,
};
use futures_util::FutureExt;
use hyper::{Body, Response, StatusCode};
use ic_interfaces::{execution_environment::QueryExecutionService, registry::RegistryClient};
use ic_logger::{trace, ReplicaLogger};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{
        CertificateDelegation, HttpQueryContent, HttpRequest, HttpRequestEnvelope,
        SignedRequestBytes, UserQuery,
    },
};
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
    validator_executor: ValidatorExecutor,
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
        validator_executor: ValidatorExecutor,
        registry_client: Arc<dyn RegistryClient>,
        query_execution_service: QueryExecutionService,
        malicious_flags: MaliciousFlags,
    ) -> QueryService {
        Self {
            log,
            metrics,
            health_status,
            delegation_from_nns,
            validator_executor,
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
        // Replace query service stored in struct with cloned verison of query_service.
        let mut old_query_execution_service = std::mem::replace(
            &mut self.query_execution_service,
            new_query_execution_service,
        );

        let registry_client = self.registry_client.get_latest_version();
        let malicious_flags = self.malicious_flags.clone();
        let validator_executor = self.validator_executor.clone();
        Box::pin(async move {
            match validator_executor
                .get_authorized_canisters(&request, registry_client, &malicious_flags)
                .await
            {
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
            old_query_execution_service
                .call((request.take_content(), delegation_from_nns))
                .map(|result| {
                    let v = result?;
                    Ok(cbor_response(&v))
                })
                .await
        })
    }
}
