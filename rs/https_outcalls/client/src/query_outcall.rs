//! The replica-side client for non-replicated HTTP outcalls made from queries.
//!
//! Unlike [`crate::CanisterHttpAdapterClientImpl`], which serves consensus and
//! is shaped around its polling loop, this is a plain tower service: one
//! request, one awaitable response, no correlation ids and no state kept between
//! calls. Nothing here touches consensus, cycles, or the replicated state.
//!
//! It also deliberately does not apply the response transform. A query outcall's
//! transform runs inside the query context that requested it, because the
//! service that would otherwise run it shares its thread pool with the very
//! query that is waiting.

use crate::client::{execute_http_request, validate_response};
use ic_error_types::RejectCode;
use ic_https_outcalls_pricing::query::QueryOutcallBudget;
use ic_https_outcalls_service::https_outcalls_service_client::HttpsOutcallsServiceClient;
use ic_https_outcalls_socks_proxy::SocksProxyProvider;
use ic_interfaces::execution_environment::QueryOutcallService;
use ic_logger::{ReplicaLogger, info};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_types::canister_http::{CanisterHttpReject, QueryOutcallOutcome, QueryOutcallRequest};
use ic_types_cycles::Cycles;
use prometheus::{HistogramVec, IntCounterVec, IntGauge};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Service, util::BoxCloneService};

const LABEL_STATUS: &str = "status";
const LABEL_STATUS_CODE: &str = "status_code";
const LABEL_HTTP_METHOD: &str = "http_method";
const LABEL_REASON: &str = "reason";

/// Metrics for outcalls made from queries.
///
/// Deliberately named apart from [`crate::metrics::Metrics`], which covers the
/// consensus-driven outcalls: registering the same metric name twice panics, and
/// the two paths have very different volume and failure modes anyway.
#[derive(Clone)]
struct QueryOutcallMetrics {
    /// Duration of the adapter call, by resulting HTTP status.
    duration: HistogramVec,
    total: IntCounterVec,
    in_flight: IntGauge,
    rejected: IntCounterVec,
}

impl QueryOutcallMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            duration: metrics_registry.histogram_vec(
                "query_http_outcall_duration_seconds",
                "Duration of an HTTP outcall made from a query.",
                // 100ms, 200ms, 500ms, …, 10s, 20s, 50s
                decimal_buckets(-1, 1),
                &[LABEL_STATUS_CODE, LABEL_HTTP_METHOD],
            ),
            total: metrics_registry.int_counter_vec(
                "query_http_outcalls_total",
                "HTTP outcalls made from queries, by outcome.",
                &[LABEL_STATUS, LABEL_HTTP_METHOD],
            ),
            in_flight: metrics_registry.int_gauge(
                "query_http_outcalls_in_flight",
                "HTTP outcalls made from queries that are currently in flight.",
            ),
            rejected: metrics_registry.int_counter_vec(
                "query_http_outcalls_rejected_total",
                "HTTP outcalls from queries refused before reaching the adapter.",
                &[LABEL_REASON],
            ),
        }
    }
}

/// Keeps the in-flight gauge honest when the outcall future is dropped.
struct InFlightGuard(IntGauge);

impl InFlightGuard {
    fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        Self(gauge)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

#[derive(Clone)]
struct QueryOutcallServiceImpl {
    /// `None` if this replica has no adapter to talk to.
    grpc_channel: Option<tonic::transport::Channel>,
    socks_proxy: Arc<dyn SocksProxyProvider>,
    metrics: QueryOutcallMetrics,
    log: ReplicaLogger,
}

impl Service<QueryOutcallRequest> for QueryOutcallServiceImpl {
    type Response = QueryOutcallOutcome;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Concurrency is bounded upstream, by how many queries this node keeps
        // suspended. A limit here would queue callers rather than refuse them.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: QueryOutcallRequest) -> Self::Future {
        let channel = self.grpc_channel.clone();
        let socks_proxy = Arc::clone(&self.socks_proxy);
        let metrics = self.metrics.clone();
        let log = self.log.clone();

        Box::pin(
            async move { Ok(perform_outcall(channel, socks_proxy, metrics, log, request).await) },
        )
    }
}

async fn perform_outcall(
    channel: Option<tonic::transport::Channel>,
    socks_proxy: Arc<dyn SocksProxyProvider>,
    metrics: QueryOutcallMetrics,
    log: ReplicaLogger,
    request: QueryOutcallRequest,
) -> QueryOutcallOutcome {
    let http_method = request.http_method.as_str().to_string();

    let Some(channel) = channel else {
        metrics
            .rejected
            .with_label_values(&["adapter_unavailable"])
            .inc();
        return unspent(CanisterHttpReject {
            reject_code: RejectCode::SysFatal,
            message: "HTTPS outcalls adapter is not available".to_string(),
        });
    };

    let _in_flight_guard = InFlightGuard::new(metrics.in_flight.clone());
    let mut adapter_client = HttpsOutcallsServiceClient::new(channel);

    let QueryOutcallRequest {
        requester,
        url,
        http_method: canister_http_method,
        headers,
        body,
        max_response_bytes,
        max_response_time,
        allowance,
    } = request;

    let mut budget = QueryOutcallBudget::new(allowance, max_response_bytes, max_response_time);

    let outcome = execute_http_request(
        &mut adapter_client,
        url,
        canister_http_method,
        headers,
        body,
        socks_proxy.socks_proxy_addrs(),
        &mut budget,
        // Charge for the time the outcall actually took.
        None,
    )
    .await;

    let result = match outcome {
        Ok((adapter_response, downloaded_bytes, elapsed)) => {
            let response = validate_response(adapter_response);
            let status_code = match &response {
                Ok(payload) => payload.status.to_string(),
                Err(reject) => reject.reject_code.to_string(),
            };
            metrics
                .duration
                .with_label_values(&[status_code.as_str(), http_method.as_str()])
                .observe(elapsed.as_secs_f64());
            info!(
                log,
                "Completed HTTP outcall from a query: requester {}, downloaded_bytes {}, \
                response_time_ms {}, max_response_bytes {}, spent {}",
                requester,
                downloaded_bytes,
                elapsed.as_millis(),
                max_response_bytes,
                budget.spent(),
            );
            response
        }
        Err(reject) => Err(reject),
    };

    let status = match &result {
        Ok(_) => "success",
        Err(_) => "reject",
    };
    metrics
        .total
        .with_label_values(&[status, http_method.as_str()])
        .inc();

    // Reported on the reject path too: a failure still costs bytes and time.
    QueryOutcallOutcome {
        result,
        spent: budget.spent(),
    }
}

/// An outcall refused before it reached the adapter, so nothing was spent.
fn unspent(reject: CanisterHttpReject) -> QueryOutcallOutcome {
    QueryOutcallOutcome {
        result: Err(reject),
        spent: Cycles::zero(),
    }
}

/// The service performing non-replicated HTTP outcalls on behalf of queries.
///
/// A `channel` of `None` yields a service that reports the adapter as
/// unavailable for every request.
pub fn setup_query_outcall_service(
    channel: Option<tonic::transport::Channel>,
    socks_proxy: Arc<dyn SocksProxyProvider>,
    metrics_registry: &MetricsRegistry,
    log: ReplicaLogger,
) -> QueryOutcallService {
    BoxCloneService::new(QueryOutcallServiceImpl {
        grpc_channel: channel,
        socks_proxy,
        metrics: QueryOutcallMetrics::new(metrics_registry),
        log,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        SingleResponseAdapter, create_result_from_response, serve_mock_adapter,
    };
    use ic_https_outcalls_service::{
        CanisterHttpError, CanisterHttpErrorKind, HttpHeader, HttpMethod, HttpsOutcallResponse,
        HttpsOutcallResult, https_outcall_result,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_types::{
        CanisterId, NumBytes,
        canister_http::{CanisterHttpHeader, CanisterHttpMethod, MAX_CANISTER_HTTP_RESPONSE_BYTES},
    };
    use std::time::Duration;
    use tonic::Code;
    use tower::ServiceExt;

    struct NoProxies;

    impl SocksProxyProvider for NoProxies {
        fn socks_proxy_addrs(&self) -> Vec<String> {
            Vec::new()
        }
    }

    struct FixedProxies(Vec<String>);

    impl SocksProxyProvider for FixedProxies {
        fn socks_proxy_addrs(&self) -> Vec<String> {
            self.0.clone()
        }
    }

    fn request() -> QueryOutcallRequest {
        QueryOutcallRequest {
            requester: CanisterId::from(1),
            url: "https://example.com/path".to_string(),
            http_method: CanisterHttpMethod::GET,
            headers: vec![],
            body: None,
            max_response_bytes: NumBytes::from(MAX_CANISTER_HTTP_RESPONSE_BYTES),
            max_response_time: Duration::from_secs(10),
            // Ample, so that these tests exercise the request path rather than
            // the budget; the budget has its own tests in the pricing crate.
            allowance: Cycles::new(1_000_000_000_000),
        }
    }

    fn service(
        channel: Option<tonic::transport::Channel>,
        socks_proxy: Arc<dyn SocksProxyProvider>,
    ) -> QueryOutcallService {
        setup_query_outcall_service(
            channel,
            socks_proxy,
            &MetricsRegistry::new(),
            no_op_logger(),
        )
    }

    fn ok_response() -> HttpsOutcallResult {
        create_result_from_response(HttpsOutcallResponse {
            status: 200,
            headers: vec![HttpHeader {
                name: "Content-Type".to_string(),
                value: "text/plain".to_string(),
            }],
            content: b"hello".to_vec(),
        })
    }

    fn adapter_error(kind: CanisterHttpErrorKind, message: &str) -> HttpsOutcallResult {
        HttpsOutcallResult {
            metrics: None,
            result: Some(https_outcall_result::Result::Error(CanisterHttpError {
                kind: kind.into(),
                message: message.to_string(),
            })),
        }
    }

    #[tokio::test]
    async fn returns_the_adapter_response() {
        let channel = serve_mock_adapter(SingleResponseAdapter::new(Ok(ok_response()))).await;
        let svc = service(Some(channel), Arc::new(NoProxies));

        let response = svc.oneshot(request()).await.unwrap().result.unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello".to_vec());
        assert_eq!(response.headers.len(), 1);
    }

    /// The request the adapter receives must carry the limits and the target that
    /// the query asked for; the adapter is the component that enforces them.
    #[tokio::test]
    async fn propagates_the_request_to_the_adapter() {
        let adapter = SingleResponseAdapter::new(Ok(ok_response()));
        let received = adapter.requests();
        let channel = serve_mock_adapter(adapter).await;
        let svc = service(
            Some(channel),
            Arc::new(FixedProxies(vec![
                "socks5h://[2001:db8::1]:1080".to_string(),
            ])),
        );

        let outcall = QueryOutcallRequest {
            http_method: CanisterHttpMethod::POST,
            headers: vec![CanisterHttpHeader {
                name: "X-Test".to_string(),
                value: "1".to_string(),
            }],
            body: Some(b"payload".to_vec()),
            max_response_bytes: NumBytes::from(4096),
            ..request()
        };
        svc.oneshot(outcall).await.unwrap().result.unwrap();

        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        let received = &received[0];
        assert_eq!(received.url, "https://example.com/path");
        assert_eq!(received.method, i32::from(HttpMethod::Post));
        assert_eq!(received.max_response_size_bytes, 4096);
        assert_eq!(received.body, b"payload".to_vec());
        assert_eq!(received.headers.len(), 1);
        assert_eq!(received.headers[0].name, "X-Test");
        assert_eq!(
            received.socks_proxy_addrs,
            vec!["socks5h://[2001:db8::1]:1080".to_string()]
        );
    }

    #[tokio::test]
    async fn maps_every_http_method() {
        for (method, expected) in [
            (CanisterHttpMethod::GET, HttpMethod::Get),
            (CanisterHttpMethod::HEAD, HttpMethod::Head),
            (CanisterHttpMethod::POST, HttpMethod::Post),
            (CanisterHttpMethod::PUT, HttpMethod::Put),
            (CanisterHttpMethod::DELETE, HttpMethod::Delete),
            (CanisterHttpMethod::PATCH, HttpMethod::Patch),
        ] {
            let adapter = SingleResponseAdapter::new(Ok(ok_response()));
            let received = adapter.requests();
            let channel = serve_mock_adapter(adapter).await;
            let svc = service(Some(channel), Arc::new(NoProxies));

            svc.oneshot(QueryOutcallRequest {
                http_method: method,
                ..request()
            })
            .await
            .unwrap()
            .result
            .unwrap();

            assert_eq!(
                received.lock().unwrap()[0].method,
                i32::from(expected),
                "method {method:?} was not mapped correctly"
            );
        }
    }

    /// A canister must see the same reject codes it would see for a replicated
    /// outcall, so that its error handling does not have to distinguish the two.
    #[tokio::test]
    async fn maps_adapter_errors_to_reject_codes() {
        for (kind, expected) in [
            (CanisterHttpErrorKind::InvalidInput, RejectCode::SysFatal),
            (CanisterHttpErrorKind::LimitExceeded, RejectCode::SysFatal),
            (CanisterHttpErrorKind::Unspecified, RejectCode::SysFatal),
            (CanisterHttpErrorKind::Connection, RejectCode::SysTransient),
            (CanisterHttpErrorKind::Internal, RejectCode::SysTransient),
        ] {
            let channel =
                serve_mock_adapter(SingleResponseAdapter::new(Ok(adapter_error(kind, "boom"))))
                    .await;
            let svc = service(Some(channel), Arc::new(NoProxies));

            let reject = svc.oneshot(request()).await.unwrap().result.unwrap_err();

            assert_eq!(reject.reject_code, expected, "{kind:?} mapped incorrectly");
            assert_eq!(reject.message, "boom");
        }
    }

    #[tokio::test]
    async fn maps_grpc_failures_to_reject_codes() {
        for (code, expected) in [
            (Code::Unavailable, RejectCode::SysTransient),
            (Code::InvalidArgument, RejectCode::SysFatal),
        ] {
            let channel = serve_mock_adapter(SingleResponseAdapter::new(Err((
                code,
                "grpc failed".to_string(),
            ))))
            .await;
            let svc = service(Some(channel), Arc::new(NoProxies));

            let reject = svc.oneshot(request()).await.unwrap().result.unwrap_err();

            assert_eq!(reject.reject_code, expected, "{code:?} mapped incorrectly");
        }
    }

    #[tokio::test]
    async fn empty_adapter_result_is_rejected() {
        let channel = serve_mock_adapter(SingleResponseAdapter::new(Ok(HttpsOutcallResult {
            metrics: None,
            result: None,
        })))
        .await;
        let svc = service(Some(channel), Arc::new(NoProxies));

        let reject = svc.oneshot(request()).await.unwrap().result.unwrap_err();

        assert_eq!(reject.reject_code, RejectCode::SysFatal);
        assert_eq!(reject.message, "Adapter returned empty result");
    }

    /// The deadline comes from the query's remaining walltime budget, so an
    /// outcall that outlives it must be abandoned rather than left to run.
    #[tokio::test]
    async fn abandons_the_outcall_when_its_deadline_elapses() {
        let channel = serve_mock_adapter(
            SingleResponseAdapter::new(Ok(ok_response())).with_delay(Duration::from_secs(30)),
        )
        .await;
        let svc = service(Some(channel), Arc::new(NoProxies));

        let reject = svc
            .oneshot(QueryOutcallRequest {
                max_response_time: Duration::from_millis(10),
                ..request()
            })
            .await
            .unwrap()
            .result
            .unwrap_err();

        assert_eq!(reject.reject_code, RejectCode::SysTransient);
        assert_eq!(reject.message, "Deadline Exceeded");
    }

    #[tokio::test]
    async fn reports_a_missing_adapter() {
        let svc = service(None, Arc::new(NoProxies));

        let reject = svc.oneshot(request()).await.unwrap().result.unwrap_err();

        assert_eq!(reject.reject_code, RejectCode::SysFatal);
        assert_eq!(reject.message, "HTTPS outcalls adapter is not available");
    }

    /// A response the adapter accepted may still be malformed; the same header
    /// and body validation as the replicated path applies.
    #[tokio::test]
    async fn rejects_a_response_with_too_many_headers() {
        let headers = (0..65)
            .map(|i| HttpHeader {
                name: format!("h{i}"),
                value: "v".to_string(),
            })
            .collect();
        let channel = serve_mock_adapter(SingleResponseAdapter::new(Ok(
            create_result_from_response(HttpsOutcallResponse {
                status: 200,
                headers,
                content: vec![],
            }),
        )))
        .await;
        let svc = service(Some(channel), Arc::new(NoProxies));

        let reject = svc.oneshot(request()).await.unwrap().result.unwrap_err();

        assert_eq!(reject.reject_code, RejectCode::SysFatal);
        assert!(
            reject.message.contains("exceeds"),
            "unexpected message: {}",
            reject.message
        );
    }
}
