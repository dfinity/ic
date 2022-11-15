use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_BODY_RECEIVE_TIMEOUT, LABEL_CONNECT,
    LABEL_DOWNLOAD, LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_HTTP_SCHEME,
    LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS, LABEL_UPLOAD, LABEL_URL_PARSE,
};
use byte_unit::Byte;
use core::convert::TryFrom;
use http::{uri::Scheme, Uri};
use hyper::{
    client::connect::Connect,
    header::{HeaderMap, ToStrError},
    Body, Client, Method,
};
use ic_async_utils::{receive_body_without_timeout, BodyReceiveError};
use ic_canister_http_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use tonic::{Request, Response, Status};

/// implements RPC
pub struct CanisterHttp<C: Clone + Connect + Send + Sync + 'static> {
    client: Client<C>,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
}

impl<C: Clone + Connect + Send + Sync + 'static> CanisterHttp<C> {
    pub fn new(client: Client<C>, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        Self {
            client,
            logger,
            metrics: AdapterMetrics::new(metrics),
        }
    }
}

#[tonic::async_trait]
impl<C: Clone + Connect + Send + Sync + 'static> CanisterHttpService for CanisterHttp<C> {
    async fn canister_http_send(
        &self,
        request: Request<CanisterHttpSendRequest>,
    ) -> Result<Response<CanisterHttpSendResponse>, Status> {
        self.metrics.requests.inc();

        let req = request.into_inner();

        let uri = req.url.parse::<Uri>().map_err(|err| {
            debug!(self.logger, "Failed to parse URL: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_URL_PARSE])
                .inc();
            Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse URL: {}", err),
            )
        })?;

        if uri.scheme() != Some(&Scheme::HTTPS) {
            debug!(
                self.logger,
                "Got request with no or http scheme specified. {}", uri
            );
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_HTTP_SCHEME])
                .inc();
            return Err(Status::new(
                tonic::Code::InvalidArgument,
                "Url need to specify https scheme",
            ));
        }

        let method = HttpMethod::from_i32(req.method)
            .ok_or_else(|| {
                Status::new(
                    tonic::Code::InvalidArgument,
                    "Failed to get HTTP method".to_string(),
                )
            })
            .and_then(|method| match method {
                HttpMethod::Get => Ok(Method::GET),
                HttpMethod::Post => Ok(Method::POST),
                HttpMethod::Head => Ok(Method::HEAD),
                _ => {
                    self.metrics
                        .request_errors
                        .with_label_values(&[LABEL_HTTP_METHOD])
                        .inc();
                    Err(Status::new(
                        tonic::Code::InvalidArgument,
                        format!("Unsupported HTTP method {:?}", method),
                    ))
                }
            })?;

        // Build Http Request.
        let mut request_size = req.body.len();
        let mut http_req = hyper::Request::new(Body::from(req.body));
        let headers: HeaderMap = HeaderMap::try_from(
            &req.headers
                .into_iter()
                .map(|h| {
                    request_size += h.name.len() + h.value.len();
                    (h.name, h.value)
                })
                .collect(),
        )
        .map_err(|err| {
            debug!(self.logger, "Failed to parse headers: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
            Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse headers: {}", err),
            )
        })?;
        *http_req.headers_mut() = headers;
        *http_req.method_mut() = method;
        *http_req.uri_mut() = uri;

        let http_resp = self.client.request(http_req).await.map_err(|err| {
            debug!(self.logger, "Failed to connect: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_CONNECT])
                .inc();
            Status::new(
                tonic::Code::Unavailable,
                format!("Failed to connect: {}", err),
            )
        })?;
        self.metrics
            .network_traffic
            .with_label_values(&[LABEL_UPLOAD])
            .inc_by(request_size as u64);

        let status = http_resp.status().as_u16() as u32;

        // Parse received headers.
        let mut headers_size_bytes = 0;
        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                let name = k.to_string();
                // Use the header value in bytes for the size.
                // It is possible that bytes.len() > str.len().
                headers_size_bytes += name.len() + v.len();
                let value = v.to_str()?.to_string();
                Ok(HttpHeader { name, value })
            })
            .collect::<Result<Vec<_>, ToStrError>>()
            .map_err(|err| {
                debug!(self.logger, "Failed to parse headers: {}", err);
                self.metrics
                    .request_errors
                    .with_label_values(&[LABEL_RESPONSE_HEADERS])
                    .inc();
                Status::new(
                    tonic::Code::Unavailable,
                    format!("Failed to parse headers: {}", err),
                )
            })?;

        // We don't need a timeout here because there is a global timeout on the entire request.
        let body_bytes = receive_body_without_timeout(
            http_resp.into_body(),
            // Account for size of headers.
            Byte::from(
                req.max_response_size_bytes
                    .checked_sub(headers_size_bytes as u64)
                    .ok_or_else(|| {
                        self.metrics
                            .request_errors
                            .with_label_values(&[LABEL_HEADER_RECEIVE_SIZE])
                            .inc();
                        Status::new(
                            tonic::Code::OutOfRange,
                            format!(
                                "Header size exceeds specified response size limit {}",
                                req.max_response_size_bytes
                            ),
                        )
                    })?,
            ),
        )
        .await
        .map_err(|err| {
            debug!(self.logger, "Failed to fetch body: {}", err);
            match err {
                // SysTransient error
                BodyReceiveError::Timeout(e) | BodyReceiveError::Unavailable(e) => {
                    self.metrics
                        .request_errors
                        .with_label_values(&[LABEL_BODY_RECEIVE_TIMEOUT])
                        .inc();
                    Status::new(
                        tonic::Code::Unavailable,
                        format!("Failed to fetch body: {}", e),
                    )
                }
                // SysFatal error
                BodyReceiveError::TooLarge(e) => {
                    self.metrics
                        .request_errors
                        .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                        .inc();
                    Status::new(tonic::Code::OutOfRange, e)
                }
            }
        })?;

        self.metrics
            .network_traffic
            .with_label_values(&[LABEL_DOWNLOAD])
            .inc_by(body_bytes.len() as u64 + headers_size_bytes as u64);
        Ok(Response::new(CanisterHttpSendResponse {
            status,
            headers,
            content: body_bytes.to_vec(),
        }))
    }
}
