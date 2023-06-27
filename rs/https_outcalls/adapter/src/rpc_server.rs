use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_BODY_RECEIVE_TIMEOUT, LABEL_CONNECT,
    LABEL_DOWNLOAD, LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_HTTP_SCHEME,
    LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS, LABEL_UPLOAD, LABEL_URL_PARSE,
};
use byte_unit::Byte;
use core::convert::TryFrom;
use http::{uri::Scheme, Uri};
use hyper::{
    client::HttpConnector,
    header::{HeaderMap, ToStrError},
    Body, Client, Method,
};
use hyper_socks2::SocksConnector;
use hyper_tls::HttpsConnector;
use ic_async_utils::{receive_body_without_timeout, BodyReceiveError};
use ic_https_outcalls_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::{collections::HashMap, fmt, net::SocketAddr};
use tonic::{Request, Response, Status};

/// Hyper only supports a maximum of 32768 headers https://docs.rs/hyper/0.14.23/hyper/header/index.html#limitations-1
/// and it panics if we try to allocate more headers. And since hyper sometimes grows the map by doubling the entries
/// we choose a lower value to be safe.
const HEADERS_LIMIT: usize = 1_024;
/// Hyper also limits the size of the HeaderName to 32768. https://docs.rs/hyper/0.14.23/hyper/header/index.html#limitations.
const HEADER_NAME_VALUE_LIMIT: usize = 8_192;

/// implements RPC
pub struct CanisterHttp {
    client: Client<HttpsConnector<HttpConnector>>,
    socks_client: Client<HttpsConnector<SocksConnector<HttpConnector>>>,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
}

impl CanisterHttp {
    pub fn new(
        client: Client<HttpsConnector<HttpConnector>>,
        socks_client: Client<HttpsConnector<SocksConnector<HttpConnector>>>,
        logger: ReplicaLogger,
        metrics: &MetricsRegistry,
    ) -> Self {
        Self {
            client,
            socks_client,
            logger,
            metrics: AdapterMetrics::new(metrics),
        }
    }
}

#[tonic::async_trait]
impl CanisterHttpService for CanisterHttp {
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
        let headers = validate_headers(req.headers).map_err(|err| {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
            err
        })?;
        let mut request_size = req.body.len();
        request_size += headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>();

        // If we are allowed to use socks and condition described in `should_use_socks_proxy` hold,
        // we do the requests through the socks proxy. If not we use the default IPv6 route.
        let http_resp = if req.socks_proxy_allowed {
            // Http request does not implement clone. So we have to manually contruct a clone.
            let req_body_clone = req.body.clone();
            let mut http_req = hyper::Request::new(Body::from(req.body));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();

            if !should_use_socks_proxy(&uri).await {
                let mut http_req_clone = hyper::Request::new(Body::from(req_body_clone));
                *http_req_clone.headers_mut() = http_req.headers().clone();
                *http_req_clone.method_mut() = http_req.method().clone();
                *http_req_clone.uri_mut() = http_req.uri().clone();
                // If we fail to connect through IPv6 we retry with socks.
                match self.client.request(http_req).await {
                    Err(direct_err) if direct_err.is_connect() => {
                        self.metrics.requests_socks.inc();
                        self.socks_client
                            .request(http_req_clone)
                            .await
                            .map_err(|socks_err| {
                                RequestError::DirectAndSocks((direct_err, socks_err))
                            })
                    }
                    resp => resp.map_err(|err| RequestError::Direct(err)),
                }
            } else {
                self.metrics.requests_socks.inc();
                self.socks_client
                    .request(http_req)
                    .await
                    .map_err(|err| RequestError::Socks(err))
            }
        } else {
            let mut http_req = hyper::Request::new(Body::from(req.body));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            self.client
                .request(http_req)
                .await
                .map_err(|err| RequestError::Direct(err))
        }
        .map_err(|err| {
            debug!(self.logger, "Failed to connect: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_CONNECT])
                .inc();
            Status::new(
                tonic::Code::Unavailable,
                format!(
                    "Connecting to {:.50} failed: {}",
                    uri.host().unwrap_or(""),
                    err,
                ),
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

enum RequestError {
    Direct(hyper::Error),
    Socks(hyper::Error),
    DirectAndSocks((hyper::Error, hyper::Error)),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(direct_err) => {
                write!(f, "Request failed: {}", direct_err)
            }
            Self::Socks(direct_err) => {
                write!(f, "Request through socks proxy failed: {}", direct_err)
            }
            Self::DirectAndSocks((direct_err, socks_err)) => {
                write!(
                    f,
                    "Request failed to connect: {} fallback to socks also failed: {}",
                    direct_err, socks_err
                )
            }
        }
    }
}

/// Decides if socks proxy should be used to connect to given Uri. In the following cases we do NOT use the proxy:
/// 1. If we can't get the necessary infromation from the url to do the dns lookup.
/// 2. If the dns resolution fails.
/// 3. If we connect to localhost.
/// 4. If the dns resoultion returns at least a single IPV6.
async fn should_use_socks_proxy(url: &Uri) -> bool {
    let host = match url.host() {
        Some(host) => host,
        None => return false,
    };
    // We use a default port in case no port is specfied becuase `lookup_host` requires us to specify a port.
    let port = url.port_u16().unwrap_or(443);

    let mut lookup = match tokio::net::lookup_host((host, port)).await {
        Ok(lookup) => lookup,
        Err(_) => return false,
    };

    // Check if localhost address.
    if lookup.all(|addr| addr.ip().is_loopback()) {
        return false;
    }

    if lookup.any(|addr| matches!(addr, SocketAddr::V6(_))) {
        return false;
    }
    true
}

fn validate_headers(raw_headers: Vec<HttpHeader>) -> Result<HeaderMap, Status> {
    // Check we are within limit for number of headers.
    if raw_headers.len() > HEADERS_LIMIT {
        return Err(Status::new(
            tonic::Code::InvalidArgument,
            format!("Too many headers. Maximum allowed: {}", HEADERS_LIMIT),
        ));
    }
    // Check that header name and values are within limit.
    if raw_headers
        .iter()
        .any(|h| h.name.len() > HEADER_NAME_VALUE_LIMIT || h.value.len() > HEADER_NAME_VALUE_LIMIT)
    {
        return Err(Status::new(
            tonic::Code::InvalidArgument,
            format!(
                "Header name or value exceeds size limit of {}",
                HEADER_NAME_VALUE_LIMIT
            ),
        ));
    }

    let headers: HeaderMap = HeaderMap::try_from(
        &raw_headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect::<HashMap<String, String>>(),
    )
    .map_err(|err| {
        Status::new(
            tonic::Code::InvalidArgument,
            format!("Failed to parse headers {err}",),
        )
    })?;

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    #[test]
    // Verify that hyper does not panic within header limits.
    fn test_max_headers() {
        let mut header_vec = Vec::new();
        for _ in 0..HEADERS_LIMIT {
            let name: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(HEADER_NAME_VALUE_LIMIT)
                .map(char::from)
                .collect();
            let value: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(HEADER_NAME_VALUE_LIMIT)
                .map(char::from)
                .collect();

            header_vec.push(HttpHeader { name, value });
        }
        validate_headers(header_vec).unwrap();
    }

    #[test]
    // Verify that hyper does not panic within header limits.
    fn test_too_many_headers() {
        let mut header_vec = Vec::new();
        for i in 0..(HEADERS_LIMIT + 1) {
            header_vec.push(HttpHeader {
                name: i.to_string(),
                value: "hi".to_string(),
            });
        }
        validate_headers(header_vec).unwrap_err();
    }

    #[test]
    // Verify that hyper does not panic within header limits.
    fn test_too_big_header() {
        let mut header_vec = Vec::new();
        for i in 0..10 {
            header_vec.push(HttpHeader {
                name: i.to_string().repeat(HEADER_NAME_VALUE_LIMIT + 1),
                value: "hi".to_string(),
            });
        }
        validate_headers(header_vec).unwrap_err();
    }
}
