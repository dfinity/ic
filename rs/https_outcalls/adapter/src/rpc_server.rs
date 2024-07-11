use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_BODY_RECEIVE_TIMEOUT, LABEL_CONNECT,
    LABEL_DOWNLOAD, LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_HTTP_SCHEME,
    LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS, LABEL_UPLOAD, LABEL_URL_PARSE,
};
use byte_unit::Byte;
use core::convert::TryFrom;
use http::{header::USER_AGENT, uri::Scheme, HeaderName, HeaderValue, Uri};
use hyper::{
    client::HttpConnector,
    header::{HeaderMap, ToStrError},
    Body, Client, Method,
};
use hyper_rustls::HttpsConnector;
use hyper_socks2::SocksConnector;
use ic_async_utils::{receive_body_without_timeout, BodyReceiveError};
use ic_https_outcalls_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::str::FromStr;
use tonic::{Request, Response, Status};

/// Hyper only supports a maximum of 32768 headers https://docs.rs/hyper/0.14.23/hyper/header/index.html#limitations-1
/// and it panics if we try to allocate more headers. And since hyper sometimes grows the map by doubling the entries
/// we choose a lower value to be safe.
const HEADERS_LIMIT: usize = 1_024;
/// Hyper also limits the size of the HeaderName to 32768. https://docs.rs/hyper/0.14.23/hyper/header/index.html#limitations.
const HEADER_NAME_VALUE_LIMIT: usize = 8_192;

/// By default most higher-level http libs like `curl` set some `User-Agent` so we do the same here to avoid getting rejected due to strict server requirements.
const USER_AGENT_ADAPTER: &str = "ic/1.0";

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

        let method = HttpMethod::try_from(req.method)
            .map_err(|_| {
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
        let mut headers = validate_headers(req.headers).map_err(|err| {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
            err
        })?;

        // Add user-agent header if not present.
        add_fallback_user_agent_header(&mut headers);

        let mut request_size = req.body.len();
        request_size += headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>();

        // If we are allowed to use socks and condition described in `should_use_socks_proxy` hold,
        // we do the requests through the socks proxy. If not we use the default IPv6 route.
        let http_resp = if req.socks_proxy_allowed {
            // Http request does not implement clone. So we have to manually construct a clone.
            let req_body_clone = req.body.clone();
            let mut http_req = hyper::Request::new(Body::from(req.body));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            let mut http_req_clone = hyper::Request::new(Body::from(req_body_clone));
            *http_req_clone.headers_mut() = http_req.headers().clone();
            *http_req_clone.method_mut() = http_req.method().clone();
            *http_req_clone.uri_mut() = http_req.uri().clone();

            match self.client.request(http_req).await {
                // If we fail we try with the socks proxy. For destinations that are ipv4 only this should
                // fail fast because our interface does not have an ipv4 assigned.
                Err(direct_err) => {
                    self.metrics.requests_socks.inc();
                    self.socks_client.request(http_req_clone).await.map_err(|e| {
                        format!("Request failed direct connect {direct_err} and connect through socks {e}")
                    })
                }
                Ok(resp)=> Ok(resp),
            }
        } else {
            let mut http_req = hyper::Request::new(Body::from(req.body));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            self.client.request(http_req).await.map_err(|e| format!("Failed to directly connect: {e}"))
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

    // Parse header name and values
    let mut parsed_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    for raw_h in raw_headers {
        parsed_headers.push((
            HeaderName::from_str(&raw_h.name).map_err(|err| {
                Status::new(
                    tonic::Code::InvalidArgument,
                    format!("Failed to parse header name {err}",),
                )
            })?,
            HeaderValue::from_str(&raw_h.value).map_err(|err| {
                Status::new(
                    tonic::Code::InvalidArgument,
                    format!("Failed to parse header value {err}",),
                )
            })?,
        ));
    }

    let headers: HeaderMap = HeaderMap::from_iter(parsed_headers);

    Ok(headers)
}

/// Adds a fallback user agent header if not already present in headermap
fn add_fallback_user_agent_header(header_map: &mut HeaderMap) {
    if !header_map
        .iter()
        .map(|h| h.0.as_str().to_lowercase())
        .any(|h| h == USER_AGENT.as_str().to_lowercase())
    {
        header_map.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_ADAPTER));
    }
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

    #[test]
    // Verify that multiple headers with same header name are all inserted under same header name.
    fn test_same_header_append() {
        let header_vec = vec![
            HttpHeader {
                name: "TTT".to_string(),
                value: "a".to_string(),
            },
            HttpHeader {
                name: "ttt".to_string(),
                value: "b".to_string(),
            },
            HttpHeader {
                name: "ttt".to_string(),
                value: "c".to_string(),
            },
        ];
        let headers = validate_headers(header_vec).unwrap();
        assert_eq!(headers.get_all("ttt").iter().count(), 3);
    }

    #[test]
    // Verify that both upper and lower case header names/values are accepted.
    fn test_upper_case_headers_allowed() {
        let header_vec = vec![
            HttpHeader {
                name: "TTT".to_string(),
                value: "aaaa".to_string(),
            },
            HttpHeader {
                name: "rr".to_string(),
                value: "BB".to_string(),
            },
            HttpHeader {
                name: "EEE".to_string(),
                value: "CCC".to_string(),
            },
        ];
        let headers = validate_headers(header_vec).unwrap();
        assert_eq!(headers.len(), 3);
    }
}
