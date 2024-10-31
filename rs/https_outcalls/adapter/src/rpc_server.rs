use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_CONNECT, LABEL_DOWNLOAD,
    LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS,
    LABEL_UPLOAD, LABEL_URL_PARSE,
};
use crate::Config;
use bytes::BytesMut;
use core::convert::TryFrom;
use http::{header::USER_AGENT, HeaderName, HeaderValue};
use ic_https_outcalls_service::{
    https_outcalls_service_server::HttpsOutcallsService, HttpHeader, HttpMethod,
    HttpsOutcallRequest, HttpsOutcallResponse,
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use reqwest::{
    header::{HeaderMap, ToStrError},
    Client, Method,
};
use std::str::FromStr;
use std::time::Duration;
use tonic::{Request, Response, Status};

/// Reqwest only supports a maximum of 32768 headers https://docs.rs/reqwest/latest/reqwest/header/index.html#limitations-1
/// and it panics if we try to allocate more headers. And since reqwest may sometimes grow the map by doubling the entries
/// we choose a lower value to be safe.
const HEADERS_LIMIT: usize = 1_024;
/// Reqwest also limits the size of the HeaderName to 32768. https://docs.rs/reqwest/latest/reqwest/header/index.html#limitations.
const HEADER_NAME_VALUE_LIMIT: usize = 8_192;

/// By default most higher-level http libs like `curl` set some `User-Agent` so we do the same here to avoid getting rejected due to strict server requirements.
const USER_AGENT_ADAPTER: &str = "ic/1.0";

/// We should support at least 48 KB in headers and values according to the IC spec:
/// "the total number of bytes representing the header names and values must not exceed 48KiB".
const MAX_HEADER_LIST_SIZE: u32 = 52 * 1024;

/// Implements HttpsOutcallsService
// TODO: consider making this private
pub struct CanisterHttp {
    socks_client: Client,
    client: Client,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
}

impl CanisterHttp {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(config.http_connect_timeout_secs))
            //.http2_max_header_list_size(MAX_HEADER_LIST_SIZE)
            .build()
            .expect("Failed to create reqwest client");

        let mut socks_client_builder = Client::builder()
            .connect_timeout(Duration::from_secs(config.http_connect_timeout_secs))
            //.http2_max_header_list_size(MAX_HEADER_LIST_SIZE);

        // This uses a DNS resolver and results in an error if the proxy is not a valid URL.
        // We don't want to panic here during test.
        let maybe_proxy = reqwest::Proxy::all(config.socks_proxy.clone());

        match maybe_proxy {
            Ok(proxy) => {
                socks_client_builder = socks_client_builder.proxy(proxy);
            }
            Err(e) => {
                debug!(logger, "Failed to create socks proxy: {}", e);
            }
        }

        let socks_client = socks_client_builder
            .build()
            .expect("Failed to create socks reqwest client");

        Self {
            client,
            socks_client,
            logger,
            metrics: AdapterMetrics::new(metrics),
        }
    }
}

#[tonic::async_trait]
impl HttpsOutcallsService for CanisterHttp {
    async fn https_outcall(
        &self,
        request: Request<HttpsOutcallRequest>,
    ) -> Result<Response<HttpsOutcallResponse>, Status> {
        self.metrics.requests.inc();

        let req = request.into_inner();

        let url = reqwest::Url::parse(&req.url).map_err(|err| {
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
        #[cfg(not(feature = "http"))]
        if url.scheme() != "https" {
            use crate::metrics::LABEL_HTTP_SCHEME;
            debug!(
                self.logger,
                "Got request with no or http scheme specified. {}", url
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
        let mut headers = validate_headers(req.headers).inspect_err(|_| {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
        })?;

        // Add user-agent header if not present.
        add_fallback_user_agent_header(&mut headers);

        let mut request_size = req.body.len();
        request_size += headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>();

        //TODO(mihailjianu1): figure out if cloning is necessary / how expensive
        let resp = self
            .client
            .request(method.clone(), url)
            .headers(headers.clone())
            .body(req.body.clone())
            .send()
            .await;
        let mut http_resp = match resp {
            Ok(resp) => Ok(resp),
            Err(direct_err) => {
                if req.socks_proxy_allowed {
                    self.socks_client
                        .request(method, req.url.clone())
                        .headers(headers)
                        .body(req.body)
                        .send()
                        .await
                        .map_err(|e| {
                            self.metrics.requests_socks.inc();
                            format!("Request failed direct connect {direct_err} and connect through socks {e}")
                        })
                } else {
                    Err(format!("Failed to directly connect: {direct_err}"))
                }
            }
        }.map_err(|err| {
            debug!(self.logger, "Failed to connect: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_CONNECT])
                .inc();
            Status::new(
                tonic::Code::Unavailable,
                format!(
                    "Connecting to {:.50} failed: {}",
                    req.url,
                    err,
                ),
            )
        })?;

        self.metrics
            .network_traffic
            .with_label_values(&[LABEL_UPLOAD])
            .inc_by(request_size as u64);

        let status = http_resp.status().as_u16() as u32;

        let mut headers_size_bytes = 0;
        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                let name = k.to_string();
                // Use the header value in bytes for the size.
                // It is possible that bytes.len() > str.len().
                headers_size_bytes += name.len() + v.len();
                let value = v.to_str().unwrap().to_string();
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

        if headers_size_bytes > req.max_response_size_bytes as usize {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_HEADER_RECEIVE_SIZE])
                .inc();
            return Err(Status::new(
                tonic::Code::OutOfRange,
                format!(
                    "Header size exceeds specified response size limit {}",
                    req.max_response_size_bytes
                ),
            ));
        }

        // Important: we should not read the whole body at once, because it might be too big.
        // Once we've confirmed that the body is not too big, we can load it using bytes().
        // Initialize a mutable BytesMut buffer
        let mut buffer = BytesMut::new();
        let mut total_bytes = 0;
        loop {
            match http_resp.chunk().await {
                Ok(Some(chunk)) => {
                    total_bytes += chunk.len();
                    if total_bytes + headers_size_bytes > req.max_response_size_bytes as usize {
                        self.metrics
                            .request_errors
                            .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                            .inc();
                        return Err(Status::new(
                            tonic::Code::OutOfRange,
                            format!(
                                "Http body exceeds size limit of {} bytes.",
                                req.max_response_size_bytes
                            ),
                        ));
                    }
                    buffer.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    debug!(self.logger, "Failed to fetch body: {}", err);
                    self.metrics
                        .request_errors
                        .with_label_values(&[LABEL_DOWNLOAD])
                        .inc();
                    return Err(Status::new(
                        tonic::Code::Unavailable,
                        format!("Failed to fetch body: {}", err),
                    ));
                }
            }
        }

        let body_bytes = buffer.freeze();

        self.metrics
            .network_traffic
            .with_label_values(&[LABEL_DOWNLOAD])
            .inc_by(body_bytes.len() as u64 + headers_size_bytes as u64);
        Ok(Response::new(HttpsOutcallResponse {
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
    // Verify that reqwest does not panic within header limits.
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
    // Verify that reqwest does not panic within header limits.
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
    // Verify that reqwest does not panic within header limits.
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
