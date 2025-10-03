use crate::Config;
use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_CONNECT, LABEL_DOWNLOAD,
    LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS,
    LABEL_UPLOAD, LABEL_URL_PARSE,
};
use core::convert::TryFrom;
use http::{header::USER_AGENT, HeaderName, HeaderValue, Method, Uri};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, ToStrError};
use ic_https_outcalls_service::{
    HttpHeader, HttpMethod, HttpsOutcallRequest, HttpsOutcallResponse,
    https_outcalls_service_server::HttpsOutcallsService,
};
use ic_logger::{debug, info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use rand::{seq::SliceRandom, thread_rng};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};

/// Hyper only supports a maximum of 32768 headers https://docs.rs/hyper/1.5.0/hyper/header/index.html
/// and it panics if we try to allocate more headers. And since hyper sometimes grows the map by doubling the entries
/// we choose a lower value to be safe.
const HEADERS_LIMIT: usize = 1_024;
/// Hyper also limits the size of the HeaderName to 32768. https://docs.rs/hyper/1.5.0/hyper/header/index.html.
const HEADER_NAME_VALUE_LIMIT: usize = 8_192;

/// By default most higher-level http libs like `curl` set some `User-Agent` so we do the same here to avoid getting rejected due to strict server requirements.
const USER_AGENT_ADAPTER: &str = "ic/1.0";

/// We should support at least 48 KB in headers and values according to the IC spec:
/// "the total number of bytes representing the header names and values must not exceed 48KiB".
const MAX_HEADER_LIST_SIZE: u32 = 52 * 1024;

/// The maximum number of times we will try to connect to a SOCKS proxy.
const MAX_SOCKS_PROXY_TRIES: usize = 2;

// REFACTOR: The client cache now stores reqwest::Client instances.
type Cache = BTreeMap<String, reqwest::Client>;

pub struct CanisterHttp {
    // REFACTOR: The primary client is now a reqwest::Client.
    client: reqwest::Client,
    cache: Arc<RwLock<Cache>>,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
    http_connect_timeout_secs: u64,
}

impl CanisterHttp {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        // REFACTOR: Replaced the complex hyper client setup with a simple reqwest::ClientBuilder.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(config.http_connect_timeout_secs))
            .user_agent(USER_AGENT_ADAPTER)
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            logger,
            metrics: AdapterMetrics::new(metrics),
            http_connect_timeout_secs: config.http_connect_timeout_secs,
        }
    }

    // REFACTOR: This function now creates and returns a reqwest::Client configured with a SOCKS proxy.
    fn create_socks_proxy_client(&self, proxy_addr: &str) -> Result<reqwest::Client, String> {
        let proxy = reqwest::Proxy::all(proxy_addr)
            .map_err(|err| format!("Failed to create proxy object: {err}"))?;

        reqwest::Client::builder()
            .proxy(proxy)
            .connect_timeout(Duration::from_secs(self.http_connect_timeout_secs))
            .user_agent(USER_AGENT_ADAPTER)
            .build()
            .map_err(|err| format!("Failed to build SOCKS reqwest client: {err}"))
    }

    // REFACTOR: The caching logic is the same, but it now returns a reqwest::Client.
    fn get_socks_client(&self, socks_proxy_addr: &str) -> Result<reqwest::Client, String> {
        let cache_guard = self.cache.upgradable_read();

        if let Some(client) = cache_guard.get(socks_proxy_addr) {
            Ok(client.clone())
        } else {
            let mut cache_guard = RwLockUpgradableReadGuard::upgrade(cache_guard);
            self.metrics.socks_cache_misses.inc();
            let client = self.create_socks_proxy_client(socks_proxy_addr)?;
            cache_guard.insert(socks_proxy_addr.to_string(), client.clone());
            self.metrics.socks_cache_size.set(cache_guard.len() as i64);
            Ok(client)
        }
    }

    fn classify_uri_host(uri: &Uri) -> &str {
        let Some(host) = uri.host() else {
            return "empty";
        };

        if host.parse::<Ipv4Addr>().is_ok() {
            return "v4";
        }

        if host.starts_with('[') && host.ends_with(']') {
            let inside = &host[1..host.len() - 1];
            if inside.parse::<Ipv6Addr>().is_ok() {
                return "v6";
            }
        }

        "domain_name"
    }

    // REFACTOR: This function now takes a reqwest::Request and returns a reqwest::Response.
    async fn do_https_outcall_socks_proxy(
        &self,
        socks_proxy_addrs: Vec<String>,
        request: reqwest::Request,
        // FIX: Pass the original URI to classify it correctly.
        original_uri: &Uri,
    ) -> Result<reqwest::Response, String> {
        let mut socks_proxy_addrs = socks_proxy_addrs.to_owned();
        socks_proxy_addrs.shuffle(&mut thread_rng());

        let mut last_error: Option<reqwest::Error> = None;
        let mut tries = 0;

        for socks_proxy_addr in &socks_proxy_addrs {
            tries += 1;
            if tries > MAX_SOCKS_PROXY_TRIES {
                break;
            }

            let socks_client = match self.get_socks_client(socks_proxy_addr) {
                Ok(client) => client,
                Err(e) => {
                    debug!(self.logger, "Failed to get SOCKS client: {}", e);
                    continue;
                }
            };
            
            // FIX: Use the passed original_uri to classify the host.
            let url_format = Self::classify_uri_host(original_uri);
            
            // reqwest::Request is not easily clonable if it contains a streaming body.
            // For this logic, we rebuild the request for each attempt.
            let request_clone = request.try_clone().ok_or_else(|| "Failed to clone request for retry".to_string())?;

            match socks_client.execute(request_clone).await {
                Ok(resp) => {
                    self.metrics
                        .socks_connection_attempts
                        .with_label_values(&[
                            &tries.to_string(),
                            "success",
                            socks_proxy_addr,
                            url_format,
                        ])
                        .inc();
                    return Ok(resp);
                }
                Err(socks_err) => {
                    self.metrics
                        .socks_connection_attempts
                        .with_label_values(&[
                            &tries.to_string(),
                            "failure",
                            socks_proxy_addr,
                            url_format,
                        ])
                        .inc();
                    debug!(
                        self.logger,
                        "Failed to connect through SOCKS with address {}: {}",
                        socks_proxy_addr,
                        socks_err
                    );
                    last_error = Some(socks_err);
                }
            }
        }

        if let Some(last_error) = last_error {
            Err(last_error.to_string())
        } else {
            Err("No SOCKS proxy addresses provided or all failed".to_string())
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

        // Parsing and validation logic remains largely the same.
        let uri = req.url.parse::<Uri>().map_err(|err| {
            debug!(self.logger, "Failed to parse URL: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_URL_PARSE])
                .inc();
            Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse URL: {err}"),
            )
        })?;

        // FIX: Correctly handle the two-step process of parsing and then matching the enum.
        let http_method_enum = HttpMethod::try_from(req.method).map_err(|_| {
            Status::new(
                tonic::Code::InvalidArgument,
                "Failed to parse HTTP method enum: unknown value",
            )
        })?;

        let method = match http_method_enum {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Head => Method::HEAD,
            _ => {
                self.metrics
                    .request_errors
                    .with_label_values(&[LABEL_HTTP_METHOD])
                    .inc();
                return Err(Status::new(
                    tonic::Code::InvalidArgument,
                    format!("Unsupported HTTP method {:?}", http_method_enum),
                ));
            }
        };

        let mut headers = validate_headers(req.headers).inspect_err(|_| {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
        })?;
        add_fallback_user_agent_header(&mut headers);

        let request_size = req.body.len()
            + headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                .sum::<usize>();

        // REFACTOR: Build a reqwest::Request instead of a hyper::Request.
        // reqwest can consume the http:: types directly.
        let http_req_builder = http::Request::builder()
            .method(method)
            .uri(uri.clone())
            .body(req.body)
            .expect("Failed to build http::Request");

        let (mut parts, body) = http_req_builder.into_parts();
        parts.headers = headers;
        let http_req = http::Request::from_parts(parts, body);
        
        // This conversion is necessary to pass the request to reqwest's `execute` method.
        let reqwest_req = reqwest::Request::try_from(http_req).map_err(|err| {
            Status::new(
                tonic::Code::Internal,
                format!("Failed to convert to reqwest::Request: {}", err),
            )
        })?;

        info!(self.logger, "Sending request to {}", uri);

        // REFACTOR: The execution flow now uses reqwest::Client::execute.
        // The response type is now `reqwest::Response`.
        let http_resp = match self.client.execute(reqwest_req.try_clone().unwrap()).await {
            Ok(resp) => {
                info!(self.logger, "Direct connection successful.");
                Ok(resp)
            }
            Err(direct_err) => {
                info!(self.logger, "Direct connection failed: {direct_err}, trying SOCKS proxy...");
                self.metrics.requests_socks.inc();
                // FIX: Pass the original URI to the SOCKS proxy function.
                self.do_https_outcall_socks_proxy(req.socks_proxy_addrs, reqwest_req, &uri)
                    .await
                    .map_err(|socks_err| {
                        format!("Direct connection failed: {direct_err}, and SOCKS proxy failed: {socks_err}")
                    })
            }
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

        // REFACTOR: Response header parsing is similar, using reqwest::Response.
        let mut headers_size_bytes = 0;
        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                let name = k.to_string();
                headers_size_bytes += name.len() + v.as_bytes().len();
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
                    format!("Failed to parse headers: {err}"),
                )
            })?;

        let response_size_limit = req.max_response_size_bytes.saturating_sub(headers_size_bytes as u64);

        // REFACTOR: Body fetching now uses `reqwest::Response::bytes()`.
        // We check the size limit after receiving the body.
        let body_bytes = http_resp.bytes().await.map_err(|err| {
            debug!(self.logger, "Failed to fetch body: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                .inc();
            Status::new(
                tonic::Code::Unavailable,
                format!("Failed to download response body: {err}"),
            )
        })?;

        if body_bytes.len() as u64 > response_size_limit {
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

#[allow(clippy::result_large_err)]
fn validate_headers(raw_headers: Vec<HttpHeader>) -> Result<HeaderMap, Status> {
    // Check we are within limit for number of headers.
    if raw_headers.len() > HEADERS_LIMIT {
        return Err(Status::new(
            tonic::Code::InvalidArgument,
            format!("Too many headers. Maximum allowed: {HEADERS_LIMIT}"),
        ));
    }
    // Check that header name and values are within limit.
    if raw_headers
        .iter()
        .any(|h| h.name.len() > HEADER_NAME_VALUE_LIMIT || h.value.len() > HEADER_NAME_VALUE_LIMIT)
    {
        return Err(Status::new(
            tonic::Code::InvalidArgument,
            format!("Header name or value exceeds size limit of {HEADER_NAME_VALUE_LIMIT}"),
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

