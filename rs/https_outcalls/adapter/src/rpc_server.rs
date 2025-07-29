use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_CONNECT, LABEL_DOWNLOAD,
    LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS,
    LABEL_SOCKS_PROXY_ERROR, LABEL_SOCKS_PROXY_OK, LABEL_UPLOAD, LABEL_URL_PARSE,
};
use crate::Config;
use core::convert::TryFrom;
use http::{header::USER_AGENT, HeaderName, HeaderValue, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{
    body::Bytes,
    header::{HeaderMap, ToStrError},
    Method,
};
use hyper_rustls::HttpsConnector;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_socks2::SocksConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use ic_https_outcalls_service::{
    https_outcalls_service_server::HttpsOutcallsService, HttpHeader, HttpMethod,
    HttpsOutcallRequest, HttpsOutcallResponse,
};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use rand::{seq::SliceRandom, thread_rng, Rng};
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

/// TODO(NET-1765): Inline this constant into the code and remove the feature flag.
const NEW_SOCKS_PROXY_ROLLOUT: u32 = 100;

type OutboundRequestBody = Full<Bytes>;

type Cache =
    BTreeMap<String, Client<HttpsConnector<SocksConnector<HttpConnector>>, OutboundRequestBody>>;

pub struct CanisterHttp {
    client: Client<HttpsConnector<HttpConnector>, OutboundRequestBody>,
    socks_client: Client<HttpsConnector<SocksConnector<HttpConnector>>, OutboundRequestBody>,
    cache: Arc<RwLock<Cache>>,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
    http_connect_timeout_secs: u64,
}

fn should_only_use_new_socks_proxy() -> bool {
    // This is a temporary feature flag to allow us to test the new socks proxy implementation
    // without affecting the existing implementation.
    let mut rng = rand::thread_rng();
    let random_number: u32 = rng.gen_range(0..100);
    random_number < NEW_SOCKS_PROXY_ROLLOUT
}

impl CanisterHttp {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        // Socks client setup
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(config.http_connect_timeout_secs)));
        // The proxy connnector requires a the URL scheme to be specified. I.e socks5://
        // Config validity check ensures that url includes scheme, host and port.
        // Therefore the parse 'Uri' will be in the correct format. I.e socks5://somehost.com:1080
        let proxy_connector = SocksConnector {
            proxy_addr: config
                .socks_proxy
                .parse()
                .expect("Failed to parse socks url."),
            auth: None,
            connector: http_connector.clone(),
        };
        let proxied_builder = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to set native roots");
        #[cfg(not(feature = "http"))]
        let proxied_builder = proxied_builder.https_only();
        #[cfg(feature = "http")]
        let proxied_builder = proxied_builder.https_or_http();
        let proxied_https_connector = proxied_builder
            .enable_all_versions()
            .wrap_connector(proxy_connector);

        // Https client setup.
        let builder = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to set native roots");
        #[cfg(not(feature = "http"))]
        let builder = builder.https_only();
        #[cfg(feature = "http")]
        let builder = builder.https_or_http();

        let builder = builder.enable_all_versions();
        let direct_https_connector = builder.wrap_connector(http_connector);

        let socks_client =
            Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(proxied_https_connector);
        let client = Client::builder(TokioExecutor::new())
            .http2_max_header_list_size(MAX_HEADER_LIST_SIZE)
            .build::<_, Full<Bytes>>(direct_https_connector);

        Self {
            client,
            socks_client,
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            logger,
            metrics: AdapterMetrics::new(metrics),
            http_connect_timeout_secs: config.http_connect_timeout_secs,
        }
    }

    fn create_socks_proxy_client(
        &self,
        proxy_addr: Uri,
    ) -> Client<HttpsConnector<SocksConnector<HttpConnector>>, Full<Bytes>> {
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(self.http_connect_timeout_secs)));

        let builder = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to set native roots");

        #[cfg(not(feature = "http"))]
        let builder = builder.https_only();
        #[cfg(feature = "http")]
        let builder = builder.https_or_http();

        Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(
            builder
                .enable_all_versions()
                .wrap_connector(SocksConnector {
                    proxy_addr,
                    auth: None,
                    connector: http_connector,
                }),
        )
    }

    fn compare_results(
        &self,
        result: &Result<http::Response<Incoming>, String>,
        dark_launch_result: &Result<http::Response<Incoming>, String>,
    ) {
        match (result, dark_launch_result) {
            (Ok(result), Ok(dark_launch_result)) => {
                self.metrics
                    .socks_proxy_dl_requests
                    .with_label_values(&[LABEL_SOCKS_PROXY_OK, LABEL_SOCKS_PROXY_OK])
                    .inc();
                if result.status() != dark_launch_result.status() {
                    info!(
                        self.logger,
                        "SOCKS_PROXY_DL: status code mismatch: {} vs {}",
                        result.status(),
                        dark_launch_result.status(),
                    );
                }
            }
            (Err(_), Err(_)) => {
                self.metrics
                    .socks_proxy_dl_requests
                    .with_label_values(&[LABEL_SOCKS_PROXY_ERROR, LABEL_SOCKS_PROXY_ERROR])
                    .inc();
            }
            (Ok(_), Err(err)) => {
                self.metrics
                    .socks_proxy_dl_requests
                    .with_label_values(&[LABEL_SOCKS_PROXY_OK, LABEL_SOCKS_PROXY_ERROR])
                    .inc();
                info!(
                    self.logger,
                    "SOCKS_PROXY_DL: regular request succeeded, DL request failed with error {}",
                    err,
                );
            }
            (Err(err), Ok(_)) => {
                self.metrics
                    .socks_proxy_dl_requests
                    .with_label_values(&[LABEL_SOCKS_PROXY_ERROR, LABEL_SOCKS_PROXY_OK])
                    .inc();
                info!(
                    self.logger,
                    "SOCKS_PROXY_DL: DL request succeeded, regular request failed with error {}",
                    err,
                );
            }
        }
    }

    // Attempts to load the socks client from the cache. If not present, creates a new socks client and adds it to the cache.
    fn get_socks_client(
        &self,
        socks_proxy_uri: Uri,
    ) -> Client<HttpsConnector<SocksConnector<HttpConnector>>, OutboundRequestBody> {
        let cache_guard = self.cache.upgradable_read();

        if let Some(client) = cache_guard.get(&socks_proxy_uri.to_string()) {
            client.clone()
        } else {
            let mut cache_guard = RwLockUpgradableReadGuard::upgrade(cache_guard);
            self.metrics.socks_cache_misses.inc();
            let client = self.create_socks_proxy_client(socks_proxy_uri.clone());
            cache_guard.insert(socks_proxy_uri.to_string(), client.clone());
            self.metrics.socks_cache_size.set(cache_guard.len() as i64);
            client
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

    async fn do_https_outcall_socks_proxy(
        &self,
        socks_proxy_addrs: Vec<String>,
        request: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<Incoming>, String> {
        let mut socks_proxy_addrs = socks_proxy_addrs.to_owned();

        socks_proxy_addrs.shuffle(&mut thread_rng());

        let mut last_error = None;

        let mut tries = 0;

        for socks_proxy_addr in &socks_proxy_addrs {
            let socks_proxy_uri: Uri = match socks_proxy_addr.parse() {
                Ok(uri) => uri,
                Err(e) => {
                    debug!(self.logger, "Failed to parse SOCKS proxy address: {}", e);
                    continue;
                }
            };

            tries += 1;
            if tries > MAX_SOCKS_PROXY_TRIES {
                break;
            }

            let socks_client = self.get_socks_client(socks_proxy_uri);

            let url_format = Self::classify_uri_host(request.uri());

            match socks_client.request(request.clone()).await {
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
            Err(format!("{:?}", last_error))
        } else {
            Err("No SOCKS proxy addresses provided".to_string())
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

        #[cfg(not(feature = "http"))]
        if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
            use crate::metrics::LABEL_HTTP_SCHEME;
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

        // If we are allowed to use socks and condition described in `should_use_socks_proxy` hold,
        // we do the requests through the socks proxy. If not we use the default IPv6 route.
        let http_resp = if req.socks_proxy_allowed { // System subnet
            // Http request does not implement clone. So we have to manually construct a clone.
            let mut http_req = hyper::Request::new(Full::new(Bytes::from(req.body)));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            let http_req_clone = http_req.clone();

            match self.client.request(http_req).await {
                // If we fail we try with the socks proxy. For destinations that are ipv4 only this should
                // fail fast because our interface does not have an ipv4 assigned.
                Err(direct_err) => {
                    self.metrics.requests_socks.inc();

                    let deprecated_result =  if should_only_use_new_socks_proxy() {
                        None
                    } else {
                        Some(self
                            .socks_client
                            .request(http_req_clone.clone())
                            .await
                            .map_err(|socks_err| {
                                format!(
                                    "Request failed direct connect {:?} and connect through socks {:?}",
                                    direct_err, socks_err
                                )
                            }))
                        };

                    //TODO(NET-1765): Remove the compare_results once we are confident in the SOCKS proxy implementation.
                    if !req.socks_proxy_addrs.is_empty() {
                        let dark_launch_result = self
                            .do_https_outcall_socks_proxy(req.socks_proxy_addrs, http_req_clone)
                            .await;
                        match deprecated_result {
                            Some(deprecated_result) => {
                                // We compare the results of the deprecated socks proxy implementation with the new one.
                                self.compare_results(&deprecated_result, &dark_launch_result);
                                if deprecated_result.is_err() && dark_launch_result.is_ok() {
                                    // If dl found something, return that.
                                    dark_launch_result
                                } else {
                                    deprecated_result
                                }
                            }
                            None => {
                                // Eventually only this branch should be active. 
                                dark_launch_result
                            }
                        }
                    } else {
                        // We didn't receive any proxy addresses to use; this could mean one of several things:
                        // 1. There is an issue somewhere in the registry
                        // 2. There really are no active API boundary nodes
                        // 3. The caller does not want to proxy requests via the socks server.
                        // TODO: consider using the already stored socks clients.
                        match deprecated_result {
                            Some(resp) => {
                                warn!(self.logger, "SOCKS_PROXY_DL: No socks proxy addresses provided, falling back to old socks client");
                                resp
                            }
                            None => {
                                warn!(self.logger, "SOCKS_PROXY_DL: No socks proxy addresses provided, old socks client not available");
                                Err("No socks proxy addresses provided".to_string())
                            }
                        }
                    }
                }
                Ok(resp) => Ok(resp),
            }
        } else { // Application subnet. 
            // TODO: as technically socks proxies are now tried all the time, instead of using
            // the "socks_proxy_allowed" flag, we should instead send the relevant URLs in the 
            // "socks_proxy_addrs" param. Particularly, the caller should send the API BNs in 
            // the case of system subnets, and the socks5.ic0.app URL in the case of app subnets.
            let mut http_req = hyper::Request::new(Full::new(Bytes::from(req.body)));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            let http_req_clone = http_req.clone();
            match self.client
                .request(http_req)
                .await {
                Ok(http_resp) => Ok(http_resp),
                Err(direct_err) => {
                    self.metrics.requests_socks.inc();
                    self
                        .socks_client
                        .request(http_req_clone)
                        .await
                        .map_err(|socks_err| {
                            format!(
                                "Request failed direct connect {:?} and connect through socks {:?} (Please note that the canister HTTPS outcalls feature is an IPv6-only feature. While IPv4 is an experimental feature, it cannot be relied upon for this functionality. For more information, please consult the Internet Computer developer documentation)",
                                direct_err, socks_err
                            )
                        })
                    }
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
        let body_bytes = http_body_util::Limited::new(
            http_resp.into_body(),
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
                })? as usize,
        )
        .collect()
        .await
        .map(|col| col.to_bytes())
        .map_err(|err| {
            debug!(self.logger, "Failed to fetch body: {}", err);
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                .inc();
            Status::new(
                tonic::Code::OutOfRange,
                format!(
                    "Http body exceeds size limit of {} bytes.",
                    req.max_response_size_bytes
                ),
            )
        })?;

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

    #[test]
    fn test_classify_uri_host() {
        let ipv4_url = "http://127.0.0.1/path";
        let ipv6_url = "http://[2001:db8::1]/path";
        let domain_name_url = "http://example.com/something";
        let empty_hostname_url = "/hello/world";

        assert_eq!(
            CanisterHttp::classify_uri_host(&Uri::from_str(ipv4_url).unwrap()),
            "v4"
        );
        assert_eq!(
            CanisterHttp::classify_uri_host(&Uri::from_str(ipv6_url).unwrap()),
            "v6"
        );
        assert_eq!(
            CanisterHttp::classify_uri_host(&Uri::from_str(domain_name_url).unwrap()),
            "domain_name"
        );
        assert_eq!(
            CanisterHttp::classify_uri_host(&Uri::from_str(empty_hostname_url).unwrap()),
            "empty"
        );
    }
}
