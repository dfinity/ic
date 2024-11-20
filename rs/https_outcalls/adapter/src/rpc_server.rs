use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_CONNECT, LABEL_DOWNLOAD,
    LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS,
    LABEL_UPLOAD, LABEL_URL_PARSE,
};
use crate::Config;
use core::convert::TryFrom;
use http::{header::USER_AGENT, HeaderName, HeaderValue, Uri};
use http_body_util::{BodyExt, Full};
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
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
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

type OutboundRequestBody = Full<Bytes>;

type Cache =
    BTreeMap<String, Client<HttpsConnector<SocksConnector<HttpConnector>>, OutboundRequestBody>>;

use std::sync::Mutex;

pub struct CanisterHttp {
    client: Client<HttpsConnector<HttpConnector>, OutboundRequestBody>,
    cache: Arc<Mutex<Cache>>,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
    http_connect_timeout_secs: u64,
    next_proxy_index: AtomicUsize,
}

impl CanisterHttp {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        // Socks client setup
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(config.http_connect_timeout_secs)));
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

        let client = Client::builder(TokioExecutor::new())
            .http2_max_header_list_size(MAX_HEADER_LIST_SIZE)
            .build::<_, Full<Bytes>>(direct_https_connector);

        Self {
            client,
            cache: Arc::new(Mutex::new(BTreeMap::new())),
            logger,
            metrics: AdapterMetrics::new(metrics),
            http_connect_timeout_secs: config.http_connect_timeout_secs,
            next_proxy_index: AtomicUsize::new(0),
        }
    }

    fn create_cache(&self, api_bn_ips: &[String]) -> Cache {
        let mut new_cache = Cache::new();

        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(self.http_connect_timeout_secs)));

        for ip in api_bn_ips {
            match ip.parse() {
                Ok(proxy_addr) => {
                    let proxy_connector = SocksConnector {
                        proxy_addr,
                        auth: None,
                        connector: http_connector.clone(),
                    };

                    let proxied_https_connector = HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .expect("Failed to set native roots")
                        .https_only()
                        .enable_all_versions()
                        .wrap_connector(proxy_connector);

                    let socks_client = Client::builder(TokioExecutor::new())
                        .build::<_, Full<Bytes>>(proxied_https_connector);

                    new_cache.insert(ip.clone(), socks_client);
                }
                Err(e) => {
                    debug!(self.logger, "Failed to parse SOCKS IP: {}", e);
                }
            }
        }
        new_cache
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

        let mut sorted_incoming_ips = req.api_bn_ips;
        sorted_incoming_ips.sort();
        sorted_incoming_ips.dedup();

        // Lock the cache and clone the relevant data
       let clients = {
            let mut cache_guard = self.cache.lock().unwrap();

            // Check if the cache needs to be updated
            let cached_ips: Vec<String> = cache_guard.keys().cloned().collect();
            if cached_ips != sorted_incoming_ips {
                // Update the cache
                *cache_guard = self.create_cache(&sorted_incoming_ips);
            }

            // Clone the clients to avoid holding the lock during async operations
            cache_guard.values().cloned().collect::<Vec<_>>()
        };

        // Proceed with the rest of the method using `clients`
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
                "URL needs to specify HTTPS scheme",
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

        // Build HTTP Request
        let mut headers = validate_headers(req.headers).inspect_err(|_| {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_REQUEST_HEADERS])
                .inc();
        })?;

        // Add user-agent header if not present
        add_fallback_user_agent_header(&mut headers);

        let mut request_size = req.body.len();
        request_size += headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>();

        // Determine if we should use the SOCKS proxy
        let http_resp = if req.socks_proxy_allowed {
            let mut http_req = hyper::Request::new(Full::new(Bytes::from(req.body)));
            *http_req.headers_mut() = headers.clone();
            *http_req.method_mut() = method.clone();
            *http_req.uri_mut() = uri.clone();
            let http_req_clone = http_req.clone();

            match self.client.request(http_req).await {
                Err(direct_err) => {
                    self.metrics.requests_socks.inc();

                    let len = clients.len();
                    if len == 0 {
                        return Err(Status::new(
                            tonic::Code::Unavailable,
                            "No SOCKS proxy available".to_string(),
                        ));
                    }

                    let start_index = self.next_proxy_index.fetch_add(1, Ordering::SeqCst) % len;
                    let clients_iter = clients.into_iter().cycle().skip(start_index).take(len);

                    let mut response = None;

                    for client in clients_iter {
                        let http_req = http_req_clone.clone();
                        match client.request(http_req).await {
                            Ok(resp) => {
                                response = Some(resp);
                                break;
                            }
                            Err(e) => {
                                debug!(self.logger, "Failed to connect through SOCKS: {}", e);
                                continue;
                            }
                        }
                    }

                    response.ok_or_else(|| {
                        format!(
                            "Request failed direct connect {direct_err} and connect through all SOCKS proxies"
                        )
                    })
                }
                Ok(resp) => Ok(resp),
            }
        } else {
            let mut http_req = hyper::Request::new(Full::new(Bytes::from(req.body)));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            self.client
                .request(http_req)
                .await
                .map_err(|e| format!("Failed to directly connect: {:?}", e))
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

        // Parse received headers
        let mut headers_size_bytes = 0;
        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                let name = k.to_string();
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

        // Collect the body with a size limit
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
                    "HTTP body exceeds size limit of {} bytes.",
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
}
