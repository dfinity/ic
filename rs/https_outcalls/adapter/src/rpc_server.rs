use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_CONNECT, LABEL_DOWNLOAD,
    LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS,
    LABEL_UPLOAD, LABEL_URL_PARSE,
};
use crate::Config;
use core::convert::TryFrom;
use std::sync::Arc;
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
use std::str::FromStr;
use std::sync::RwLock;
use std::time::Duration;
use tonic::{Request, Response, Status};

use ic_registry_local_store::LocalStoreImpl;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client::client::RegistryClient;

use ic_registry_client_helpers::api_boundary_node::ApiBoundaryNodeRegistry;
use ic_registry_client_helpers::node::NodeRegistry;

use once_cell::sync::OnceCell;

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

use std::sync::atomic::{AtomicUsize, Ordering};

/// Implements HttpsOutcallsService
// TODO: consider making this private
pub struct CanisterHttp {
    client: Client<HttpsConnector<HttpConnector>, OutboundRequestBody>,
    socks_clients: Arc<RwLock<Vec<Arc<Client<HttpsConnector<SocksConnector<HttpConnector>>, OutboundRequestBody>>>>>,
    socks_client_index: AtomicUsize,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
    registry_client: OnceCell<Arc<RegistryClientImpl>>,
    config: Config,
}

impl CanisterHttp {

    fn registry_client(&self) -> &Arc<RegistryClientImpl> {
        self.registry_client.get_or_init(|| {
            let local_store_dir = self.config.registry_client_local_store.clone();
            let data_provider = Arc::new(LocalStoreImpl::new(local_store_dir));
            let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
            registry_client.fetch_and_start_polling();
            registry_client
        })
    }

    fn update_socks_clients(&self) {
        let registry_client = self.registry_client();
        //TODO(mihailjianu): this should handle errors.
        //TODO(mihailjianu): save the version in a variable.
        let ids = registry_client.get_api_boundary_node_ids(registry_client.get_latest_version()).unwrap();

        let ips = ids.iter().map(|id| {
            let record = registry_client.get_node_record(*id, registry_client.get_latest_version()).unwrap();
            record.unwrap().xnet.unwrap().ip_addr
        }).collect::<Vec<String>>();
        let mut new_socks_clients = Vec::new();

        for ip in ips {
            // check if creating a new connector every time is fine.
            let mut http_connector = HttpConnector::new();
            http_connector.enforce_http(false);
            http_connector.set_connect_timeout(Some(Duration::from_secs(self.config.http_connect_timeout_secs)));

            let socks_proxy_port = 1080;
            let proxy_addr = format!("socks5://{}:{}", ip, socks_proxy_port)
                .parse()
                .expect("Failed to parse socks url.");
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

                let client = Client::builder(TokioExecutor::new())
                .build::<_, Full<Bytes>>(proxied_https_connector);
    
            new_socks_clients.push(Arc::new(client));
        }
        {
            let mut clients = self.socks_clients.write().unwrap();
            *clients = new_socks_clients;
        }
    }

    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Arc<Self> {
        //TODO(mihailjianu): add tests for this
        //TODO(mihailjianu): check system tests for the socks proxy
        
        let socks_clients = Arc::new(RwLock::new(Vec::new()));  

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

        let canister_http = Arc::new(Self {
            client,
            socks_clients,
            socks_client_index: AtomicUsize::new(0),
            logger,
            metrics: AdapterMetrics::new(metrics),
            registry_client: OnceCell::new(),
            config,
        });

        let canister_http_clone = Arc::clone(&canister_http);
        tokio::spawn(async move {
            loop {
                // TODO: put this in a config
                tokio::time::sleep(Duration::from_secs(300)).await;
                canister_http_clone.update_socks_clients();
            }
        });

        return canister_http;
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
        let http_resp = if req.socks_proxy_allowed {
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
                    let socks_client = {
                        // Acquire the read lock
                        let socks_clients = self.socks_clients.read().unwrap();
                    
                        if socks_clients.is_empty() {
                            self.update_socks_clients();
                            if socks_clients.is_empty() {
                                return Err(Status::new(
                                    tonic::Code::Unavailable,
                                    format!(
                                        "Request failed with direct connect error `{}` and no SOCKS proxies available",
                                        direct_err
                                    ),
                                ));
                            }
                        }
                    
                        // Create a reference to the inner Vec to avoid moving socks_clients
                        let clients_vec = &*socks_clients;
                        let len = clients_vec.len();
                        let index = self.socks_client_index.fetch_add(1, Ordering::Relaxed) % len;
                        let socks_client = Arc::clone(&clients_vec[index]);
                    
                        // `socks_clients` goes out of scope here, releasing the lock
                        socks_client
                    };
            
                    // Now use `socks_client` without holding the lock
                    match socks_client.request(http_req_clone).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => Err(format!(
                            "Request failed with direct connect error `{}` and SOCKS proxy error `{}`",
                            direct_err, e
                        )),
                    }
                }
                Ok(resp)=> Ok(resp),
            }
        } else {
            let mut http_req = hyper::Request::new(Full::new(Bytes::from(req.body)));
            *http_req.headers_mut() = headers;
            *http_req.method_mut() = method;
            *http_req.uri_mut() = uri.clone();
            self.client.request(http_req).await.map_err(|e| format!("Failed to directly connect: {:?}", e))
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
}
