use crate::metrics::{
    AdapterMetrics, LABEL_BODY_RECEIVE_SIZE, LABEL_BODY_RECEIVE_TIMEOUT, LABEL_CONNECT,
    LABEL_DOWNLOAD, LABEL_HEADER_RECEIVE_SIZE, LABEL_HTTP_METHOD, LABEL_HTTP_SCHEME,
    LABEL_REQUEST_HEADERS, LABEL_RESPONSE_HEADERS, LABEL_UPLOAD, LABEL_URL_PARSE,
};
use core::convert::TryFrom;
use futures::StreamExt;
use ic_https_outcalls_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use reqwest::{
    header::{HeaderMap, HeaderValue, ToStrError, USER_AGENT},
    Client, Method, Url,
};
use std::collections::HashMap;
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
    client: Client,
    socks_client: Client,
    logger: ReplicaLogger,
    metrics: AdapterMetrics,
}

impl CanisterHttp {
    pub fn new(
        client: Client,
        socks_client: Client,
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

        if !req.url.is_ascii() {
            debug!(self.logger, "URL contains non-ascii characters");
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_URL_PARSE])
                .inc();
            return Err(Status::new(
                tonic::Code::InvalidArgument,
                "Failed to parse URL: URL contains non-ascii characters".to_string(),
            ));
        }

        let url = req.url.parse::<Url>().map_err(|err| {
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

        if url.scheme() != "https" {
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
            let response = self.client.request(method.clone(), url.clone()).headers(headers.clone()).body(req.body.clone()).send().await;

            match response {
                // If we fail we try with the socks proxy. For destinations that are ipv4 only this should
                // fail fast because our interface does not have an ipv4 assigned.
                Err(direct_err) => {
                    self.metrics.requests_socks.inc();
                    self.socks_client.request(method.clone(), url.clone()).headers(headers.clone()).body(req.body).send().await.map_err(|e| {
                        format!("Request failed direct connect {direct_err} and connect through socks {e}")
                    })
                }
                Ok(resp)=> Ok(resp),
            }
        } else {
            self.client.request(method.clone(), url.clone()).headers(headers.clone()).body(req.body).send().await.map_err(|e| format!("Failed to directly connect: {e}"))
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
                    url.host().map(|host| host.to_string()).unwrap_or("".to_string()),
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

        let available_size = req
            .max_response_size_bytes
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
            })? as usize;

        let length = http_resp.content_length().unwrap_or_default() as usize;

        if length > available_size {
            self.metrics
                .request_errors
                .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                .inc();
            return Err(Status::new(
                tonic::Code::OutOfRange,
                "Value of 'Content-length' header exceeds http body size limit.",
            ));
        }

        let mut stream = http_resp.bytes_stream();
        let mut body_bytes: Vec<u8> = Vec::with_capacity(length);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                debug!(self.logger, "Failed to fetch body: {}", err);
                self.metrics
                    .request_errors
                    .with_label_values(&[LABEL_BODY_RECEIVE_TIMEOUT])
                    .inc();
                Status::new(
                    tonic::Code::Unavailable,
                    format!("Failed to fetch body: {}", err),
                )
            })?;
            let mut chunk = chunk.slice(..).to_vec();

            if body_bytes.len() + chunk.len() > available_size {
                self.metrics
                    .request_errors
                    .with_label_values(&[LABEL_BODY_RECEIVE_SIZE])
                    .inc();
                return Err(Status::new(
                    tonic::Code::OutOfRange,
                    format!("Http body exceeds size limit of {} bytes.", available_size),
                ));
            }

            body_bytes.append(&mut chunk);
        }

        self.metrics
            .network_traffic
            .with_label_values(&[LABEL_DOWNLOAD])
            .inc_by(body_bytes.len() as u64 + headers_size_bytes as u64);
        Ok(Response::new(CanisterHttpSendResponse {
            status,
            headers,
            content: body_bytes,
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

    let headers: HeaderMap = HeaderMap::try_from(
        &raw_headers
            .into_iter()
            .map(|h| (h.name.to_lowercase(), h.value))
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
}
