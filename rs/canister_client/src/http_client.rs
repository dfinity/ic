//! The hyper based HTTP client

use hyper::client::HttpConnector as HyperConnector;
use hyper::client::ResponseFuture as HyperFuture;
use hyper::Client as HyperClient;
use hyper::Uri as HyperUri;
use hyper_tls::HttpsConnector as HyperTlsConnector;
use std::time::Duration;
use url::Url;

/// An HTTP Client to communicate with a replica.
#[derive(Clone)]
pub struct HttpClient {
    hyper: HyperClient<HyperTlsConnector<HyperConnector>>,
}

impl HttpClient {
    pub fn new() -> Self {
        let native_tls_connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build tls connector");
        let mut http_connector = HyperConnector::new();
        http_connector.enforce_http(false);
        let https_connector =
            HyperTlsConnector::from((http_connector, native_tls_connector.into()));

        let hyper = HyperClient::builder()
            .pool_idle_timeout(Some(Duration::from_secs(600)))
            .pool_max_idle_per_host(1)
            .build::<_, hyper::Body>(https_connector);

        Self { hyper }
    }

    fn build_uri(&self, url: &Url, end_point: &str) -> Result<HyperUri, String> {
        let url = url.join(end_point).map_err(|e| {
            format!(
                "HttpClient: Failed to create URI for {}: {:?}",
                end_point, e
            )
        })?;

        url.as_str()
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse {:?}: {:?}", url, e))
    }

    fn build_post_request(&self, uri: HyperUri, http_body: Vec<u8>) -> Result<HyperFuture, String> {
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri.clone())
            .header("Content-Type", "application/cbor")
            .body(hyper::Body::from(http_body))
            .map_err(|e| {
                format!(
                    "HttpClient: Failed to create POST request for {:?}: {:?}",
                    uri, e
                )
            })?;
        Ok(self.hyper.request(req))
    }

    async fn wait_for_one_http_request(
        uri: HyperUri,
        response_future: HyperFuture,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let result = tokio::time::timeout_at(deadline, response_future)
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?;
        let response = result.map_err(|e| format!("Request failed for {:?}: {:?}", uri, e))?;
        if !response.status().is_success() {
            return Err(format!(
                "HTTP Client: Request for {:?} failed: {:?}",
                uri, response
            ));
        }
        hyper::body::to_bytes(response)
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| {
                format!(
                    "HttpClient: Request failed to get bytes for {:?}: {:?}",
                    uri, e
                )
            })
    }

    pub(crate) async fn get_with_response(
        &self,
        url: &Url,
        end_point: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.hyper.get(uri.clone());
        Self::wait_for_one_http_request(uri, response_future, deadline).await
    }

    pub(crate) async fn post_with_response(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.build_post_request(uri.clone(), http_body)?;
        Self::wait_for_one_http_request(uri, response_future, deadline).await
    }

    pub async fn send_post_request(
        &self,
        url: &str,
        http_body: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> Result<(Vec<u8>, hyper::StatusCode), String> {
        let uri = url
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse URL {:?}: {:?}", url, e))?;
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri.clone())
            .header("Content-Type", "application/cbor")
            .body(hyper::Body::from(http_body))
            .map_err(|e| format!("HttpClient: Failed to fill body {:?}: {:?}", url, e))?;
        let response_future = self.hyper.request(req);

        let response = tokio::time::timeout_at(deadline, response_future)
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?;
        let response_body = response
            .map_err(|e| format!("HttpClient: Request failed out for {:?}: {:?}", uri, e))?;
        let status_code = response_body.status();
        let response_bytes =
            tokio::time::timeout_at(deadline, hyper::body::to_bytes(response_body))
                .await
                .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?
                .map(|bytes| bytes.to_vec())
                .map_err(|e| format!("HttpClient: Failed to get bytes for {:?}: {:?}", uri, e))?;

        Ok((response_bytes, status_code))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}
