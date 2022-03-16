use http::Uri;
use hyper::client::HttpConnector;
use hyper::{body, Body, Client, Method};
use hyper_tls::HttpsConnector;
use ic_canister_http_adapter_service::http_adapter_server::HttpAdapter;
use ic_logger::{debug, ReplicaLogger};
use ic_protobuf::canister_http::v1::{CanisterHttpRequest, CanisterHttpResponse, HttpHeader};
use tonic::{Request, Response, Status};

/// implements RPC
pub struct CanisterHttp {
    https_client: Client<HttpsConnector<HttpConnector>>,
    logger: ReplicaLogger,
}

impl CanisterHttp {
    /// initalize new hyper clients
    pub fn new(logger: ReplicaLogger) -> CanisterHttp {
        let https = HttpsConnector::new();
        let https_client = Client::builder().build::<_, hyper::Body>(https);
        Self {
            https_client,
            logger,
        }
    }
}

#[tonic::async_trait]
impl HttpAdapter for CanisterHttp {
    async fn send_http_request(
        &self,
        request: Request<CanisterHttpRequest>,
    ) -> Result<Response<CanisterHttpResponse>, Status> {
        let req = request.into_inner();

        let uri = req.url.parse::<Uri>().map_err(|err| {
            debug!(self.logger, "Failed to parse URL: {}", err);
            Status::new(tonic::Code::InvalidArgument, "Failed to parse url")
        })?;

        // TODO: Connect to SOCKS proxy (NET-881)
        let http_req = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::from(req.body))
            .map_err(|err| {
                debug!(self.logger, "Failed to build HTTP request URL: {}", err);
                Status::new(tonic::Code::InvalidArgument, "Failed to build http request")
            })?;

        let http_resp = self.https_client.request(http_req).await.map_err(|err| {
            debug!(self.logger, "Failed to connect: {}", err);
            Status::new(tonic::Code::Unavailable, "Failed to connect")
        })?;

        let status = http_resp.status().as_u16() as u32;

        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| HttpHeader {
                name: k.to_string(),
                value: v.as_bytes().to_vec(),
            })
            .collect::<Vec<HttpHeader>>();

        // TODO: replace this with a bounded version with timeout. (NET-882)
        let body_bytes = body::to_bytes(http_resp).await.map_err(|err| {
            debug!(self.logger, "Failed to fetch body: {}", err);
            Status::new(tonic::Code::Unavailable, "Failed to fetch body")
        })?;

        Ok(Response::new(CanisterHttpResponse {
            status,
            headers,
            content: body_bytes.to_vec(),
        }))
    }
}
