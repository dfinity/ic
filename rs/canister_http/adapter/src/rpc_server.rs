use http::Uri;
use hyper::client::connect::Connect;
use hyper::{body, Body, Client, Method};
use ic_canister_http_adapter_service::http_adapter_server::HttpAdapter;
use ic_logger::{debug, ReplicaLogger};
use ic_protobuf::canister_http::v1::{CanisterHttpRequest, CanisterHttpResponse, HttpHeader};
use tonic::{Request, Response, Status};

/// implements RPC
pub struct CanisterHttp<C: Clone + Connect + Send + Sync + 'static> {
    client: Client<C>,
    logger: ReplicaLogger,
}

impl<C: Clone + Connect + Send + Sync + 'static> CanisterHttp<C> {
    pub fn new(client: Client<C>, logger: ReplicaLogger) -> Self {
        Self { client, logger }
    }
}

#[tonic::async_trait]
impl<C: Clone + Connect + Send + Sync + 'static> HttpAdapter for CanisterHttp<C> {
    async fn send_http_request(
        &self,
        request: Request<CanisterHttpRequest>,
    ) -> Result<Response<CanisterHttpResponse>, Status> {
        let req = request.into_inner();

        let uri = req.url.parse::<Uri>().map_err(|err| {
            debug!(self.logger, "Failed to parse URL: {}", err);
            Status::new(tonic::Code::InvalidArgument, "Failed to parse url")
        })?;

        let http_req = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::from(req.body))
            .map_err(|err| {
                debug!(self.logger, "Failed to build HTTP request URL: {}", err);
                Status::new(tonic::Code::InvalidArgument, "Failed to build http request")
            })?;

        let http_resp = self.client.request(http_req).await.map_err(|err| {
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
