use core::convert::TryFrom;
use http::Uri;
use hyper::{
    body,
    client::connect::Connect,
    header::{HeaderMap, ToStrError},
    Body, Client, Method,
};
use ic_canister_http_adapter_service::{
    http_adapter_server::HttpAdapter, CanisterHttpRequest, CanisterHttpResponse, HttpHeader,
};
use ic_logger::{debug, ReplicaLogger};
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
            Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse URL: {}", err),
            )
        })?;

        // Build Http Request.
        let mut http_req = hyper::Request::new(Body::from(req.body));
        let headers: HeaderMap =
            HeaderMap::try_from(&req.headers.into_iter().map(|h| (h.name, h.value)).collect())
                .map_err(|err| {
                    debug!(self.logger, "Failed to parse headers: {}", err);
                    Status::new(
                        tonic::Code::InvalidArgument,
                        format!("Failed to parse headers: {}", err),
                    )
                })?;
        *http_req.headers_mut() = headers;
        *http_req.method_mut() = Method::GET;
        *http_req.uri_mut() = uri;

        let http_resp = self.client.request(http_req).await.map_err(|err| {
            debug!(self.logger, "Failed to connect: {}", err);
            Status::new(
                tonic::Code::Unavailable,
                format!("Failed to connect: {}", err),
            )
        })?;

        let status = http_resp.status().as_u16() as u32;

        // Parse received headers.
        let headers = http_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                Ok(HttpHeader {
                    name: k.to_string(),
                    value: v.to_str()?.to_string(),
                })
            })
            .collect::<Result<Vec<_>, ToStrError>>()
            .map_err(|err| {
                debug!(self.logger, "Failed to parse headers: {}", err);
                Status::new(
                    tonic::Code::Unavailable,
                    format!("Failed to parse headers: {}", err),
                )
            })?;

        // TODO: replace this with a bounded version with timeout. (NET-882)
        let body_bytes = body::to_bytes(http_resp).await.map_err(|err| {
            debug!(self.logger, "Failed to fetch body: {}", err);
            Status::new(
                tonic::Code::Unavailable,
                format!("Failed to fetch body: {}", err),
            )
        })?;

        Ok(Response::new(CanisterHttpResponse {
            status,
            headers,
            content: body_bytes.to_vec(),
        }))
    }
}
