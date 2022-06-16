use byte_unit::Byte;
use core::convert::TryFrom;
use http::Uri;
use hyper::{
    client::connect::Connect,
    header::{HeaderMap, ToStrError},
    Body, Client, Method,
};
use ic_async_utils::receive_body_without_timeout;
use ic_canister_http_service::{
    canister_http_service_server::CanisterHttpService, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader,
};
use ic_logger::{debug, ReplicaLogger};
use tonic::{Request, Response, Status};

/// implements RPC
pub struct CanisterHttp<C: Clone + Connect + Send + Sync + 'static> {
    client: Client<C>,
    response_size_limit: Byte,
    logger: ReplicaLogger,
}

impl<C: Clone + Connect + Send + Sync + 'static> CanisterHttp<C> {
    pub fn new(client: Client<C>, response_size_limit: Byte, logger: ReplicaLogger) -> Self {
        Self {
            client,
            response_size_limit,
            logger,
        }
    }
}

#[tonic::async_trait]
impl<C: Clone + Connect + Send + Sync + 'static> CanisterHttpService for CanisterHttp<C> {
    async fn canister_http_send(
        &self,
        request: Request<CanisterHttpSendRequest>,
    ) -> Result<Response<CanisterHttpSendResponse>, Status> {
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

        // We don't need a timeout here because there is a global timeout on the entire request.
        let body_bytes =
            receive_body_without_timeout(http_resp.into_body(), self.response_size_limit)
                .await
                .map_err(|err| {
                    debug!(self.logger, "Failed to fetch body: {}", err);
                    Status::new(
                        tonic::Code::Unavailable,
                        format!("Failed to fetch body: {}", err),
                    )
                })?;

        Ok(Response::new(CanisterHttpSendResponse {
            status,
            headers,
            content: body_bytes.to_vec(),
        }))
    }
}
