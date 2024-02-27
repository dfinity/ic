//! Module that deals with requests to /_/catch_up_package

use crate::receive_request_body;
use crate::{common, EndpointService};

use axum::body::Body;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::consensus::catchup::CatchUpPackageParam;
use ic_types::consensus::CatchUpPackage;
use prost::Message;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::BoxError;
use tower::{util::BoxCloneService, Service};

#[derive(Clone)]
pub(crate) struct CatchUpPackageService {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

impl CatchUpPackageService {
    pub(crate) fn new_service(
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ) -> EndpointService {
        BoxCloneService::new(Self {
            consensus_pool_cache,
        })
    }
}

/// Write the provided prost::Message as a serialized protobuf into a Response
/// object.
fn protobuf_response<R: Message>(r: &R) -> Response<Body> {
    use hyper::header;
    let mut buf = Vec::<u8>::new();
    r.encode(&mut buf)
        .expect("impossible: Serialization failed");
    let mut response = Response::new(Body::new(Full::from(buf).map_err(BoxError::from)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(common::CONTENT_TYPE_PROTOBUF),
    );
    response
}

impl Service<Request<Body>> for CatchUpPackageService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let body = request.into_body();
        let cup_proto = self.consensus_pool_cache.cup_as_protobuf();
        Box::pin(async move {
            let body = match receive_request_body(body).await {
                Ok(bytes) => bytes,
                Err(e) => return Ok(e),
            };

            if body.is_empty() {
                Ok(protobuf_response(&cup_proto))
            } else {
                match serde_cbor::from_slice::<CatchUpPackageParam>(&body) {
                    Ok(param) => {
                        let cup: CatchUpPackage =
                            (&cup_proto).try_into().expect("deserializing CUP failed");
                        if CatchUpPackageParam::from(&cup) > param {
                            Ok(protobuf_response(&cup_proto))
                        } else {
                            Ok(common::empty_response())
                        }
                    }
                    Err(e) => Ok(common::make_plaintext_response(
                        StatusCode::BAD_REQUEST,
                        format!("Could not parse body as CatchUpPackage param: {}", e),
                    )),
                }
            }
        })
    }
}
