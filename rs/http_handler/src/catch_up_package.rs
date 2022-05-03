//! Module that deals with requests to /_/catch_up_package

use crate::{
    common,
    types::{to_legacy_request_type, ApiReqType},
    HttpHandlerMetrics, UNKNOWN_LABEL,
};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::consensus::catchup::CatchUpPackageParam;
use prost::Message;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{BoxError, Service};

#[derive(Clone)]
pub(crate) struct CatchUpPackageService {
    metrics: HttpHandlerMetrics,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

impl CatchUpPackageService {
    pub(crate) fn new(
        metrics: HttpHandlerMetrics,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ) -> Self {
        Self {
            metrics,
            consensus_pool_cache,
        }
    }
}

/// Write the provided prost::Message as a serialized protobuf into a Response
/// object.
fn protobuf_response<R: Message>(r: &R) -> Response<Body> {
    use hyper::header;
    let mut buf = Vec::<u8>::new();
    r.encode(&mut buf)
        .expect("impossible: Serialization failed");
    let mut response = Response::new(Body::from(buf));
    *response.status_mut() = StatusCode::OK;
    *response.headers_mut() = common::get_cors_headers();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(common::CONTENT_TYPE_PROTOBUF),
    );
    response
}

impl Service<Vec<u8>> for CatchUpPackageService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, body: Vec<u8>) -> Self::Future {
        self.metrics
            .requests_body_size_bytes
            .with_label_values(&[
                to_legacy_request_type(ApiReqType::CatchUpPackage),
                ApiReqType::CatchUpPackage.into(),
                UNKNOWN_LABEL,
            ])
            .observe(body.len() as f64);

        let cup = self.consensus_pool_cache.cup_with_protobuf();
        let res = if body.is_empty() {
            Ok(protobuf_response(&cup.protobuf))
        } else {
            match serde_cbor::from_slice::<CatchUpPackageParam>(&body) {
                Ok(param) => {
                    if CatchUpPackageParam::from(&cup.cup) > param {
                        Ok(protobuf_response(&cup.protobuf))
                    } else {
                        Ok(common::empty_response())
                    }
                }
                Err(e) => Ok(common::make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Could not parse body as CatchUpPackage param: {}", e),
                )),
            }
        };
        Box::pin(async move { res })
    }
}
