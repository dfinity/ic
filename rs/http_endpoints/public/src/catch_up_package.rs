//! Module that deals with requests to /_/catch_up_package

use crate::{
    body::BodyReceiverLayer, common, types::ApiReqType, EndpointService, HttpHandlerMetrics,
    LABEL_UNKNOWN,
};
use bytes::Bytes;
use http::Request;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::consensus::catchup::CatchUpPackageParam;
use ic_types::consensus::CatchUpPackage;
use prost::Message;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, util::BoxCloneService, Service, ServiceBuilder,
};

#[derive(Clone)]
pub(crate) struct CatchUpPackageService {
    metrics: HttpHandlerMetrics,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

impl CatchUpPackageService {
    pub(crate) fn new_service(
        config: Config,
        metrics: HttpHandlerMetrics,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ) -> EndpointService {
        let base_service = BoxCloneService::new(
            ServiceBuilder::new()
                .layer(GlobalConcurrencyLimitLayer::new(
                    config.max_catch_up_package_concurrent_requests,
                ))
                .service(Self {
                    metrics,
                    consensus_pool_cache,
                }),
        );

        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(BodyReceiverLayer::new(&config))
                .service(base_service),
        )
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

impl Service<Request<Bytes>> for CatchUpPackageService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        self.metrics
            .request_body_size_bytes
            .with_label_values(&[ApiReqType::CatchUpPackage.into(), LABEL_UNKNOWN])
            .observe(request.body().len() as f64);

        let body = request.into_body();
        let cup_proto = self.consensus_pool_cache.cup_as_protobuf();
        let res = if body.is_empty() {
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
        };
        Box::pin(async move { res })
    }
}
