//! Module that deals with requests to /_/catch_up_package

use crate::{
    common,
    types::{ApiReqType, RequestType},
    HttpHandlerMetrics, UNKNOWN_LABEL,
};
use hyper::{Body, Response};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::{canonical_error::invalid_argument_error, consensus::catchup::CatchUpPackageParam};
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
                RequestType::CatchUpPackage.as_str(),
                ApiReqType::CatchUpPackage.as_str(),
                UNKNOWN_LABEL,
            ])
            .observe(body.len() as f64);

        let cup = self.consensus_pool_cache.cup_with_protobuf();
        let res = if body.is_empty() {
            Ok(common::protobuf_response(&cup.protobuf))
        } else {
            match serde_cbor::from_slice::<CatchUpPackageParam>(&body) {
                Ok(param) => {
                    if CatchUpPackageParam::from(&cup.cup) > param {
                        Ok(common::protobuf_response(&cup.protobuf))
                    } else {
                        Ok(common::empty_response())
                    }
                }
                Err(e) => Ok(common::make_response(invalid_argument_error(format!(
                    "Could not parse body as CatchUpPackage param: {}",
                    e
                )))),
            }
        };
        Box::pin(async move { res })
    }
}
