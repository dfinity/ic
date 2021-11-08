//! Module that deals with requests to /_/catch_up_package

use crate::common;
use hyper::{Body, Response};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::{
    canonical_error::{invalid_argument_error, CanonicalError},
    consensus::catchup::CatchUpPackageParam,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{limit::ConcurrencyLimit, load_shed::LoadShed, Service, ServiceBuilder};

const MAX_CONCURRENT_CATCH_UP_PACKAGE_REQUESTS: usize = 1000;

#[derive(Clone)]
pub(crate) struct CatchUpPackageService {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

impl CatchUpPackageService {
    pub(crate) fn new(
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ) -> LoadShed<ConcurrencyLimit<CatchUpPackageService>> {
        let base_service = Self {
            consensus_pool_cache,
        };
        ServiceBuilder::new()
            .load_shed()
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                MAX_CONCURRENT_CATCH_UP_PACKAGE_REQUESTS,
            ))
            .service(base_service)
    }
}

impl Service<Vec<u8>> for CatchUpPackageService {
    type Response = Response<Body>;
    type Error = CanonicalError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, body: Vec<u8>) -> Self::Future {
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
                Err(e) => Err(invalid_argument_error(&format!(
                    "Could not parse body as CatchUpPackage param: {}",
                    e
                ))),
            }
        };
        Box::pin(async move { res })
    }
}
