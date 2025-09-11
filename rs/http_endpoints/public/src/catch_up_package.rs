//! Module that deals with requests to /_/catch_up_package

use crate::common;
use crate::verify_cbor_content_header;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::response::IntoResponse;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::consensus::CatchUpPackage;
use ic_types::consensus::catchup::CatchUpPackageParam;
use prost::Message;
use std::sync::Arc;
use tower::{BoxError, ServiceBuilder};

#[derive(Clone)]
pub(crate) struct CatchUpPackageService {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

impl CatchUpPackageService {
    pub(crate) fn route() -> &'static str {
        "/_/catch_up_package"
    }
}

impl CatchUpPackageService {
    pub(crate) fn new_router(consensus_pool_cache: Arc<dyn ConsensusPoolCache>) -> Router {
        let state = Self {
            consensus_pool_cache,
        };
        Router::new().route_service(
            Self::route(),
            axum::routing::post(cup).with_state(state).layer(
                ServiceBuilder::new().layer(axum::middleware::from_fn(verify_cbor_content_header)),
            ),
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
    let mut response = Response::new(Body::new(Full::from(buf).map_err(BoxError::from)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(common::CONTENT_TYPE_PROTOBUF),
    );
    response
}

async fn cup(
    State(CatchUpPackageService {
        consensus_pool_cache,
    }): State<CatchUpPackageService>,
    body: Bytes,
) -> impl IntoResponse {
    let cup_proto = consensus_pool_cache.cup_as_protobuf();
    if body.is_empty() {
        protobuf_response(&cup_proto)
    } else {
        match serde_cbor::from_slice::<CatchUpPackageParam>(&body) {
            Ok(param) => {
                let cup: CatchUpPackage =
                    (&cup_proto).try_into().expect("deserializing CUP failed");
                if CatchUpPackageParam::from(&cup) > param {
                    protobuf_response(&cup_proto)
                } else {
                    StatusCode::NO_CONTENT.into_response()
                }
            }
            Err(e) => {
                let code = StatusCode::BAD_REQUEST;
                let text = format!("Could not parse body as CatchUpPackage param: {e}");
                (code, text).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{Method, Request, header::CONTENT_TYPE};
    use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
    use tower::ServiceExt;

    use crate::{CONTENT_TYPE_CBOR, common::CONTENT_TYPE_PROTOBUF};

    use super::*;

    #[tokio::test]
    async fn return_cup_empty_request() {
        use ic_protobuf::types::v1 as pb;
        let mut mock_cache = MockConsensusPoolCache::default();
        mock_cache
            .expect_cup_as_protobuf()
            .returning(|| pb::CatchUpPackage {
                ..Default::default()
            });

        let cup_router = CatchUpPackageService::new_router(Arc::new(mock_cache));

        let resp = cup_router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(CatchUpPackageService::route())
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let resceived_cup =
            pb::CatchUpPackage::decode(axum::body::to_bytes(body, usize::MAX).await.unwrap())
                .unwrap();

        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get(CONTENT_TYPE).unwrap(),
            CONTENT_TYPE_PROTOBUF
        );
        assert_eq!(resceived_cup, pb::CatchUpPackage::default());
    }
}
