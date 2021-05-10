//! Module that deals with requests to /_/catch_up_package

use crate::common;
use hyper::{Body, Response, StatusCode};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_types::consensus::catchup::CatchUpPackageParam;

/// Handles a call to /_/catch_up_package
pub(crate) fn handle(
    consensus_pool_cache: &dyn ConsensusPoolCache,
    body: Vec<u8>,
) -> Response<Body> {
    let cup = consensus_pool_cache.cup_with_protobuf();
    if body.is_empty() {
        common::protobuf_response(&cup.protobuf)
    } else {
        match serde_cbor::from_slice::<CatchUpPackageParam>(&body) {
            Ok(param) => {
                if CatchUpPackageParam::from(&cup.cup) > param {
                    common::protobuf_response(&cup.protobuf)
                } else {
                    common::empty_response()
                }
            }
            Err(e) => common::make_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Could not parse body as CatchUpPackage param: {}", e).as_str(),
            ),
        }
    }
}
