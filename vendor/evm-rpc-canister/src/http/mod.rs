use crate::{
    constants::{COLLATERAL_CYCLES_PER_NODE, CONTENT_TYPE_VALUE},
    memory::{get_num_subnet_nodes, is_demo_active, next_request_id},
    util::canonicalize_json,
};
use canhttp::{
    convert::ConvertRequestLayer,
    cycles::{ChargeCaller, CyclesAccounting},
    http::{
        json::{
            CreateJsonRpcIdFilter, HttpJsonRpcRequest, HttpJsonRpcResponse, JsonRequestConverter,
            JsonResponseConverter,
        },
        FilterNonSuccessfulHttpResponse, HttpRequestConverter, HttpResponseConverter,
    },
    observability::ObservabilityLayer,
    retry::DoubleMaxResponseBytes,
    ConvertServiceBuilder,
};
use error::HttpClientError;
use evm_rpc_types::RpcError;
use http::{header::CONTENT_TYPE, HeaderValue};
use ic_cdk::management_canister::{
    HttpRequestArgs as IcHttpRequest, HttpRequestResult as IcHttpResponse, TransformArgs,
};
use observability::{
    observe_http_client_error, observe_http_json_rpc_request, observe_http_json_rpc_response,
};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use tower::{
    layer::util::{Identity, Stack},
    retry::RetryLayer,
    util::MapRequestLayer,
    Service, ServiceBuilder,
};
use tower_http::{set_header::SetRequestHeaderLayer, ServiceBuilderExt};

pub mod error;
pub mod legacy;
mod observability;

pub fn http_client<I, O>(
    retry: bool,
) -> impl Service<HttpJsonRpcRequest<I>, Response = HttpJsonRpcResponse<O>, Error = RpcError>
where
    I: Serialize + Clone + Debug,
    O: DeserializeOwned + Debug,
{
    let maybe_retry = if retry {
        Some(RetryLayer::new(DoubleMaxResponseBytes))
    } else {
        None
    };
    let maybe_unique_id = if retry {
        Some(MapRequestLayer::new(generate_request_id))
    } else {
        None
    };
    ServiceBuilder::new()
        .map_err(|e: HttpClientError| RpcError::from(e))
        .option_layer(maybe_retry)
        .option_layer(maybe_unique_id)
        .layer(
            ObservabilityLayer::new()
                .on_request(observe_http_json_rpc_request)
                .on_response(observe_http_json_rpc_response)
                .on_error(observe_http_client_error),
        )
        .filter_response(CreateJsonRpcIdFilter::new())
        .layer(service_request_builder())
        .convert_response(JsonResponseConverter::new())
        .convert_response(FilterNonSuccessfulHttpResponse)
        .convert_response(HttpResponseConverter)
        .convert_request(CyclesAccounting::new(charging_policy_with_collateral()))
        .service(canhttp::Client::new_with_error::<HttpClientError>())
}

fn generate_request_id<I>(request: HttpJsonRpcRequest<I>) -> HttpJsonRpcRequest<I> {
    let (parts, mut body) = request.into_parts();
    body.set_id(next_request_id());
    http::Request::from_parts(parts, body)
}

type JsonRpcServiceBuilder<I> = ServiceBuilder<
    Stack<
        ConvertRequestLayer<HttpRequestConverter>,
        Stack<
            ConvertRequestLayer<JsonRequestConverter<I>>,
            Stack<SetRequestHeaderLayer<HeaderValue>, Identity>,
        >,
    >,
>;

/// Middleware that takes care of transforming the request.
///
/// It's required to separate it from the other middlewares, to compute the exact request cost.
pub fn service_request_builder<I>() -> JsonRpcServiceBuilder<I> {
    ServiceBuilder::new()
        .insert_request_header_if_not_present(
            CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_VALUE),
        )
        .convert_request(JsonRequestConverter::<I>::new())
        .convert_request(HttpRequestConverter)
}

pub fn charging_policy_with_collateral(
) -> ChargeCaller<impl Fn(&IcHttpRequest, u128) -> u128 + Clone> {
    let charge_caller = if is_demo_active() {
        |_request: &IcHttpRequest, _request_cost| 0
    } else {
        |_request: &IcHttpRequest, request_cost| {
            let collateral_cycles =
                COLLATERAL_CYCLES_PER_NODE.saturating_mul(get_num_subnet_nodes() as u128);
            request_cost + collateral_cycles
        }
    };
    ChargeCaller::new(charge_caller)
}

pub fn transform_http_request(args: TransformArgs) -> IcHttpResponse {
    IcHttpResponse {
        status: args.response.status,
        body: canonicalize_json(&args.response.body).unwrap_or(args.response.body),
        // Remove headers (which may contain a timestamp) for consensus
        headers: vec![],
    }
}
