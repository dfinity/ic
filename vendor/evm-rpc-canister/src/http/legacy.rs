use crate::{
    memory::get_override_provider, providers::resolve_rpc_service, types::MetricRpcMethod,
};
use canhttp::{
    http::json::{HttpJsonRpcRequest, JsonRpcRequest},
    MaxResponseBytesRequestExtension, TransformContextRequestExtension,
};
use evm_rpc_types::{RpcError, RpcResult, RpcService, ValidationError};
use ic_management_canister_types::{TransformContext, TransformFunc};

/// Create the HTTP JSON-RPC request for the legacy `request` endpoint.
///
/// The `request` endpoint is deprecated but exists for backwards-compatibility.
/// It has been replaced with the `multi_request` endpoint which, similarly to
/// other RPC endpoints, aggregates the response from multiple RPC providers.
pub fn json_rpc_request(
    service: RpcService,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> RpcResult<HttpJsonRpcRequest<serde_json::Value>> {
    let resolved_service = resolve_rpc_service(service.clone())?;
    let body: JsonRpcRequest<serde_json::Value> =
        serde_json::from_str(json_rpc_payload).map_err(|e| {
            RpcError::ValidationError(ValidationError::Custom(format!(
                "Invalid JSON RPC request: {e}"
            )))
        })?;
    resolved_service
        .post(&get_override_provider())?
        .max_response_bytes(max_response_bytes)
        .transform_context(TransformContext {
            function: TransformFunc(candid::Func {
                method: "__transform_json_rpc".to_string(),
                principal: ic_cdk::api::canister_self(),
            }),
            context: vec![],
        })
        .body(body)
        .map(|mut request| {
            request.extensions_mut().insert(service);
            request.extensions_mut().insert(MetricRpcMethod {
                method: "request".to_string(),
                is_manual_request: true,
            });
            request
        })
        .map_err(|e| {
            RpcError::ValidationError(ValidationError::Custom(format!("Invalid request: {e}")))
        })
}
