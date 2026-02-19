use crate::{
    add_metric_entry,
    http::error::{is_consensus_error, HttpClientError},
    logs::Priority,
    types::{MetricRpcMethod, MetricRpcService},
};
use canhttp::{
    http::{
        json::{
            ConsistentResponseIdFilterError, HttpJsonRpcRequest, HttpJsonRpcResponse, Id,
            JsonResponseConversionError,
        },
        FilterNonSuccessfulHttpResponseError,
    },
    HttpsOutcallError, IcError,
};
use canlog::log;
use evm_rpc_types::{LegacyRejectionCode, RpcService};
use std::fmt::Debug;

pub fn observe_http_json_rpc_request<I: Debug>(req: &HttpJsonRpcRequest<I>) -> MetricData {
    let req_data = from_request(req);
    add_metric_entry!(
        requests,
        (req_data.method.clone(), req_data.service.clone()),
        1
    );
    log!(
        Priority::TraceHttp,
        "JSON-RPC request with id `{}` to {}: {:?}",
        req_data.request_id,
        req_data.service.host,
        req.body()
    );
    req_data
}

pub fn observe_http_json_rpc_response<O: Debug>(
    req_data: MetricData,
    response: &HttpJsonRpcResponse<O>,
) {
    log!(
        Priority::TraceHttp,
        "Got response for request with id `{}`. Response with status {}: {:?}",
        req_data.request_id,
        response.status(),
        response.body()
    );
    add_status_code_metric(
        req_data.method,
        req_data.service,
        response.status().as_u16(),
    );
}

pub fn observe_http_client_error(req_data: MetricData, error: &HttpClientError) {
    match error {
        HttpClientError::IcError(error) => {
            if error.is_response_too_large() {
                add_metric_entry!(
                    err_max_response_size_exceeded,
                    (req_data.method, req_data.service),
                    1
                );
            } else if is_consensus_error(error) {
                add_metric_entry!(err_no_consensus, (req_data.method, req_data.service), 1);
            } else {
                log!(
                    Priority::TraceHttp,
                    "IC error for request with id `{}`: {}",
                    req_data.request_id,
                    error
                );
                match error {
                    IcError::CallRejected { code, .. } => {
                        add_metric_entry!(
                            err_http_outcall,
                            (
                                req_data.method,
                                req_data.service,
                                LegacyRejectionCode::from(*code)
                            ),
                            1
                        );
                    }
                    IcError::InsufficientLiquidCycleBalance { .. } => {}
                }
            }
        }

        HttpClientError::UnsuccessfulHttpResponse(
            FilterNonSuccessfulHttpResponseError::UnsuccessfulResponse(response),
        ) => {
            log!(
                Priority::TraceHttp,
                "Unsuccessful HTTP response for request with id `{}`. Response with status {}: {}",
                req_data.request_id,
                response.status(),
                String::from_utf8_lossy(response.body())
            );
            add_status_code_metric(
                req_data.method,
                req_data.service,
                response.status().as_u16(),
            );
        }
        HttpClientError::InvalidJsonResponse(
            JsonResponseConversionError::InvalidJsonResponse {
                status,
                body: _,
                parsing_error: _,
            },
        ) => {
            log!(
                Priority::TraceHttp,
                "Invalid JSON RPC response for request with id `{}`: {}",
                req_data.request_id,
                error
            );
            add_status_code_metric(req_data.method, req_data.service, *status);
        }
        HttpClientError::InvalidJsonResponseId(
            ConsistentResponseIdFilterError::InconsistentId {
                status,
                request_id: _,
                response_id: _,
            },
        ) => {
            log!(
                Priority::TraceHttp,
                "Invalid JSON RPC response for request with id `{}`: {}",
                req_data.request_id,
                error
            );
            add_status_code_metric(req_data.method, req_data.service, *status);
        }
        // TODO DEFI-2565: Improve log message once `req_data` supports JSON-RPC batch requests
        HttpClientError::InvalidJsonResponseId(
            ConsistentResponseIdFilterError::InconsistentBatchIds {
                status,
                request_ids: _,
                response_ids: _,
            },
        ) => {
            log!(
                Priority::TraceHttp,
                "Invalid JSON RPC batch response: {}",
                error
            );
            add_status_code_metric(req_data.method, req_data.service, *status);
        }
        HttpClientError::NotHandledError(e) => {
            log!(Priority::Info, "BUG: Unexpected error: {}", e);
        }
        HttpClientError::CyclesAccountingError(_) => {}
    }
}

pub struct MetricData {
    method: MetricRpcMethod,
    service: MetricRpcService,
    request_id: Id,
}

fn from_request<I>(request: &HttpJsonRpcRequest<I>) -> MetricData {
    let method = request
        .extensions()
        .get::<MetricRpcMethod>()
        .expect("`MetricRpcMethod` request extension missing")
        .clone();
    let rpc_service = request
        .extensions()
        .get::<RpcService>()
        .expect("`RpcService` request extension missing");
    let host = request
        .uri()
        .host()
        .expect("Could not extract host from request URI")
        .to_string();
    let service = MetricRpcService {
        host,
        is_supported: !matches!(rpc_service, RpcService::Custom(_)),
    };
    let request_id = request.body().id().clone();
    MetricData {
        method,
        service,
        request_id,
    }
}

fn add_status_code_metric(method: MetricRpcMethod, host: MetricRpcService, status: u16) {
    let status: u32 = status as u32;
    add_metric_entry!(responses, (method, host, status.into()), 1);
}
