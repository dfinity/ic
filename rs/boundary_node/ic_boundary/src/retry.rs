use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use http::StatusCode;

use crate::{
    persist::RouteSubnet,
    routes::{ApiError, ErrorCause, RequestContext},
    snapshot::Node,
};

#[derive(Clone)]
pub struct RetryParams {
    pub retry_count: usize,
    pub retry_update_call: bool,
    pub disable_latency_routing: bool,
}

#[derive(Clone)]
pub struct RetryResult {
    // Number of retries done
    pub retries: usize,
    // If the retries made request succeed
    pub success: bool,
}

// Check if we need to retry the request based on the response that we got from lower layers
fn request_needs_retrying(response: &Response) -> bool {
    let status = response.status();

    // Retry on 429
    if status == StatusCode::TOO_MANY_REQUESTS {
        return true;
    }

    // Do not retry on other 4xx
    if status.is_client_error() {
        return false;
    }

    // Otherwise check ErrorCause, if it's missing - retry on 5xx
    match response.extensions().get::<ErrorCause>() {
        Some(v) => v.retriable(),
        None => response.status().is_server_error(),
    }
}

// Middleware that optionally retries the request according to the predefined conditions
pub async fn retry_request(
    State(params): State<RetryParams>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<RouteSubnet>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    // Select up to 1+retry_count nodes from the subnet if there are any
    let nodes = if !params.disable_latency_routing && (ctx.request_type.is_call()) {
        let factor = subnet.fault_tolerance_factor() + 1;
        subnet.pick_n_out_of_m_closest(1 + params.retry_count, factor)?
    } else {
        subnet.pick_random_nodes(1 + params.retry_count)?
    };

    // Skip retrying in certain cases
    if params.retry_count == 0 || (ctx.request_type.is_call() && !params.retry_update_call) {
        // Pick one node and pass the request down the stack
        // At this point there would be at least one node in the vector
        let node = nodes[0].clone();
        request.extensions_mut().insert(node.clone());
        let mut response = next.run(request).await;
        response.extensions_mut().insert(node);
        return Ok(response);
    }

    let mut response_last: Option<Response> = None;
    let mut node_last: Option<Arc<Node>> = None;
    let mut retry_result = RetryResult {
        retries: 0,
        success: false,
    };

    let (parts, body) = request.into_parts();
    // We don't care for the max size since the body already buffered and checked before.
    // And it cannot fail since it's already in-memory.
    let body = to_bytes(body, usize::MAX).await.unwrap();

    for node in nodes.into_iter() {
        let mut request = Request::from_parts(parts.clone(), Body::from(body.clone()));
        request.extensions_mut().insert(node.clone());
        let mut response = next.clone().run(request).await;

        // Stop if the request does not need retrying
        if !request_needs_retrying(&response) {
            if retry_result.retries > 0 {
                retry_result.success = true;
                response.extensions_mut().insert(retry_result);
            }

            response.extensions_mut().insert(node);
            return Ok(response);
        }

        response_last = Some(response);
        node_last = Some(node);
        retry_result.retries += 1;
    }

    // Return the last response if all retries failed
    let mut response = response_last.unwrap();
    response.extensions_mut().insert(retry_result);
    response.extensions_mut().insert(node_last.unwrap());

    Ok(response)
}

#[cfg(test)]
pub mod test;
