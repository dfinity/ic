use std::sync::Arc;

use axum::{body::Body, extract::State, middleware::Next, response::IntoResponse, Extension};
use bytes::Bytes;
use http::{request::Parts, Request, StatusCode};
use hyper::body;
use ic_types::{CanisterId, SubnetId};

use crate::{
    http::AxumResponse,
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
fn request_needs_retrying(response: &AxumResponse) -> bool {
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

/// Clones the request from components
fn request_clone(parts: &Parts, body: &Bytes) -> Request<Body> {
    let mut request = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version)
        .body(body::Body::from(body.clone()))
        .unwrap();

    *request.headers_mut() = parts.headers.clone();

    // Extensions design in http crate 0.x sucks - there's no way to iterate over them,
    // though they're stored in a hash map. Nor there's a way to clone them (at least until http 1.0.0 crate)
    //
    // TODO upgrade to 1.0.0 at some point, for now we just manually copy the following extensions that have
    // to be present. This must be kept in sync with whatever extensions we inject into the request before retry middleware.

    request.extensions_mut().insert(
        parts
            .extensions
            .get::<Arc<RequestContext>>()
            .unwrap()
            .clone(),
    );

    if let Some(canister_id) = parts.extensions.get::<CanisterId>().cloned() {
        request.extensions_mut().insert(canister_id);
    }
    if let Some(subnet_id) = parts.extensions.get::<SubnetId>().cloned() {
        request.extensions_mut().insert(subnet_id);
    }
    if let Some(route_subnet) = parts.extensions.get::<Arc<RouteSubnet>>().cloned() {
        request.extensions_mut().insert(route_subnet);
    }

    request
}

// Middleware that optionally retries the request according to the predefined conditions
pub async fn retry_request(
    State(params): State<RetryParams>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<RouteSubnet>>,
    mut request: Request<Body>,
    next: Next<Body>,
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

    // TODO after migrating to http 1.0.0 crate use built-in cloning
    //
    // Deconstruct the request to be able to clone it
    let (parts, body) = request.into_parts();
    // This cannot fail since the body is not streaming and is just an in-memory buffer
    let body = body::to_bytes(body).await.unwrap();

    let mut response_last: Option<AxumResponse> = None;
    let mut node_last: Option<Arc<Node>> = None;
    let mut retry_result = RetryResult {
        retries: 0,
        success: false,
    };

    for node in nodes.into_iter() {
        let mut request = request_clone(&parts, &body);
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
