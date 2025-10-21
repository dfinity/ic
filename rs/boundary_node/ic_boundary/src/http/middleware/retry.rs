use std::sync::Arc;

use axum::{
    Extension,
    body::{Body, to_bytes},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;

use crate::{
    errors::{ApiError, ErrorCause},
    routes::RequestContext,
    snapshot::{Node, Subnet},
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
    Extension(subnet): Extension<Arc<Subnet>>,
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
mod test {
    use super::*;

    use std::{
        str::FromStr,
        sync::{Arc, RwLock},
    };

    use anyhow::Error;
    use axum::{
        Router, body::Body, extract::State, http::Request, middleware, response::IntoResponse,
        routing::method_routing::post,
    };
    use http::StatusCode;
    use ic_bn_lib::principal;
    use ic_types::CanisterId;
    use tower::Service;

    use crate::{
        http::RequestType,
        persist::test::{generate_test_subnets, node},
    };

    struct TestState {
        failures: u8,
        fail_code: StatusCode,
        error_cause: Option<ErrorCause>,
    }

    fn gen_request(request_type: RequestType) -> Request<Body> {
        let ctx = RequestContext {
            request_type,
            canister_id: Some(principal!("f7crg-kabae")),
            sender: Some(principal!("f7crg-kabae")),
            method_name: Some("foo".into()),
            ingress_expiry: Some(1),
            arg: Some(vec![1, 2, 3, 4]),
            ..Default::default()
        };

        let ctx = Arc::new(ctx);

        let mut subnet = generate_test_subnets(0)[0].clone();
        subnet.nodes = vec![];
        for i in 0..10 {
            subnet.nodes.push(node(i, subnet.id))
        }

        let mut req = Request::post("/").body(Body::from("foobar")).unwrap();
        req.extensions_mut().insert(ctx);
        req.extensions_mut()
            .insert(CanisterId::from_str("f7crg-kabae").unwrap());
        req.extensions_mut().insert(Arc::new(subnet));

        req
    }

    // Generate a response
    async fn handler(State(state): State<Arc<RwLock<TestState>>>) -> impl IntoResponse {
        let mut s = state.write().unwrap();

        let mut resp = "foobar".into_response();

        if let Some(v) = &s.error_cause {
            resp.extensions_mut().insert(v.clone());
        }

        if s.failures > 0 {
            s.failures -= 1;
            *resp.status_mut() = s.fail_code;
        }

        resp
    }

    #[tokio::test]
    async fn test_retry() -> Result<(), Error> {
        let state = Arc::new(RwLock::new(TestState {
            failures: 2,
            fail_code: StatusCode::INTERNAL_SERVER_ERROR,
            error_cause: None,
        }));

        let mut app = Router::new()
            .route("/", post(handler).with_state(state.clone()))
            .layer(middleware::from_fn_with_state(
                RetryParams {
                    retry_count: 3,
                    retry_update_call: false,
                    disable_latency_routing: true,
                },
                retry_request,
            ));

        // Check successful retry
        let req = gen_request(RequestType::QueryV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Check retries exhaustion
        {
            state.write().unwrap().failures = 4;
        }

        let req = gen_request(RequestType::QueryV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Check non-retriable status code
        {
            state.write().unwrap().failures = 2;
            state.write().unwrap().fail_code = StatusCode::BAD_REQUEST;
        }

        let req = gen_request(RequestType::QueryV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Check update call not retried
        {
            state.write().unwrap().failures = 2;
            state.write().unwrap().fail_code = StatusCode::INTERNAL_SERVER_ERROR;
        }

        let req = gen_request(RequestType::CallV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Check retriable ErrorCause
        {
            state.write().unwrap().failures = 2;
            state.write().unwrap().error_cause = Some(ErrorCause::ReplicaErrorConnect);
        }

        let req = gen_request(RequestType::QueryV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Check non-retriable ErrorCause
        {
            state.write().unwrap().failures = 2;
            state.write().unwrap().error_cause = Some(ErrorCause::PayloadTooLarge(123));
        }

        let req = gen_request(RequestType::QueryV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Check update call retried
        let mut app = Router::new()
            .route("/", post(handler).with_state(state.clone()))
            .layer(middleware::from_fn_with_state(
                RetryParams {
                    retry_count: 3,
                    retry_update_call: true,
                    disable_latency_routing: true,
                },
                retry_request,
            ));

        {
            state.write().unwrap().failures = 2;
            state.write().unwrap().error_cause = None;
        }

        let req = gen_request(RequestType::CallV2);
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }
}
