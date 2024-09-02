use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::bail;
use axum::body::Body;
use axum::extract::{FromRef, State};
use bytes::Bytes;
use candid::Principal;
use http::header::{HeaderValue, HOST};
use hyper::{Request, Response, StatusCode, Uri};
use ic_agent::{
    agent::{Agent, RejectCode, RejectResponse},
    AgentError,
};
use ic_response_verification::MAX_VERIFICATION_VERSION;
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::http_request::{HeaderField, HttpRequestCanister},
};
use tracing::{instrument, Span};

use crate::{
    canister_id,
    error::ErrorFactory,
    http::{
        headers::{ACCEPT_ENCODING_HEADER_NAME, CACHE_HEADER_NAME},
        request::HttpRequest,
        response::{AgentResponseAny, HttpResponse},
    },
    http_client::{
        RequestHeaders, HEADER_IC_CANISTER_ID, HEADER_X_IC_COUNTRY_CODE, HEADER_X_REAL_IP,
        HEADER_X_REQUEST_ID, REQUEST_HEADERS,
    },
    metrics::RequestContext,
    proxy::{denylist::Denylist, geoip::GeoIp, AppState, DomainCanisterMatcher, HandleError},
    validate::Validate,
};

pub struct Args<V> {
    agent: Agent,
    domain_match: Option<Arc<DomainCanisterMatcher>>,
    geoip: Option<Arc<GeoIp>>,
    denylist: Option<Arc<Denylist>>,
    validator: V,
    debug: bool,
}

pub struct Pool {
    counter: AtomicUsize,
    replicas: Box<[(Agent, Arc<Uri>)]>,
}

impl Pool {
    pub fn new(replicas: impl IntoIterator<Item = (Agent, Uri)>) -> Self {
        Pool {
            counter: AtomicUsize::new(0),
            replicas: replicas
                .into_iter()
                .map(|(agent, uri)| (agent, Arc::new(uri)))
                .collect(),
        }
    }
}
impl<V: Clone> FromRef<AppState<V>> for Args<V> {
    fn from_ref(state: &AppState<V>) -> Self {
        let agent = if let Some(v) = &state.0.agent {
            v.clone()
        } else {
            let pool = state.pool();
            let counter = pool.counter.fetch_add(1, Ordering::Relaxed) % pool.replicas.len();
            let (agent, _) = pool.replicas[counter].clone();
            agent
        };

        Args {
            agent,
            domain_match: state.domain_match(),
            validator: state.validator().clone(),
            geoip: state.geoip(),
            denylist: state.denylist(),
            debug: state.debug(),
        }
    }
}

#[instrument(
    level = "error",
    parent = None,
    target = "",
    skip_all,
    fields(
        request_id,
        canister_id,
        client_ip,
        country_code,
        method,
        uri,
        code,
        req_len,
        resp_len,
        stream,
        error
    )
)]
pub async fn handler<V: Validate + 'static>(
    State(args): State<Args<V>>,
    uri_canister_id: Option<canister_id::UriHost>,
    host_canister_id: Option<canister_id::HostHeader>,
    query_param_canister_id: Option<canister_id::QueryParam>,
    referer_host_canister_id: Option<canister_id::RefererHeaderHost>,
    referer_query_param_canister_id: Option<canister_id::RefererHeaderQueryParam>,
    request: Request<Body>,
) -> Response<Body> {
    let uri_canister_id = uri_canister_id.map(|v| v.0);
    let host_canister_id = host_canister_id.map(|v| v.0);
    let query_param_canister_id = query_param_canister_id.map(|v| v.0);
    let referer_host_canister_id = referer_host_canister_id.map(|v| v.0);
    let referer_query_param_canister_id = referer_query_param_canister_id.map(|v| v.0);

    let canister_id = uri_canister_id
        .or(host_canister_id)
        .or(query_param_canister_id)
        .or(referer_host_canister_id)
        .or(referer_query_param_canister_id);

    let span = Span::current();
    span.record("method", request.method().as_str());
    span.record("uri", request.uri().to_string());

    let request_id = request
        .headers()
        .get(HEADER_X_REQUEST_ID)
        .cloned()
        .map(|x| x.to_str().unwrap_or("<malformed id>").to_string())
        .unwrap_or("<unknown id>".into());
    span.record("request_id", &request_id);

    // Try to get & parse client IP from the header
    let client_ip = request
        .headers()
        .get(HEADER_X_REAL_IP)
        .and_then(|x| x.to_str().ok().and_then(|x| x.parse::<IpAddr>().ok()));

    let country_code = client_ip
        .and_then(|x| args.geoip.as_ref().map(|v| v.lookup(x)))
        .unwrap_or("N/A".into());

    span.record(
        "client_ip",
        client_ip.map(|x| x.to_string()).unwrap_or("unknown".into()),
    );
    span.record("country_code", &country_code);

    // Initialize task local variable and process the request
    let res = REQUEST_HEADERS
        .scope(RequestHeaders::new(), async {
            process_request(request, &args, canister_id, &country_code).await
        })
        .await;

    let mut res = res.handle_error(args.debug);
    res.headers_mut().insert(
        HEADER_X_IC_COUNTRY_CODE,
        HeaderValue::from_maybe_shared(Bytes::from(country_code)).unwrap(),
    );

    if let Some(v) = canister_id {
        res.headers_mut().insert(
            HEADER_IC_CANISTER_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
        );
    }

    res
}

async fn process_request<V: Validate + 'static>(
    request: Request<Body>,
    args: &Args<V>,
    canister_id: Option<Principal>,
    country_code: &str,
) -> Result<Response<Body>, anyhow::Error> {
    let agent = &args.agent;
    let span = Span::current();

    if canister_id.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Could not find a canister id to forward to".into())
            .unwrap());
    }

    let canister_id = canister_id.unwrap();
    span.record("canister_id", canister_id.to_string());

    if let Some(v) = &args.denylist {
        if v.is_blocked(canister_id, country_code) {
            return Ok(Response::builder()
                .status(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
                .body("".into())
                .unwrap());
        }
    }

    let (parts, body) = request.into_parts();

    let host = parts.headers.get(HOST).and_then(|x| x.to_str().ok());
    let host = match host {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Host header is missing or corrupt".into())
                .unwrap());
        }

        Some(x) => x,
    };

    // Check the domain-canister match if configured
    if let Some(v) = &args.domain_match {
        if !v.check(canister_id, host) {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("".into())
                .unwrap());
        }
    }

    // Store the request headers in task local storage
    REQUEST_HEADERS.with(|x| {
        x.borrow_mut().headers_out = parts.headers.clone();
    });

    let body = match HttpRequest::read_body(body).await {
        Ok(data) => data,
        Err(ErrorFactory::PayloadTooLarge) => {
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("Request size exceeds limit"))?)
        }
        Err(e) => bail!(e),
    };

    span.record("req_len", body.len());

    let http_request = HttpRequest::from((&parts, body));

    let canister = HttpRequestCanister::create(agent, canister_id);
    let header_fields = http_request
        .headers
        .iter()
        .filter(|(name, _)| name != "x-request-id")
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case(ACCEPT_ENCODING_HEADER_NAME) {
                let mut encodings = value.split(',').map(|s| s.trim()).collect::<Vec<_>>();
                if !encodings.iter().any(|s| s.eq_ignore_ascii_case("identity")) {
                    encodings.push("identity");
                };

                let value = encodings.join(", ");
                return HeaderField(name.into(), value.into());
            }

            HeaderField(name.into(), value.into())
        })
        .collect::<Vec<_>>() // it needs to be an ExactSizeIterator
        .into_iter();

    let query_result = canister
        .http_request_custom(
            &http_request.method,
            http_request.uri.to_string().as_str(),
            header_fields.clone(),
            &http_request.body,
            Some(&u16::from(MAX_VERIFICATION_VERSION)),
        )
        .call()
        .await;

    let agent_response = match handle_result(query_result) {
        Ok(http_response) => http_response,
        Err(response_or_error) => return response_or_error,
    };

    let is_update_call = agent_response.upgrade == Some(true);
    let agent_response = if is_update_call {
        let update_result = canister
            .http_request_update_custom(
                &http_request.method,
                http_request.uri.to_string().as_str(),
                header_fields.clone(),
                &http_request.body,
            )
            .call_and_wait()
            .await;
        match handle_result(update_result) {
            Ok(http_response) => http_response,
            Err(response_or_error) => return response_or_error,
        }
    } else {
        agent_response
    };

    span.record("resp_len", agent_response.body.len());

    let http_response = HttpResponse::create(agent, &agent_response).await?;
    span.record("stream", http_response.has_streaming_body);

    let mut response_builder =
        Response::builder().status(StatusCode::from_u16(http_response.status_code)?);

    // At the moment verification is only performed if the response is not using a streaming
    // strategy. Performing verification for those requests would required to join all the chunks
    // and this could cause memory issues and possibly create DOS attack vectors.
    let should_validate = !http_response.has_streaming_body && !is_update_call;
    let validation_info = if should_validate {
        let validation_result =
            args.validator
                .validate(agent, &canister_id, &http_request, &http_response);

        match validation_result {
            Err(err) => {
                span.record("error", format!("Request validation failed: {err}"));

                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(err.into())
                    .unwrap());
            }
            Ok(validation_info) => validation_info,
        }
    } else {
        None
    };

    match validation_info {
        // if there is no validation info, that means we've skipped verification,
        // this should only happen for raw domains,
        // return response as-is
        None => {
            for (name, value) in &http_response.headers {
                response_builder = response_builder.header(name, value);
            }
        }

        Some(validation_info) => {
            if validation_info.verification_version < 2 {
                // status codes are not certified in v1, reject known dangerous status codes
                if http_response.status_code >= 300 && http_response.status_code < 400 {
                    let msg = "Response verification v1 does not allow redirects";
                    span.record("error", msg);

                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(msg.into())
                        .unwrap());
                }

                // headers are also not certified in v1, filter known dangerous headers
                for (name, value) in &http_response.headers {
                    if !name.eq_ignore_ascii_case(CACHE_HEADER_NAME) {
                        response_builder = response_builder.header(name, value);
                    }
                }
            } else {
                match validation_info.response {
                    // if there is no response, the canister has decided to certifiably skip verification,
                    // assume the developer knows what they're doing and return the response as-is
                    None => {
                        for (name, value) in &http_response.headers {
                            response_builder = response_builder.header(name, value);
                        }
                    }
                    // if there is a response, the canister has decided to certify some (but not necessarily all) headers,
                    // return only the certified headers
                    Some(certified_http_response) => {
                        for (name, value) in &certified_http_response.headers {
                            response_builder = response_builder.header(name, value);
                        }
                    }
                }
            }
        }
    }

    let mut response = response_builder
        .header(
            "X-IC-Streaming-Response",
            http_response.has_streaming_body.to_string(),
        )
        .body(match http_response.streaming_body {
            Some(body) => body,
            None => Body::from(http_response.body),
        })?;

    // Extract response headers from task local storage
    REQUEST_HEADERS.with(|x| {
        for (k, v) in x.borrow().headers_in.iter() {
            response.headers_mut().insert(k, v.clone());
        }
    });

    // Create per-request context
    let ctx = RequestContext {
        request_size: http_request.body.len() as u64,
        streaming_request: http_response.has_streaming_body,
    };

    // Inject it into response
    response.extensions_mut().insert(ctx);

    Ok(response)
}

fn handle_result(
    result: Result<(AgentResponseAny,), AgentError>,
) -> Result<AgentResponseAny, Result<Response<Body>, anyhow::Error>> {
    use AgentError::{CertifiedReject, ResponseSizeExceededLimit, UncertifiedReject};
    use RejectCode::DestinationInvalid;

    let result = match result {
        Ok((http_response,)) => {
            return Ok(http_response);
        }
        Err(e) => e,
    };

    let span = Span::current();

    let response = match result {
        // Turn all `DestinationInvalid`s into 404
        CertifiedReject(RejectResponse {
            reject_code: DestinationInvalid,
            reject_message,
            ..
        }) => {
            span.record("error", format!("Destination invalid: {reject_message}"));

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(reject_message.into())
                .unwrap()
        }

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        CertifiedReject(response) => {
            let msg = format!(
                "Replica Error: reject code {:?}, message {}, error code {:?}",
                response.reject_code, response.reject_message, response.error_code,
            );

            span.record("error", &msg);

            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(msg.into())
                .unwrap()
        }

        UncertifiedReject(RejectResponse {
            reject_code: DestinationInvalid,
            reject_message,
            ..
        }) => {
            span.record("error", format!("Destination invalid: {reject_message}"));

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(reject_message.into())
                .unwrap()
        }

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        UncertifiedReject(response) => {
            let msg = format!(
                "Replica Error: reject code {:?}, message {}, error code {:?}",
                response.reject_code, response.reject_message, response.error_code,
            );

            span.record("error", &msg);

            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(msg.into())
                .unwrap()
        }

        ResponseSizeExceededLimit() => {
            span.record("error", "Response size exceeds limit");

            Response::builder()
                .status(StatusCode::INSUFFICIENT_STORAGE)
                .body("Response size exceeds limit".into())
                .unwrap()
        }

        // Handle all other errors
        e => {
            return Err(Err(e.into()));
        }
    };

    Err(Ok(response))
}
