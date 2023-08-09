use std::{
    borrow::Borrow,
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::bail;
use axum::extract::{ConnectInfo, FromRef, State};
use hyper::{
    http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Body, Request, Response, StatusCode, Uri,
};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    agent_error::HttpErrorPayload,
    export::Principal,
    Agent, AgentError,
};
use ic_response_verification::MAX_VERIFICATION_VERSION;
use ic_utils::interfaces::http_request::HeaderField;
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::http_request::HttpRequestCanister,
};
use tracing::{enabled, error, info, instrument, trace, Level};

use crate::error::ErrorFactory;
use crate::http;
use crate::http::request::HttpRequest;
use crate::http::response::{AgentResponseAny, HttpResponse};
use crate::{
    canister_id,
    proxy::{AppState, HandleError, HyperService, REQUEST_BODY_SIZE_LIMIT},
    validate::Validate,
};

// The maximum length of a body we should log as tracing.
const MAX_LOG_BODY_SIZE: usize = 100;

pub struct Args<V, C> {
    agent: Agent,
    replica_uri: Arc<Uri>,
    validator: V,
    client: C,
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
impl<V: Clone, C: Clone> FromRef<AppState<V, C>> for Args<V, C> {
    fn from_ref(state: &AppState<V, C>) -> Self {
        let pool = state.pool();
        let counter = pool.counter.fetch_add(1, Ordering::Relaxed) % pool.replicas.len();
        let (agent, replica_uri) = pool.replicas[counter].clone();
        Args {
            agent,
            replica_uri,
            validator: state.validator().clone(),
            client: state.client().clone(),
            debug: state.debug(),
        }
    }
}

fn create_proxied_request<B>(
    client_ip: &IpAddr,
    proxy_url: Uri,
    mut request: Request<B>,
) -> Result<Request<B>, anyhow::Error> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(proxy_url, &request)?;

    // Add forwarding information in the headers
    // (TODO: should we switch to `http::header::FORWARDED`?)
    static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
    request
        .headers_mut()
        .append(X_FORWARDED_FOR.clone(), client_ip.to_string().parse()?);

    Ok(request)
}

fn forward_uri<B>(proxy_url: Uri, req: &Request<B>) -> Result<Uri, anyhow::Error> {
    let mut parts = proxy_url.into_parts();
    parts.path_and_query = req.uri().path_and_query().cloned();
    Ok(Uri::from_parts(parts)?)
}

fn is_not_hop_header(name: impl Borrow<HeaderName>) -> bool {
    use hyper::http::header::*;
    // `keep-alive` is a non-standard header for H2 and beyond so it doesn't have a constant :(
    static KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

    match name.borrow() {
        &CONNECTION | &PROXY_AUTHENTICATE | &PROXY_AUTHORIZATION | &TE | &TRAILER
        | &TRANSFER_ENCODING | &UPGRADE => false,
        x => x != KEEP_ALIVE,
    }
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn remove_hop_headers(headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    headers
        .iter()
        .filter(|(k, _v)| is_not_hop_header(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

// Dive into the error chain and figure out if the underlying error was caused by an HTTP2 GOAWAY frame
fn is_h2_goaway(e: &anyhow::Error) -> bool {
    if let Some(AgentError::TransportError(e)) = e.downcast_ref::<AgentError>() {
        if let Some(e) = e.downcast_ref::<hyper::Error>() {
            let def_err = h2::Error::from(h2::Reason::INTERNAL_ERROR);

            if let Some(e) = e.source().unwrap_or(&def_err).downcast_ref::<h2::Error>() {
                return e.is_go_away();
            }
        }
    }

    false
}

// Suppresses a clippy::let_with_type_underscore lint error which only manifests on GitHub CI
// and seems unrelated to this function.
// Remove "#[allow(unknown_lints)]" to check if issue persists.
#[allow(unknown_lints)]
#[instrument(level = "info", skip_all, fields(addr = display(addr), replica = display(&*args.replica_uri)))]
pub async fn handler<V: Validate, C: HyperService<Body>>(
    State(mut args): State<Args<V, C>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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
    let referer_canister_id = referer_host_canister_id.map(|v| v.0);
    let referer_query_param_canister_id = referer_query_param_canister_id.map(|v| v.0);

    // Read the request body into a Vec
    let (parts, body) = request.into_parts();
    let body = match http::body::read_streaming_body(body, REQUEST_BODY_SIZE_LIMIT).await {
        Err(e) => {
            error!("Unable to read body: {}", e);
            return Response::builder()
                .status(500)
                .body("Error reading body".into())
                .unwrap();
        }
        Ok(b) => b,
    };

    let mut retries = 3;
    loop {
        // Create a new request based on the incoming one
        let mut request_new = Request::new(Body::from(body.clone()));
        *request_new.headers_mut() = parts.headers.clone();
        *request_new.method_mut() = parts.method.clone();
        *request_new.uri_mut() = parts.uri.clone();

        let res = process_request_inner(
            request_new,
            addr,
            &args.agent,
            &args.replica_uri,
            &args.validator,
            &mut args.client,
            uri_canister_id
                .or(host_canister_id)
                .or(query_param_canister_id)
                .or(referer_canister_id)
                .or(referer_query_param_canister_id),
        )
        .await;

        // If we have retries left - check if the underlying reason is a GOAWAY and retry if that's the case.
        // GOAWAY is issued when the server is gracefully shutting down and it will not execute the request.
        // So we can safely retry the request even if it's not idempotent since it was never worked on in case of GOAWAY.
        if retries > 0 {
            if let Err(e) = &res {
                if is_h2_goaway(e) {
                    retries -= 1;
                    info!("HTTP GOAWAY received, retrying request");
                    continue;
                }
            }
        }

        return res.handle_error(args.debug);
    }
}

async fn process_request_inner(
    request: Request<Body>,
    addr: SocketAddr,
    agent: &Agent,
    replica_uri: &Uri,
    validator: &impl Validate,
    client: &mut impl HyperService<Body>,
    canister_id: Option<Principal>,
) -> Result<Response<Body>, anyhow::Error> {
    let canister_id = match canister_id {
        None => {
            return if request.uri().path().starts_with("/api") {
                info!("forwarding");
                let proxied_request =
                    create_proxied_request(&addr.ip(), replica_uri.clone(), request)?;
                let response = client.call(proxied_request).await?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, body.into()))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Could not find a canister id to forward to.".into())
                    .unwrap())
            }
        }

        #[cfg(feature = "dev_proxy")]
        Some(_) if request.uri().path().starts_with("/api") => {
            info!("forwarding");
            let proxied_request = create_proxied_request(&addr.ip(), replica_uri.clone(), request)?;
            let response = client.call(proxied_request).await?;
            let (parts, body) = response.into_parts();
            return Ok(Response::from_parts(parts, body.into()));
        }

        Some(canister_id) => canister_id,
    };

    trace!(
        "<< {} {} {:?}",
        request.method(),
        request.uri(),
        request.version()
    );

    let (parts, body) = request.into_parts();
    let http_request = HttpRequest::from((
        &parts,
        match HttpRequest::read_body(body).await {
            Ok(data) => data,
            Err(ErrorFactory::PayloadTooLarge) => {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("Request size exceeds limit"))?)
            }
            Err(e) => bail!(e),
        },
    ));

    trace!("<<");
    if enabled!(Level::TRACE) {
        let body = String::from_utf8_lossy(
            &http_request.body[0..usize::min(http_request.body.len(), MAX_LOG_BODY_SIZE)],
        );
        trace!(
            "<< \"{}\"{}",
            &body.escape_default(),
            if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    let canister = HttpRequestCanister::create(agent, canister_id);
    let header_fields = http_request
        .headers
        .iter()
        .map(|(name, value)| HeaderField(name.into(), value.into()));

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

    let http_response = HttpResponse::from((agent, agent_response));
    let mut response_builder =
        Response::builder().status(StatusCode::from_u16(http_response.status_code)?);
    for (name, value) in &http_response.headers {
        response_builder = response_builder.header(name, value);
    }

    // At the moment verification is only performed if the response is not using a streaming
    // strategy. Performing verification for those requests would required to join all the chunks
    // and this could cause memory issues and possibly create DOS attack vectors.
    let should_validate = !http_response.has_streaming_body && !is_update_call;
    if should_validate {
        let validation = validator.validate(agent, &canister_id, &http_request, &http_response);

        if validation.is_err() {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(validation.unwrap_err().into())
                .unwrap());
        }
    }

    let response = response_builder.body(match http_response.streaming_body {
        Some(body) => body,
        None => Body::from(http_response.body.clone()),
    })?;

    if enabled!(Level::TRACE) {
        trace!(
            ">> {:?} {} {}",
            &response.version(),
            response.status().as_u16(),
            response.status().to_string()
        );

        for (name, value) in response.headers() {
            let value = String::from_utf8_lossy(value.as_bytes());
            trace!(">> {}: {}", name, value);
        }

        let body = match http_response.has_streaming_body {
            true => b"... streaming ...".to_vec(),
            false => http_response.body.clone(),
        };

        trace!(">>");
        trace!(
            ">> \"{}\"{}",
            String::from_utf8_lossy(&body[..usize::min(MAX_LOG_BODY_SIZE, body.len())])
                .escape_default(),
            if http_response.has_streaming_body {
                "... streaming".to_string()
            } else if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    Ok(response)
}

fn handle_result(
    result: Result<(AgentResponseAny,), AgentError>,
) -> Result<AgentResponseAny, Result<Response<Body>, anyhow::Error>> {
    // If the result is a Replica error, returns the 500 code and message. There is no information
    // leak here because a user could use `dfx` to get the same reply.
    match result {
        Ok((http_response,)) => Ok(http_response),

        Err(AgentError::ReplicaError(RejectResponse {
            reject_code: RejectCode::DestinationInvalid,
            reject_message,
            ..
        })) => Err(Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(reject_message.into())
            .unwrap())),

        Err(AgentError::ReplicaError(response)) => Err(Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(response.to_string().into())
            .unwrap())),

        Err(AgentError::HttpError(HttpErrorPayload {
            status: 451,
            content_type,
            content,
        })) => Err(Ok(content_type
            .into_iter()
            .fold(Response::builder(), |r, c| r.header(CONTENT_TYPE, c))
            .status(451)
            .body(content.into())
            .unwrap())),

        Err(AgentError::ResponseSizeExceededLimit()) => Err(Ok(Response::builder()
            .status(StatusCode::INSUFFICIENT_STORAGE)
            .body("Response size exceeds limit".into())
            .unwrap())),
        Err(e) => Err(Err(e.into())),
    }
}
