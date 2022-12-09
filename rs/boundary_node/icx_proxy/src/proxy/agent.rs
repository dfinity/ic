use std::{
    borrow::Borrow,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::bail;
use axum::extract::{ConnectInfo, FromRef, State};
use futures::StreamExt;
use http_body::{LengthLimitError, Limited};
use hyper::{
    body,
    http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Body, Request, Response, StatusCode, Uri,
};
use ic_agent::{agent_error::HttpErrorPayload, export::Principal, Agent, AgentError};
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::http_request::{
        HeaderField, HttpRequestCanister, HttpRequestStreamingCallbackAny, HttpResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    },
};
use tracing::{enabled, info, instrument, trace, warn, Level};

use crate::{
    canister_id,
    headers::extract_headers_data,
    proxy::{AppState, HandleError, HyperService, REQUEST_BODY_SIZE_LIMIT},
    validate::Validate,
};

type HttpResponseAny = HttpResponse<Token, HttpRequestStreamingCallbackAny>;

// Limit the total number of calls to an HTTP Request loop to 1000 for now.
const MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT: usize = 1000;

// Limit the number of Stream Callbacks buffered
const STREAM_CALLBACK_BUFFFER: usize = 2;

// The maximum length of a body we should log as tracing.
const MAX_LOG_BODY_SIZE: usize = 100;

static REQUIRE_CERTIFICATION_HEADER: HeaderName =
    HeaderName::from_static("x-icx-require-certification");

/// https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes
struct ReplicaErrorCodes;
impl ReplicaErrorCodes {
    const DESTINATION_INVALID: u64 = 3;
}
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

#[instrument(level = "info", skip_all, fields(addr = display(addr), replica = display(&*args.replica_uri)))]
pub async fn handler<V: Validate, C: HyperService<Body>>(
    State(args): State<Args<V, C>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    uri_canister_id: Option<canister_id::UriHost>,
    host_canister_id: Option<canister_id::HostHeader>,
    query_param_canister_id: Option<canister_id::QueryParam>,
    request: Request<Body>,
) -> Response<Body> {
    let uri_canister_id = uri_canister_id.map(|v| v.0);
    let host_canister_id = host_canister_id.map(|v| v.0);
    let query_param_canister_id = query_param_canister_id.map(|v| v.0);
    process_request_inner(
        request,
        addr,
        args.agent,
        &args.replica_uri,
        args.validator,
        args.client,
        uri_canister_id
            .or(host_canister_id)
            .or(query_param_canister_id),
    )
    .await
    .handle_error(args.debug)
}

async fn process_request_inner(
    request: Request<Body>,
    addr: SocketAddr,
    agent: Agent,
    replica_uri: &Uri,
    validator: impl Validate,
    mut client: impl HyperService<Body>,
    canister_id: Option<Principal>,
) -> Result<Response<Body>, anyhow::Error> {
    let canister_id = match canister_id {
        None => {
            if request.uri().path().starts_with("/api") {
                info!("forwarding");
                let proxied_request =
                    create_proxied_request(&addr.ip(), replica_uri.clone(), request)?;
                let response = client.call(proxied_request).await?;
                let (parts, body) = response.into_parts();
                return Ok(Response::from_parts(parts, body.into()));
            } else {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Could not find a canister id to forward to.".into())
                    .unwrap());
            }
        }
        Some(canister_id) => canister_id,
    };
    let (parts, body) = request.into_parts();
    let certification_required = parts.headers.contains_key(&REQUIRE_CERTIFICATION_HEADER);

    trace!("<< {} {} {:?}", parts.method, parts.uri, parts.version);

    let method = parts.method;
    let uri = parts.uri.to_string();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some(HeaderField(
                name.as_str().into(),
                value.to_str().ok()?.into(),
            ))
        })
        .inspect(|HeaderField(name, value)| {
            trace!("<< {}: {}", name, value);
        })
        .collect::<Vec<_>>();

    // Limit request body size
    let body = Limited::new(body, REQUEST_BODY_SIZE_LIMIT);
    let entire_body = match body::to_bytes(body).await {
        Ok(data) => data,
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("Request size exceeds limit"))?);
            }
            bail!("Failed to read body: {err}");
        }
    }
    .to_vec();

    trace!("<<");
    if enabled!(Level::TRACE) {
        let body = String::from_utf8_lossy(
            &entire_body[0..usize::min(entire_body.len(), MAX_LOG_BODY_SIZE)],
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

    let canister = HttpRequestCanister::create(&agent, canister_id);
    let query_result = canister
        .http_request_custom(
            method.as_str(),
            uri.as_str(),
            headers.iter().cloned(),
            &entire_body,
        )
        .call()
        .await;

    fn handle_result(
        result: Result<(HttpResponseAny,), AgentError>,
    ) -> Result<HttpResponseAny, Result<Response<Body>, anyhow::Error>> {
        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        match result {
            Ok((http_response,)) => Ok(http_response),

            Err(AgentError::ReplicaError {
                reject_code: ReplicaErrorCodes::DESTINATION_INVALID,
                reject_message,
            }) => Err(Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(reject_message.into())
                .unwrap())),

            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) => Err(Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(format!(r#"Replica Error ({}): "{}""#, reject_code, reject_message).into())
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

    let http_response = match handle_result(query_result) {
        Ok(http_response) => http_response,
        Err(response_or_error) => return response_or_error,
    };

    let http_response = if http_response.upgrade == Some(true) {
        let waiter = garcon::Delay::builder()
            .throttle(Duration::from_millis(500))
            .timeout(Duration::from_secs(15))
            .build();
        let update_result = canister
            .http_request_update_custom(
                method.as_str(),
                uri.as_str(),
                headers.iter().cloned(),
                &entire_body,
            )
            .call_and_wait(waiter)
            .await;
        match handle_result(update_result) {
            Ok(http_response) => http_response,
            Err(response_or_error) => return response_or_error,
        }
    } else {
        http_response
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(http_response.status_code)?);
    for HeaderField(name, value) in &http_response.headers {
        builder = builder.header(name.as_ref(), value.as_ref());
    }

    let headers_data = extract_headers_data(&http_response.headers);
    let body = if enabled!(Level::TRACE) {
        Some(http_response.body.clone())
    } else {
        None
    };
    let is_streaming = http_response.streaming_strategy.is_some();
    let response = if let Some(streaming_strategy) = http_response.streaming_strategy {
        let body = http_response.body;
        let body = futures::stream::once(async move { Ok(body) });
        let body = match streaming_strategy {
            StreamingStrategy::Callback(callback) => body::Body::wrap_stream(
                body.chain(futures::stream::try_unfold(
                    (agent.clone(), callback.callback.0, Some(callback.token)),
                    move |(agent, callback, callback_token)| async move {
                        let callback_token = match callback_token {
                            Some(callback_token) => callback_token,
                            None => return Ok(None),
                        };

                        let canister = HttpRequestCanister::create(&agent, callback.principal);
                        match canister
                            .http_request_stream_callback(&callback.method, callback_token)
                            .call()
                            .await
                        {
                            Ok((StreamingCallbackHttpResponse { body, token },)) => {
                                Ok(Some((body, (agent, callback, token))))
                            }
                            Err(e) => {
                                warn!("Error happened during streaming: {}", e);
                                Err(e)
                            }
                        }
                    },
                ))
                .take(MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT)
                .map(|x| async move { x })
                .buffered(STREAM_CALLBACK_BUFFFER),
            ),
        };

        builder.body(body)?
    } else {
        let body_valid = validator.validate(
            certification_required,
            &headers_data,
            &canister_id,
            &agent,
            &parts.uri,
            &http_response.body,
        );
        if body_valid.is_err() {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body_valid.unwrap_err().into())
                .unwrap());
        }
        builder.body(http_response.body.into())?
    };

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

        let body = body.unwrap_or_else(|| b"... streaming ...".to_vec());

        trace!(">>");
        trace!(
            ">> \"{}\"{}",
            String::from_utf8_lossy(&body[..usize::min(MAX_LOG_BODY_SIZE, body.len())])
                .escape_default(),
            if is_streaming {
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
