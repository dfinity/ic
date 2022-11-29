use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::bail;
use axum::{extract::ConnectInfo, Extension};
use futures::StreamExt;
use http_body::{LengthLimitError, Limited};
use hyper::{
    body,
    http::header::{HeaderName, CONTENT_TYPE},
    Body, Request, Response, StatusCode, Uri,
};
use ic_agent::{agent_error::HttpErrorPayload, Agent, AgentError};
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::http_request::{
        HeaderField, HttpRequestCanister, HttpRequestStreamingCallbackAny, HttpResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    },
};
use tracing::{enabled, instrument, trace, warn, Level};

use crate::{
    canister_id::Resolver as CanisterIdResolver,
    headers::extract_headers_data,
    proxy::{HandleError, REQUEST_BODY_SIZE_LIMIT},
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

pub struct ArgsInner {
    pub validator: Box<dyn Validate>,
    pub resolver: Box<dyn CanisterIdResolver>,
    pub counter: AtomicUsize,
    pub replicas: Vec<(Agent, Uri)>,
    pub debug: bool,
}

pub struct Args {
    args: Arc<ArgsInner>,
    current: usize,
}

impl Clone for Args {
    fn clone(&self) -> Self {
        let args = self.args.clone();
        Args {
            current: args.counter.fetch_add(1, Ordering::Relaxed) % args.replicas.len(),
            args,
        }
    }
}

impl From<ArgsInner> for Args {
    fn from(args: ArgsInner) -> Self {
        Args {
            args: Arc::new(args),
            current: 0,
        }
    }
}
impl Args {
    fn replica(&self) -> (&Agent, &Uri) {
        let v = &self.args.replicas[self.current];
        (&v.0, &v.1)
    }
}

#[instrument(level = "info", skip_all, fields(addr = display(addr), replica = display(args.replica().1)))]
pub async fn handler(
    Extension(args): Extension<Args>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let agent = args.replica().0;
    let args = &args.args;
    process_request_inner(
        request,
        agent,
        args.resolver.as_ref(),
        args.validator.as_ref(),
    )
    .await
    .handle_error(args.debug)
}

async fn process_request_inner(
    request: Request<Body>,
    agent: &Agent,
    resolver: &dyn CanisterIdResolver,
    validator: &dyn Validate,
) -> Result<Response<Body>, anyhow::Error> {
    let (parts, body) = request.into_parts();

    let canister_id = match resolver.resolve(&parts) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Could not find a canister id to forward to.".into())
                .unwrap())
        }
        Some(x) => x,
    };
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

    let canister = HttpRequestCanister::create(agent, canister_id);
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
            agent,
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
