use crate::{
    common::{make_plaintext_response, CONTENT_TYPE_HTML, CONTENT_TYPE_PROTOBUF},
    EndpointService,
};

use axum::body::Body;
use futures_util::Future;
use http::{header, request::Parts, Request};
use http_body_util::{BodyExt, Full};
use hyper::{self, Response, StatusCode};
use ic_pprof::{Error, PprofCollector};
use std::{
    collections::HashMap,
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tower::{
    limit::GlobalConcurrencyLimitLayer, util::BoxCloneService, BoxError, Service, ServiceBuilder,
};

pub const CONTENT_TYPE_SVG: &str = "image/svg+xml";
/// Default CPU profile duration.
pub const DEFAULT_DURATION_SECONDS: u64 = 30;
/// Default sampling frequency. 250Hz is the default Linux software clock
/// frequency.
pub const DEFAULT_FREQUENCY: i32 = 250;

/// `/_/pprof` root page, listing the available profiles.
const PPROF_HOME_HTML: &str = r#"<html>
<head>
<title>/_/pprof/</title>
<style>
.profile-name{
        display:inline-block;
        width:6rem;
}
</style>
</head>
<body>
/_/pprof/<br>
<br>
Types of profiles available:
<ul>
<li><div class=profile-name><a href=pprof/profile>profile</a>:</div> CPU profile in pprof protobuf format. You can specify the duration in the <code>seconds</code> query parameter, and the frequency via the <code>frequency</code> parameter. After you get the profile file, use the <code>go tool pprof</code> command to investigate the profile.</li>
<li><div class=profile-name><a href=pprof/flamegraph>flamegraph</a>:</div> CPU profile in flamegraph SVG format. You can specify the duration in the <code>seconds</code> query parameter, and the frequency via the <code>frequency</code> parameter.</li>
</ul>
</p>
</body>
</html>"#;

fn query(parts: Parts) -> Result<(Duration, i32), String> {
    let query_pairs: HashMap<_, _> = match parts.uri.query() {
        Some(query) => url::form_urlencoded::parse(query.as_bytes()).collect(),
        None => Default::default(),
    };

    let seconds: u64 = match query_pairs.get("seconds") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => {
                return Err(err.to_string());
            }
        },
        None => DEFAULT_DURATION_SECONDS,
    };
    let duration = Duration::from_secs(seconds);

    let frequency: i32 = match query_pairs.get("frequency") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => {
                return Err(err.to_string());
            }
        },
        None => DEFAULT_FREQUENCY,
    };
    Ok((duration, frequency))
}

/// Converts an `ic_pprof::profile()` output into an HTTP response.
fn into_response(result: Result<Vec<u8>, Error>, content_type: &'static str) -> Response<Body> {
    match result {
        Ok(body) => ok_response(body, content_type),
        Err(err) => make_plaintext_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// Converts a successful `ic_pprof::profile()` output into an HTTP response.
fn ok_response(body: Vec<u8>, content_type: &'static str) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::new(Full::from(body).map_err(BoxError::from)))
        .unwrap();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response
}

/// Returns the `/_/pprof` root page, listing the available profiles.
#[derive(Clone)]
pub(crate) struct PprofHomeService;

impl PprofHomeService {
    pub fn new_service(concurrency_limiter: GlobalConcurrencyLimitLayer) -> EndpointService {
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(concurrency_limiter)
                .service(Self),
        )
    }
}

impl Service<Request<Body>> for PprofHomeService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _unused: Request<Body>) -> Self::Future {
        let mut response = Response::new(Body::new(
            PPROF_HOME_HTML.to_string().map_err(BoxError::from),
        ));
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static(CONTENT_TYPE_HTML),
        );

        Box::pin(async move { Ok(response) })
    }
}

#[derive(Clone)]
pub(crate) struct PprofProfileService {
    collector: Arc<dyn PprofCollector>,
}

impl PprofProfileService {
    pub fn new_service(
        collector: Arc<dyn PprofCollector>,
        concurrency_limiter: GlobalConcurrencyLimitLayer,
    ) -> EndpointService {
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(concurrency_limiter)
                .service(Self { collector }),
        )
    }
}

impl Service<Request<Body>> for PprofProfileService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Collects a CPU profile in `pprof` or flamegraph format.
    ///
    /// Supported query arguments are `seconds`, for the duration of the CPU
    /// profile; and `frequency`, for the frequency at whicn stack trace samples
    /// should be collected.
    ///
    /// `frequency` and its accuracy are limited (on Linux) by the resolution of
    /// the software clock, which is 250Hz by default. See
    /// [`man 7 time`](https://linux.die.net/man/7/time) for details.
    fn call(&mut self, body: Request<Body>) -> Self::Future {
        let parts = body.into_parts().0;
        let collector = self.collector.clone();

        Box::pin(async move {
            Ok(match query(parts) {
                Ok((duration, frequency)) => into_response(
                    collector.profile(duration, frequency).await,
                    CONTENT_TYPE_PROTOBUF,
                ),
                Err(err) => make_plaintext_response(StatusCode::BAD_REQUEST, err),
            })
        })
    }
}

#[derive(Clone)]
pub(crate) struct PprofFlamegraphService {
    collector: Arc<dyn PprofCollector>,
}

impl PprofFlamegraphService {
    pub fn new_service(
        collector: Arc<dyn PprofCollector>,
        concurrency_limiter: GlobalConcurrencyLimitLayer,
    ) -> EndpointService {
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(concurrency_limiter)
                .service(Self { collector }),
        )
    }
}

impl Service<Request<Body>> for PprofFlamegraphService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, body: Request<Body>) -> Self::Future {
        let parts = body.into_parts().0;
        let collector = self.collector.clone();

        Box::pin(async move {
            Ok(match query(parts) {
                Ok((duration, frequency)) => into_response(
                    collector.flamegraph(duration, frequency).await,
                    CONTENT_TYPE_SVG,
                ),
                Err(err) => make_plaintext_response(StatusCode::BAD_REQUEST, err),
            })
        })
    }
}
