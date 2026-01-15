// TODO(MR-683): Address the regression and re-enable.
#![allow(dead_code, unused_variables)]

use crate::common::{CONTENT_TYPE_PROTOBUF, CONTENT_TYPE_SVG};

use axum::{
    Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use http::header;
use hyper::{self, StatusCode};
use ic_pprof::PprofCollector;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

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
<b>Temporarily disabled due to a regression.</b><br>
<br>
Types of profiles available:
<ul>
<li><div class=profile-name><a href="/_/pprof/profile">profile</a>:</div> CPU profile in pprof protobuf format. You can specify the duration in the <code>seconds</code> query parameter, and the frequency via the <code>frequency</code> parameter. After you get the profile file, use the <code>go tool pprof</code> command to investigate the profile.</li>
<li><div class=profile-name><a href="/_/pprof/flamegraph">flamegraph</a>:</div> CPU profile in flamegraph SVG format. You can specify the duration in the <code>seconds</code> query parameter, and the frequency via the <code>frequency</code> parameter.</li>
</ul>
</p>
</body>
</html>"#;

/// Returns the `/_/pprof` root page, listing the available profiles.
#[derive(Clone)]
pub(crate) struct PprofHomeService;

impl PprofHomeService {
    pub fn route() -> &'static str {
        "/_/pprof"
    }
    pub fn new_router() -> Router {
        Router::new().route(
            Self::route(),
            axum::routing::get(|| async { Html(PPROF_HOME_HTML) }),
        )
    }
}

#[derive(Clone)]
pub(crate) struct PprofProfileService {
    collector: Arc<dyn PprofCollector>,
}

impl PprofProfileService {
    pub fn route() -> &'static str {
        "/_/pprof/profile"
    }
    pub fn new_router(collector: Arc<dyn PprofCollector>) -> Router {
        let state = PprofProfileService { collector };
        Router::new().route(
            Self::route(),
            // TODO(MR-683): Address the regression and re-enable.
            // axum::routing::get(pprof_profile).with_state(state),
            axum::routing::get(|| async { Html(PPROF_HOME_HTML) }),
        )
    }
}

#[derive(Deserialize)]
pub(crate) struct PprofParams {
    frequency: Option<i32>,
    seconds: Option<u64>,
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
async fn pprof_profile(
    Query(params): Query<PprofParams>,
    State(PprofProfileService { collector }): State<PprofProfileService>,
) -> impl IntoResponse {
    match collector
        .profile(
            Duration::from_secs(params.seconds.unwrap_or(DEFAULT_DURATION_SECONDS)),
            params.frequency.unwrap_or(DEFAULT_FREQUENCY),
        )
        .await
    {
        Ok(v) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)],
            v,
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[derive(Clone)]
pub(crate) struct PprofFlamegraphService {
    collector: Arc<dyn PprofCollector>,
}

impl PprofFlamegraphService {
    pub fn route() -> &'static str {
        "/_/pprof/flamegraph"
    }
    pub fn new_router(collector: Arc<dyn PprofCollector>) -> Router {
        let state = PprofFlamegraphService { collector };
        Router::new().route(
            Self::route(),
            // TODO(MR-683): Address the regression and re-enable.
            // axum::routing::get(pprof_flamegraph).with_state(state),
            axum::routing::get(|| async { Html(PPROF_HOME_HTML) }),
        )
    }
}

pub(crate) async fn pprof_flamegraph(
    Query(params): Query<PprofParams>,
    State(PprofFlamegraphService { collector }): State<PprofFlamegraphService>,
) -> impl IntoResponse {
    match collector
        .flamegraph(
            Duration::from_secs(params.seconds.unwrap_or(DEFAULT_DURATION_SECONDS)),
            params.frequency.unwrap_or(DEFAULT_FREQUENCY),
        )
        .await
    {
        Ok(v) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, CONTENT_TYPE_SVG)],
            v,
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}
