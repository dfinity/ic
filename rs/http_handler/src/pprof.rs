use std::{collections::HashMap, time::Duration};

use crate::{
    common::{get_cors_headers, make_response, CONTENT_TYPE_HTML, CONTENT_TYPE_PROTOBUF},
    types::PprofPage,
};
use http::{header, request::Parts};
use hyper::{self, Body, Response, StatusCode};
use ic_pprof::{flamegraph, profile, Error};

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

/// Returns the `/_/pprof` root page, listing the available profiles.
fn home() -> Response<Body> {
    let mut response = make_response(StatusCode::OK, PPROF_HOME_HTML);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(CONTENT_TYPE_HTML),
    );
    response
}

/// Handles a call to `/_/pprof[/<profile>]`.
pub(crate) async fn handle(page: PprofPage, parts: Parts) -> Response<Body> {
    match page {
        PprofPage::Home => home(),
        PprofPage::Profile => cpu_profile(Format::Pprof, parts).await,
        PprofPage::Flamegraph => cpu_profile(Format::Flamegraph, parts).await,
    }
}

/// CPU profile output format.
enum Format {
    Pprof,
    Flamegraph,
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
async fn cpu_profile(format: Format, parts: Parts) -> Response<Body> {
    let query_pairs: HashMap<_, _> = match parts.uri.query() {
        Some(query) => url::form_urlencoded::parse(query.as_bytes()).collect(),
        None => Default::default(),
    };

    let seconds: u64 = match query_pairs.get("seconds") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => {
                return make_response(StatusCode::BAD_REQUEST, &err.to_string());
            }
        },
        None => DEFAULT_DURATION_SECONDS,
    };
    let duration = Duration::from_secs(seconds);

    let frequency: i32 = match query_pairs.get("frequency") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => {
                return make_response(StatusCode::BAD_REQUEST, &err.to_string());
            }
        },
        None => DEFAULT_FREQUENCY,
    };

    match format {
        Format::Pprof => into_response(profile(duration, frequency).await, CONTENT_TYPE_PROTOBUF),
        Format::Flamegraph => {
            into_response(flamegraph(duration, frequency).await, CONTENT_TYPE_SVG)
        }
    }
}

/// Converts an `ic_pprof::profile()` output into an HTTP response.
fn into_response(result: Result<Vec<u8>, Error>, content_type: &'static str) -> Response<Body> {
    match result {
        Ok(body) => ok_response(body, content_type),
        Err(err) => make_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

/// Converts a successful `ic_pprof::profile()` output into an HTTP response.
fn ok_response(body: Vec<u8>, content_type: &'static str) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(body.into())
        .unwrap();
    *response.headers_mut() = get_cors_headers();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response
}
