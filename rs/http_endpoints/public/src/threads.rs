use crate::common::make_plaintext_response;
use axum::body::Body;
use hyper::{Response, StatusCode};

/// Collects a backtrace of all threads of this process in text format.
#[allow(dead_code)]
pub(crate) async fn collect() -> Response<Body> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let (status, body) = match tokio::task::spawn_blocking(ic_backtrace::collect_fmt).await {
        // Backtrace collected.
        Ok(Ok(backtrace)) => (StatusCode::OK, backtrace),

        // `spawn_blocking()` succeeded, backtrace collection failed.
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e),

        // `spawn_blocking()` failed.
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking() failed: {}", e),
        ),
    };

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let (status, body) = (
        StatusCode::OK,
        "Backtraces are only supported on Linux".into(),
    );

    make_plaintext_response(status, body)
}
