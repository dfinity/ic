//! Per-group static file server for the Local system-test backend.
//!
//! The Farm backend uploads `icos_images` (GuestOS/HostOS disk and update
//! images) to a content-addressed HTTP store from which Farm-hosted IC nodes
//! download them. The Local backend has no external network access, so instead
//! we serve those images ourselves: this task runs a tiny HTTP server bound to
//! the group's IPv6 management address (see
//! [`LocalBackend::group_mgmt_ipv6`](crate::driver::local_backend::LocalBackend::group_mgmt_ipv6))
//! on [`FILE_SERVER_PORT`], and the `..._url` helpers in
//! [`ic_images`](crate::driver::ic_images) return URLs pointing at it.
//!
//! The management address lies *outside* every node's `/64`, mirroring
//! production where the web server hosting these images is not on the IC nodes'
//! subnet. Nodes still reach it because the Local backend's Router
//! Advertisement installs the host as their default router; see
//! [`LocalBackend::create_group`](crate::driver::local_backend::LocalBackend::create_group).
//!
//! Files are addressed by their SHA-256 hash (mirroring Farm's content-
//! addressed scheme): a `GET /<sha256>` returns the image whose contents hash
//! to `<sha256>`. The hash→path map is built from the `ENV_DEPS__<X>_PATH` /
//! `ENV_DEPS__<X>_HASH` environment-variable pairs that the
//! `system_test(local = True, ...)` Bazel macro and `run_systest.sh` provide.
//!
//! The task is modelled exactly like
//! [`logs_stream_task`](crate::driver::logs_stream_task): it never
//! returns and is wired into the plan as a supervisor over the
//! setup → tests → teardown subtree, so the task scheduler silently kills it
//! once the subtree finishes (this is not treated as a failure).

use crate::driver::{
    constants::GROUP_SETUP_DIR,
    context::GroupContext,
    local_backend::LocalBackend,
    test_env::{TestEnv, TestEnvAttribute},
    test_setup::GroupSetup,
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use slog::{Logger, debug, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio_util::io::ReaderStream;

pub(crate) const SERVE_FILES_TASK_NAME: &str = "serve_files";

/// Delay between retries while waiting for the group setup / binding the socket.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// TCP port on which the per-group file server listens (on the group's IPv6
/// management address). Under the Local backend there is no external network, so
/// `icos_images` that IC nodes must fetch over HTTP (e.g. GuestOS/HostOS update
/// images used by upgrade tests) are served by a small web server spawned from
/// the test driver (see `serve_files_task`). The port is fixed because every
/// group has its own (per-group unique) management address, so there is no
/// cross-group contention on it.
pub const FILE_SERVER_PORT: u16 = 8080;

pub(crate) fn serve_files_task(group_ctx: GroupContext) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {SERVE_FILES_TASK_NAME}");

    // Wait until `GroupSetup` has been persisted so we can derive the group's
    // management address. Under the Local backend that address is assigned to
    // `lo` inline in the parent process before the task scheduler starts, so
    // this normally succeeds on the first iteration; the loop only guards
    // against an unexpected startup race.
    let group_setup = loop {
        let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
        if setup_dir.exists() {
            let env = TestEnv::new_without_duplicating_logger(setup_dir, logger.clone());
            if let Ok(group_setup) = GroupSetup::try_read_attribute(&env) {
                break group_setup;
            }
        }
        info!(
            logger,
            "{SERVE_FILES_TASK_NAME}: waiting for group setup to be persisted ..."
        );
        std::thread::sleep(RETRY_DELAY);
    };

    let mgmt = LocalBackend::group_mgmt_ipv6(&group_setup.infra_group_name);
    let files = collect_served_files(&logger);
    info!(
        logger,
        "{SERVE_FILES_TASK_NAME}: serving {} image(s) on [{mgmt}]:{FILE_SERVER_PORT}",
        files.len()
    );

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));

    rt.block_on(async move {
        let state = Arc::new(ServerState {
            files,
            logger: logger.clone(),
        });
        let app = Router::new()
            .route("/{sha256}", get(serve_file))
            .with_state(state);

        let addr = format!("[{mgmt}]:{FILE_SERVER_PORT}");
        let listener = loop {
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => break listener,
                Err(err) => {
                    warn!(
                        logger,
                        "{SERVE_FILES_TASK_NAME}: failed to bind {addr}: {err}; retrying ..."
                    );
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        };
        info!(logger, "{SERVE_FILES_TASK_NAME}: listening on {addr}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap_or_else(|err| panic!("{SERVE_FILES_TASK_NAME}: server error: {err}"));
    });
}

/// Shared, read-only server state: the content-addressed file map and a logger.
struct ServerState {
    /// Maps a SHA-256 hex digest to the (canonical) path of the file that hashes
    /// to it.
    files: HashMap<String, PathBuf>,
    logger: Logger,
}

/// Build the `sha256 -> path` map served by the file server.
///
/// For every `ENV_DEPS__<X>_PATH` environment variable that has a matching
/// `ENV_DEPS__<X>_HASH`, the file at `<X>_PATH` is served under `<X>_HASH`. The
/// Bazel macro provides the `_PATH` variables for the Local backend and
/// `run_systest.sh` exports the `_HASH` variables, so the intersection is
/// exactly the set of `icos_images` configured for the test.
fn collect_served_files(logger: &Logger) -> HashMap<String, PathBuf> {
    let mut files = HashMap::new();
    for (key, value) in std::env::vars() {
        let Some(prefix) = key.strip_suffix("_PATH") else {
            continue;
        };
        if !prefix.starts_with("ENV_DEPS__") {
            continue;
        }
        let Ok(hash) = std::env::var(format!("{prefix}_HASH")) else {
            continue;
        };
        let path = PathBuf::from(&value);
        match path.canonicalize() {
            Ok(canonical) => {
                debug!(
                    logger,
                    "{SERVE_FILES_TASK_NAME}: {hash} -> {}",
                    canonical.display()
                );
                files.insert(hash, canonical);
            }
            Err(err) => {
                warn!(
                    logger,
                    "{SERVE_FILES_TASK_NAME}: cannot canonicalize '{}' (from {key}): {err}",
                    path.display()
                );
            }
        }
    }
    files
}

/// Serve `GET /<sha256>` by streaming the corresponding file.
///
/// The IC `FileDownloader` issues a `Range: bytes=<offset>-` header even for a
/// fresh download (with `offset == 0`) but accepts any 2xx response and appends
/// the body at `offset`. We always reply `200 OK` with the full body, which is
/// correct for the `offset == 0` case (a node downloading the image for the
/// first time). If a download is interrupted and later resumed with a non-zero
/// offset, the appended full body produces a hash mismatch, after which the
/// downloader deletes the file and restarts from offset 0 — so the download
/// still converges to the correct file.
async fn serve_file(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(sha256): Path<String>,
) -> Response {
    info!(
        state.logger,
        "{SERVE_FILES_TASK_NAME}: {peer} requested '{sha256}'"
    );
    let Some(path) = state.files.get(&sha256) else {
        warn!(
            state.logger,
            "{SERVE_FILES_TASK_NAME}: 404 for '{sha256}' (requested by {peer})"
        );
        return (StatusCode::NOT_FOUND, "no such image\n").into_response();
    };

    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(err) => {
            warn!(
                state.logger,
                "{SERVE_FILES_TASK_NAME}: cannot open '{}': {err}",
                path.display()
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "open failed\n").into_response();
        }
    };
    let len = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(err) => {
            warn!(
                state.logger,
                "{SERVE_FILES_TASK_NAME}: cannot stat '{}': {err}",
                path.display()
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "stat failed\n").into_response();
        }
    };

    let body = Body::from_stream(ReaderStream::new(file));
    info!(
        state.logger,
        "{SERVE_FILES_TASK_NAME}: serving '{sha256}' ('{}') ({len} bytes) to {peer}",
        path.display()
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .body(body)
        .expect("failed to build file response")
}
