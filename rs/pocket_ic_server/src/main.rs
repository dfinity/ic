#![allow(clippy::disallowed_types)]
use aide::{
    axum::{
        routing::{get, post},
        ApiRouter, IntoApiResponse,
    },
    openapi::{Info, OpenApi},
};
use async_trait::async_trait;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    Extension, Json,
};
use axum_server::Handle;
use clap::Parser;
use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use ic_crypto_iccsa::{public_key_bytes_from_der, types::SignatureBytes, verify};
use ic_crypto_sha2::Sha256;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE};
use pocket_ic::common::rest::{BinaryBlob, BlobCompression, BlobId, RawVerifyCanisterSigArg};
use pocket_ic_server::state_api::routes::handler_read_graph;
use pocket_ic_server::state_api::{
    routes::{http_gateway_routes, instances_routes, status, AppState, RouterExt},
    state::{ApiState, PocketIcApiStateBuilder},
};
use pocket_ic_server::BlobStore;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::{self, Error};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::channel;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::EnvFilter;

const TTL_SEC: u64 = 60;
// axum logs rejections from built-in extractors with the `axum::rejection`
// target, at `TRACE` level. `axum::rejection=trace` enables showing those events
const DEFAULT_LOG_LEVELS: &str = "pocket_ic_server=info,tower_http=info,axum::rejection=trace";
const LOG_DIR_PATH_ENV_NAME: &str = "POCKET_IC_LOG_DIR";
const LOG_DIR_LEVELS_ENV_NAME: &str = "POCKET_IC_LOG_DIR_LEVELS";

#[derive(Parser)]
#[clap(version = "9.0.3")]
struct Args {
    /// The IP address to which the PocketIC server should bind (defaults to 127.0.0.1)
    #[clap(long, short)]
    ip_addr: Option<String>,
    /// Log levels for PocketIC server logs (defaults to `pocket_ic_server=info,tower_http=info,axum::rejection=trace`).
    #[clap(long, short)]
    log_levels: Option<String>,
    /// The port at which the PocketIC server should listen
    #[clap(long, short, default_value_t = 0)]
    port: u16,
    /// The file to which the PocketIC server port should be written
    #[clap(long)]
    port_file: Option<PathBuf>,
    /// The time-to-live of the PocketIC server in seconds
    #[clap(long, default_value_t = TTL_SEC)]
    ttl: u64,
}

/// Get the path of the current running binary.
fn current_binary_path() -> Option<PathBuf> {
    std::env::args().next().map(PathBuf::from)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern "C" {
    fn install_backtrace_handler();
}

fn increase_nofile_limit(mut new_limit: u64) -> io::Result<()> {
    unsafe {
        let mut limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // Get current limits
        if getrlimit(RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(Error::last_os_error());
        }

        // Set new limit
        if new_limit > limit.rlim_max {
            debug!(
                "Setting the maximum number of open files to match the hard limit: {}",
                limit.rlim_max
            );
            new_limit = limit.rlim_max;
        }
        limit.rlim_cur = new_limit;

        if setrlimit(RLIMIT_NOFILE, &limit) != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn main() {
    let current_binary_path = current_binary_path().unwrap();
    let current_binary_name = current_binary_path.file_name().unwrap().to_str().unwrap();
    if current_binary_name != "pocket-ic" && current_binary_name != "pocket-ic-server" {
        panic!("The PocketIc server binary name must be \"pocket-ic\" or \"pocket-ic-server\" (without quotes).")
    }
    // Check if `pocket-ic-server` is running in the canister sandbox mode where it waits
    // for commands from the parent process. This check has to be performed
    // before the arguments are parsed because the parent process does not pass
    // all the normally required arguments of `pocket-ic-server`.
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        unsafe {
            install_backtrace_handler();
        }
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
    } else {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(16)
            // we use the tokio rt to dispatch blocking operations in the background
            .max_blocking_threads(16)
            .build()
            .expect("Failed to create tokio runtime!");
        let runtime_arc = Arc::new(rt);
        runtime_arc.block_on(async { start(runtime_arc.clone()).await });
    }
}

async fn start(runtime: Arc<Runtime>) {
    let args = Args::parse();

    let port_file = if let Some(ref port_file_path) = args.port_file {
        match create_file(port_file_path) {
            Ok(f) => Some(f),
            Err(_) => {
                // A PocketIC server is already running => terminate.
                return;
            }
        }
    } else {
        None
    };

    let _guard = setup_tracing(args.log_levels);

    // Set RUST_MIN_STACK if not yet set:
    // the value of 8192000 is set according to `ic-os/components/ic/ic-replica.service`.
    std::env::set_var("RUST_MIN_STACK", "8192000");

    // Set the maximum number of open files:
    // the limit of 16777216 is set according to `ic-os/components/ic/ic-replica.service`.
    if let Err(e) = increase_nofile_limit(16777216) {
        error!(
            "Failed to increase the maximum number of open files: {:?}",
            e
        );
    }

    let ip_addr = args.ip_addr.unwrap_or("127.0.0.1".to_string());
    let addr = format!("{}:{}", ip_addr, args.port);
    let listener = std::net::TcpListener::bind(addr.clone())
        .unwrap_or_else(|_| panic!("Failed to bind PocketIC server to address {}", addr));
    let real_port = listener.local_addr().unwrap().port();

    // The shared, mutable state of the PocketIC process.
    let api_state = PocketIcApiStateBuilder::default()
        .with_port(real_port)
        .build();
    // A time-to-live mechanism: Requests bump this value, and the server
    // gracefully shuts down when the value wasn't bumped for a while.
    let min_alive_until = Arc::new(RwLock::new(Instant::now()));
    let app_state = AppState {
        api_state,
        pending_requests: Arc::new(AtomicU64::new(0)),
        min_alive_until,
        runtime,
        blob_store: Arc::new(InMemoryBlobStore::new()),
    };

    let router = ApiRouter::new()
        //
        // Serve OpenAPI documentation.
        .route("/api.json", get(serve_api))
        //
        // Get server health.
        .directory_route("/status", get(status))
        //
        // Set a blob store entry.
        .directory_route("/blobstore", post(set_blob_store_entry))
        //
        // Get a blob store entry.
        .directory_route("/blobstore/{id}", get(get_blob_store_entry))
        //
        // Verify signature.
        .directory_route("/verify_signature", post(verify_signature))
        //
        // Read state: Poll a result based on a received Started{} reply.
        .directory_route("/read_graph/{state_label}/{op_id}", get(handler_read_graph))
        //
        // All instance routes.
        .nest("/instances", instances_routes::<AppState>())
        // All HTTP gateway routes.
        .nest("/http_gateway", http_gateway_routes::<AppState>())
        .fallback(|| async { (StatusCode::NOT_FOUND, "") })
        .layer(DefaultBodyLimit::disable())
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            bump_last_request_timestamp,
        ))
        .with_state(app_state.clone());

    let mut api = OpenApi {
        info: Info {
            description: Some("PocketIC server API".to_string()),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    let router = router
        // Generate documentation
        .finish_api(&mut api)
        // Expose documentation
        .layer(Extension(api))
        // For examples on how to customize the logging spans:
        // https://github.com/tokio-rs/axum/blob/main/examples/tracing-aka-logging/src/main.rs#L45
        .layer(TraceLayer::new_for_http())
        .into_make_service();

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let axum_handle = handle.clone();
    let port_file_path = args.port_file.clone();
    let app_state_clone = app_state.clone();
    // This is a safeguard against orphaning this child process.
    tokio::spawn(async move {
        loop {
            let pending_requests = app_state.pending_requests.load(Ordering::Relaxed);
            let guard = app_state.min_alive_until.read().await;
            if pending_requests == 0 && guard.elapsed() > Duration::from_secs(args.ttl) {
                break;
            }
            drop(guard);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        terminate(app_state, shutdown_handle, port_file_path).await;
    });
    // Register a signal handler.
    let (tx, mut rx) = channel(1);
    let shutdown_handle = handle.clone();
    let port_file_path = args.port_file.clone();
    tokio::spawn(async move {
        if let Some(()) = rx.recv().await {
            terminate(app_state_clone, shutdown_handle, port_file_path).await;
        }
    });
    ctrlc::set_handler(move || {
        tx.blocking_send(())
            .expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");

    let main_task = tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .handle(axum_handle)
            .serve(router)
            .await
            .unwrap();
    });

    // Wait until the PocketIC server starts listening.
    while handle.listening().await.is_none() {}

    if let Some(mut port_file) = port_file {
        let _ = port_file.write_all(format!("{}\n", real_port).as_bytes());
        let _ = port_file.flush();
    }

    info!("The PocketIC server is listening on port {}", real_port);

    main_task.await.unwrap();
}

async fn terminate(
    app_state: AppState,
    shutdown_handle: axum_server::Handle,
    port_file_path: Option<PathBuf>,
) {
    debug!("The PocketIC server will terminate");

    app_state.api_state.stop_all_http_gateways().await;
    ApiState::delete_all_instances(app_state.api_state).await;

    if let Some(port_file_path) = port_file_path {
        // Clean up port file.
        let _ = std::fs::remove_file(port_file_path);
    }

    shutdown_handle.shutdown();
}

async fn serve_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}

// Registers a global subscriber that collects tracing events and spans.
fn setup_tracing(log_levels: Option<String>) -> Option<WorkerGuard> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    use tracing_subscriber::prelude::*;

    let mut layers = Vec::new();

    let default_log_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            log_levels
                .clone()
                .unwrap_or(DEFAULT_LOG_LEVELS.to_string())
                .into()
        })
    };

    layers.push(
        tracing_subscriber::fmt::layer()
            .with_filter(default_log_filter())
            .boxed(),
    );

    let guard = match std::env::var(LOG_DIR_PATH_ENV_NAME).map(std::path::PathBuf::from) {
        Ok(p) => {
            std::fs::create_dir_all(&p).expect("Could not create directory");
            let dt = OffsetDateTime::from(std::time::SystemTime::now());
            let logfile_suffix = dt.format(&Rfc3339).unwrap().replace(':', "_");
            let appender = tracing_appender::rolling::never(
                &p,
                format!("pocket_ic_server_{logfile_suffix}.log"),
            );
            let (non_blocking_appender, guard) = tracing_appender::non_blocking(appender);

            let log_dir_filter: EnvFilter =
                tracing_subscriber::EnvFilter::try_from_env(LOG_DIR_LEVELS_ENV_NAME)
                    .unwrap_or_else(|_| default_log_filter());
            layers.push(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking_appender)
                    // disable color escape codes in files
                    .with_ansi(false)
                    .with_filter(log_dir_filter)
                    .boxed(),
            );
            Some(guard)
        }
        _ => None,
    };

    tracing_subscriber::registry().with(layers).init();

    guard
}

// Create a file at a given path ensuring atomically that the file was created freshly and giving an error otherwise.
fn create_file<P: AsRef<std::path::Path>>(file_path: P) -> std::io::Result<File> {
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&file_path)
}

async fn bump_last_request_timestamp(
    State(AppState {
        pending_requests,
        min_alive_until,
        ..
    }): State<AppState>,
    request: http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoApiResponse {
    pending_requests.fetch_add(1, Ordering::Relaxed);
    let resp = next.run(request).await;
    // TTL should not decrease: If now is later
    // than the current TTL (from previous requests), reset it.
    // Otherwise, a previous request set a larger TTL and we don't
    // touch it.
    let alive_until = Instant::now();
    let mut min_alive_until = min_alive_until.write().await;
    if *min_alive_until < alive_until {
        *min_alive_until = alive_until;
    }
    drop(min_alive_until);
    // Only mark the pending request as completed (by subtracting the counter)
    // *after* updating TTL!
    pending_requests.fetch_sub(1, Ordering::Relaxed);
    resp
}

async fn get_blob_store_entry(
    State(AppState { blob_store, .. }): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoApiResponse {
    let hash = hex::decode(id);
    if hash.is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let blob = blob_store.fetch(BlobId(hash.unwrap())).await;
    match blob {
        Some(BinaryBlob {
            compression: BlobCompression::Gzip,
            ..
        }) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_ENCODING, "gzip")],
            blob.unwrap().data,
        )
            .into_response(),
        Some(BinaryBlob {
            compression: BlobCompression::NoCompression,
            ..
        }) => (StatusCode::OK, blob.unwrap().data).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn set_blob_store_entry(
    headers: HeaderMap,
    State(AppState { blob_store, .. }): State<AppState>,
    body: axum::body::Bytes,
) -> (StatusCode, String) {
    let content_encoding = headers.get(axum::http::header::CONTENT_ENCODING);

    let blob = {
        match content_encoding {
            Some(content_encoding) => {
                let encoding_type = content_encoding.to_str();
                match encoding_type {
                    Ok("gzip") => BinaryBlob {
                        data: body.to_vec(),
                        compression: BlobCompression::Gzip,
                    },
                    _ => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "Bad encoding: Only 'gzip' content encoding is supported".to_owned(),
                        );
                    }
                }
            }
            None => BinaryBlob {
                data: body.to_vec(),
                compression: BlobCompression::NoCompression,
            },
        }
    };
    let blob_id = hex::encode(blob_store.store(blob).await.0);
    (StatusCode::OK, blob_id)
}

pub async fn verify_signature(
    axum::extract::Json(RawVerifyCanisterSigArg {
        msg,
        sig,
        pubkey,
        root_pubkey,
    }): axum::extract::Json<RawVerifyCanisterSigArg>,
) -> (StatusCode, Json<Result<(), String>>) {
    match public_key_bytes_from_der(&pubkey) {
        Ok(pubkey) => match parse_threshold_sig_key_from_der(&root_pubkey) {
            Ok(root_pubkey) => match verify(&msg, SignatureBytes(sig), pubkey, &root_pubkey) {
                Ok(()) => (StatusCode::OK, Json(Ok(()))),
                Err(err) => (
                    StatusCode::NOT_ACCEPTABLE,
                    Json(Err(format!(
                        "Canister signature verification failed: {:?}",
                        err
                    ))),
                ),
            },
            Err(err) => (
                StatusCode::BAD_REQUEST,
                Json(Err(format!(
                    "Failed to parse DER encoded root public key: {:?}",
                    err
                ))),
            ),
        },
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(Err(format!(
                "Failed to parse DER encoded public key: {:?}",
                err
            ))),
        ),
    }
}

// -------------------------------------------------------------------------------------
struct InMemoryBlobStore {
    map: RwLock<HashMap<BlobId, BinaryBlob>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        InMemoryBlobStore {
            map: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BlobStore for InMemoryBlobStore {
    async fn store(&self, blob: BinaryBlob) -> BlobId {
        let mut hasher = Sha256::new();
        hasher.write(&blob.data);
        let key = BlobId(hasher.finish().to_vec());
        let mut m = self.map.write().await;
        m.insert(key.clone(), blob);
        key
    }

    async fn fetch(&self, blob_id: BlobId) -> Option<BinaryBlob> {
        let m = self.map.read().await;
        m.get(&blob_id).cloned()
    }
}
