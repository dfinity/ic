use axum::{
    async_trait,
    extract::{DefaultBodyLimit, Path, State},
    http,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router, Server,
};
use clap::Parser;
use ic_crypto_iccsa::{public_key_bytes_from_der, types::SignatureBytes, verify};
use ic_crypto_sha2::Sha256;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use pocket_ic::common::{
    blob::{BinaryBlob, BlobCompression, BlobId},
    rest::RawVerifyCanisterSigArg,
};
use pocket_ic_server::state_api::{
    routes::{instances_routes, status, AppState, RouterExt},
    state::PocketIcApiStateBuilder,
};
use pocket_ic_server::BlobStore;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::{collections::HashMap, sync::atomic::AtomicU64};
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;

const TTL_SEC: u64 = 60;

// Command line arguments to PocketIC server.
#[derive(Parser)]
struct Args {
    /// A common identifier for all clients that use this instance of a PocketIC-server. In
    /// general, this is assumed to be the PID of the parent process of the test process. Thus, all
    /// tests of a `cargo test`-invocation (re-)use the same PocketIC-server instance.
    #[clap(long)]
    pid: u32,

    /// If provided, log files will be written to the specified directory. Note that, unless
    /// --log-to-stdout is provided additionally, the logs will not appear on stdout.
    #[clap(long, parse(from_os_str), value_hint = clap::ValueHint::FilePath)]
    log_dir: Option<std::path::PathBuf>,

    /// By default, logs are produced to stdout unless --log-dir is specified. If this flag is
    /// provided, the logs are still produced on stdout.
    ///
    /// Log levels can be controlled by the RUST_LOG environment variable.
    #[clap(long)]
    log_to_stdout: bool,

    /// If this option is provided *and* the RUST_LOG environment variable is *not* set, the log
    /// level of the pocket-ic-server- and the tower-crate are set to the specified value.
    ///
    /// The RUST_LOG environment variable always takes precedence.
    ///
    /// In particular access logs at the REST-layer are only available if the log level is set to
    /// `TRACE`. By default, rejections on the REST-layer are always logged, independent of the
    /// specified log level. That is, unless the RUST_LOG environment variable specified a log
    /// level different from `TRACE` for the axum-crate.
    #[clap(long)]
    log_level: Option<tracing::Level>,
}

impl Args {
    fn validate(self) -> ValidatedArgs {
        // XXX: Return error and use TryFrom
        let log_dir = match self.log_dir {
            Some(p) if p.is_dir() => Some(p),
            Some(p) if !p.is_dir() => panic!("log-dir directory does not exist"),
            _ => None,
        };

        let log_level = self.log_level.unwrap_or(tracing::Level::INFO);
        let log_to_stdout = self.log_to_stdout || log_dir.is_none();

        ValidatedArgs {
            pid: self.pid,
            log_to_stdout,
            log_dir,
            log_level,
        }
    }
}

struct ValidatedArgs {
    pub pid: u32,
    log_to_stdout: bool,
    log_dir: Option<std::path::PathBuf>,
    log_level: tracing::Level,
}

fn main() {
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

async fn start(runtime: Arc<Runtime>) {
    let args = Args::parse().validate();
    // If log-dir is specified, a background thread is started that writes logs into the files in
    // batches. This guard ensures that at the end of the process execution, the buffer is flushed
    // to disk.
    let _guard = setup_tracing(&args);
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", args.pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", args.pid));
    let mut new_port_file = match is_first_server(&port_file_path) {
        Ok(f) => f,
        Err(_) => {
            return;
        }
    };
    // This process is the one to start PocketIC.

    // The shared, mutable state of the PocketIC process.
    let api_state = PocketIcApiStateBuilder::default().build();
    let instance_map = Arc::new(RwLock::new(HashMap::new()));
    // A time-to-live mechanism: Requests bump this value, and the server
    // gracefully shuts down when the value wasn't bumped for a while
    let last_request = Arc::new(RwLock::new(Instant::now()));
    let app_state = AppState {
        instance_map,
        instances_sequence_counter: Arc::new(AtomicU64::from(0)),
        api_state,
        checkpoints: Arc::new(RwLock::new(HashMap::new())),
        last_request,
        runtime,
        blob_store: Arc::new(InMemoryBlobStore::new()),
    };

    let app = Router::new()
        //
        // Get server health.
        .directory_route("/status", get(status))
        //
        // Set a blob store entry.
        .directory_route("/blobstore", post(set_blob_store_entry))
        //
        // Get a blob store entry.
        .directory_route("/blobstore/:id", get(get_blob_store_entry))
        //
        // verify signature
        .directory_route("/verify_signature", post(verify_signature))
        //
        // All instance routes.
        .nest("/instances", instances_routes::<AppState>())
        //
        // List all checkpoints.
        .directory_route("/checkpoints", get(list_checkpoints))
        .layer(DefaultBodyLimit::disable())
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            bump_last_request_timestamp,
        ))
        // For examples on how to customize the logging spans:
        // https://github.com/tokio-rs/axum/blob/main/examples/tracing-aka-logging/src/main.rs#L45
        .layer(TraceLayer::new_for_http())
        .with_state(app_state.clone());

    // bind to port 0; the OS will give a specific port; communicate that to parent process
    let server = Server::bind(&"127.0.0.1:0".parse().expect("Failed to parse address"))
        .serve(app.into_make_service());
    let real_port = server.local_addr().port();
    let _ = new_port_file.write_all(real_port.to_string().as_bytes());
    let _ = new_port_file.flush();

    let ready_file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&ready_file_path);
    if ready_file.is_ok() {
        info!("The PocketIC server is listening on port {}", real_port);
    } else {
        error!("The .ready file already exists; This should not happen unless the PID has been reused, and/or the tmp dir has not been properly cleaned up");
    }

    // This is a safeguard against orphaning this child process.
    let shutdown_signal = async {
        loop {
            let guard = app_state.last_request.read().await;
            if guard.elapsed() > Duration::from_secs(TTL_SEC) {
                break;
            }
            drop(guard);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        info!("The PocketIC server will terminate");
        // Clean up tmpfiles.
        let _ = std::fs::remove_file(ready_file_path);
        let _ = std::fs::remove_file(port_file_path);
    };
    let server = server.with_graceful_shutdown(shutdown_signal);
    server.await.expect("Failed to launch the PocketIC server");
}

// Registers a global subscriber that collects tracing events and spans.
fn setup_tracing(args: &ValidatedArgs) -> Option<WorkerGuard> {
    use tracing_subscriber::prelude::*;

    let lvl = args.log_level;
    let mut layers = Vec::new();

    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // axum logs rejections from built-in extractors with the `axum::rejection`
            // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
            format!("pocket_ic_server={lvl},tower_http={lvl},axum::rejection=trace").into()
        })
        .boxed();
    layers.push(filter_layer);

    if args.log_to_stdout {
        layers.push(tracing_subscriber::fmt::layer().boxed());
    }

    let guard = if let Some(p) = &args.log_dir {
        let pid = args.pid;
        let appender = tracing_appender::rolling::never(p, format!("pocket_ic_{pid}"));
        let (non_blocking_appender, guard) = tracing_appender::non_blocking(appender);

        layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_appender)
                .boxed(),
        );
        Some(guard)
    } else {
        None
    };

    tracing_subscriber::registry().with(layers).init();
    guard
}

/// Returns the opened file if it was successfully created and is readable, writeable. Otherwise,
/// returns an error. Used to determine if this is the first process creating this file.
fn is_first_server<P: AsRef<std::path::Path>>(port_file_path: P) -> std::io::Result<File> {
    // .create_new(true) ensures atomically that this file was created newly, and gives an error otherwise.
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&port_file_path)
}

async fn bump_last_request_timestamp<B>(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state: _,
        checkpoints: _,
        last_request,
        ..
    }): State<AppState>,
    request: http::Request<B>,
    next: Next<B>,
) -> Response {
    *last_request.write().await = Instant::now();
    next.run(request).await
}

async fn get_blob_store_entry(
    State(AppState { blob_store, .. }): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let hash = hex::decode(id);
    if hash.is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let hash: Result<[u8; 32], Vec<u8>> = hash.unwrap().try_into();
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
        None => (StatusCode::NOT_FOUND).into_response(),
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

pub async fn list_checkpoints(
    State(AppState { checkpoints, .. }): State<AppState>,
) -> Json<Vec<String>> {
    let checkpoints = checkpoints
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    Json(checkpoints)
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
        let key = BlobId(hasher.finish());
        let mut m = self.map.write().await;
        m.insert(key.clone(), blob);
        key
    }

    async fn fetch(&self, blob_id: BlobId) -> Option<BinaryBlob> {
        let m = self.map.read().await;
        m.get(&blob_id).cloned()
    }
}
