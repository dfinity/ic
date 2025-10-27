#![allow(clippy::disallowed_types)]
use crate::{
    errors::{self, ApiError},
    ledger_client::LedgerAccess,
    models::*,
    request_handler::RosettaRequestHandler,
    request_types::RosettaStatus,
};
use actix_rt::time::interval;
use actix_web::{
    App, HttpResponse, HttpServer,
    dev::{Server, ServerHandle},
    get, post, web,
};

use rosetta_core::metrics::RosettaMetrics;
use rosetta_core::watchdog::WatchdogThread;
use std::{
    io,
    mem::replace,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering::{Relaxed, SeqCst},
        },
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

// Interval for syncing blocks from the ledger
const BLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(1);
use tracing::{error, info};

#[post("/account/balance")]
async fn account_balance(
    msg: web::Json<AccountBalanceRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = req_handler
        .rosetta_metrics()
        .start_request_duration_timer("account/balance");
    let res = req_handler.account_balance(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/call")]
async fn call(
    msg: web::Json<CallRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.call(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/block")]
async fn block(
    msg: web::Json<BlockRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = req_handler
        .rosetta_metrics()
        .start_request_duration_timer("block");
    let res = req_handler.block(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/block/transaction")]
async fn block_transaction(
    msg: web::Json<BlockTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.block_transaction(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/combine")]
async fn construction_combine(
    msg: web::Json<ConstructionCombineRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_combine(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/derive")]
async fn construction_derive(
    msg: web::Json<ConstructionDeriveRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_derive(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/hash")]
async fn construction_hash(
    msg: web::Json<ConstructionHashRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_hash(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/metadata")]
async fn construction_metadata(
    msg: web::Json<ConstructionMetadataRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_metadata(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/parse")]
async fn construction_parse(
    msg: web::Json<ConstructionParseRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_parse(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/payloads")]
async fn construction_payloads(
    msg: web::Json<ConstructionPayloadsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_payloads(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/preprocess")]
async fn construction_preprocess(
    msg: web::Json<ConstructionPreprocessRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_preprocess(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/construction/submit")]
async fn construction_submit(
    msg: web::Json<ConstructionSubmitRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = req_handler
        .rosetta_metrics()
        .start_request_duration_timer("construction/submit");
    let res = req_handler.construction_submit(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/network/list")]
async fn network_list(req_handler: web::Data<RosettaRequestHandler>) -> HttpResponse {
    let res = req_handler.network_list().await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/network/options")]
async fn network_options(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_options(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/network/status")]
async fn network_status(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_status(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/mempool")]
async fn mempool(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/mempool/transaction")]
async fn mempool_transaction(
    msg: web::Json<MempoolTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool_transaction(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

#[post("/search/transactions")]
async fn search_transactions(
    msg: web::Json<SearchTransactionsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = req_handler
        .rosetta_metrics()
        .start_request_duration_timer("search/transactions");
    let res = req_handler.search_transactions(msg.into_inner()).await;
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}

fn internal_error_response(
    e: impl std::fmt::Debug,
    resp: String,
    rosetta_metrics: &RosettaMetrics,
) -> HttpResponse {
    error!("Internal error: {:?}", e);
    rosetta_metrics.inc_api_status_count("700");
    HttpResponse::InternalServerError()
        .content_type("application/json")
        .body(resp)
}

fn to_rosetta_response<S: serde::Serialize>(
    result: Result<S, ApiError>,
    rosetta_metrics: &RosettaMetrics,
) -> HttpResponse {
    match result {
        Ok(x) => match serde_json::to_string(&x) {
            Ok(resp) => {
                rosetta_metrics.inc_api_status_count("200");
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(resp)
            }
            Err(e) => {
                internal_error_response(e, Error::serialization_error_json_str(), rosetta_metrics)
            }
        },
        Err(api_err) => {
            let converted = errors::convert_to_error(&api_err);
            match serde_json::to_string(&converted) {
                Ok(resp) => {
                    let err_code = format!("{}", converted.0.code);
                    rosetta_metrics.inc_api_status_count(&err_code);
                    internal_error_response(converted, resp, rosetta_metrics)
                }
                Err(e) => internal_error_response(
                    e,
                    Error::serialization_error_json_str(),
                    rosetta_metrics,
                ),
            }
        }
    }
}

#[get("/status")]
async fn status(req_handler: web::Data<RosettaRequestHandler>) -> HttpResponse {
    let rosetta_blocks_mode = req_handler.rosetta_blocks_mode().await;
    to_rosetta_response(
        Ok(RosettaStatus {
            rosetta_blocks_mode,
        }),
        &req_handler.rosetta_metrics(),
    )
}

enum ServerState {
    Unstarted(Server),
    Started,
    OfflineStarted,
    Failed,
}

pub struct RosettaApiServer {
    stopped: Arc<AtomicBool>,
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
    server: Mutex<ServerState>,
    server_handle: ServerHandle,
    watchdog_timeout_seconds: u64,
}

impl RosettaApiServer {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(
        ledger: Arc<T>,
        req_handler: RosettaRequestHandler,
        addr: String,
        listen_port_file: Option<PathBuf>,
        expose_metrics: bool,
        watchdog_timeout_seconds: u64,
    ) -> io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let http_metrics_wrapper = RosettaMetrics::http_metrics_wrapper(expose_metrics);
        let server = HttpServer::new(move || {
            App::new()
                .wrap(http_metrics_wrapper.clone())
                .app_data(web::Data::new(
                    web::JsonConfig::default()
                        .limit(4 * 1024 * 1024)
                        .error_handler(move |e, _| {
                            errors::convert_to_error(&ApiError::invalid_request(format!("{e:#?}")))
                                .into()
                        }),
                ))
                .app_data(web::Data::new(req_handler.clone()))
                .service(account_balance)
                .service(block)
                .service(call)
                .service(block_transaction)
                .service(construction_combine)
                .service(construction_derive)
                .service(construction_hash)
                .service(construction_metadata)
                .service(construction_parse)
                .service(construction_payloads)
                .service(construction_preprocess)
                .service(construction_submit)
                .service(mempool)
                .service(mempool_transaction)
                .service(network_list)
                .service(network_options)
                .service(network_status)
                .service(search_transactions)
                .service(status)
        })
        .bind(addr)?;

        if let Some(listen_port_file) = listen_port_file {
            let listen_port_file_parent = listen_port_file
                .parent()
                .expect("Unable to get the parent of listen_port_file");
            std::fs::create_dir_all(listen_port_file_parent).unwrap_or_else(|e| {
                panic!(
                    "Unable to create the parent directories for file {}: {}",
                    listen_port_file.display(),
                    e
                )
            });
            ic_sys::fs::write_string_using_tmp_file(
                &listen_port_file,
                &server.addrs().first().unwrap().port().to_string(),
            )
            .unwrap_or_else(|e| panic!("Unable to write to listen_port_file! Error: {e}"));
        }

        let server = server.run();

        Ok(Self {
            stopped,
            ledger,
            server_handle: server.handle(),
            server: Mutex::new(ServerState::Unstarted(server)),
            watchdog_timeout_seconds,
        })
    }

    pub async fn run(&self, options: RosettaApiServerOpt) -> io::Result<()> {
        let RosettaApiServerOpt {
            exit_on_sync,
            offline,
            mainnet,
            not_whitelisted,
        } = options;

        info!("Starting Rosetta API server");
        let mut server_lock = self.server.lock().await;

        *server_lock = match replace(&mut *server_lock, ServerState::Failed) {
            ServerState::Started => ServerState::Started,
            ServerState::OfflineStarted => ServerState::OfflineStarted,
            ServerState::Failed => return Err(io::Error::other("run previously failed!")),
            ServerState::Unstarted(server) if offline => {
                info!("Running in offline mode");
                server.await?;
                ServerState::OfflineStarted
            }
            ServerState::Unstarted(server) => {
                let skip_first_heartbeat_check = true;
                let rosetta_metrics = RosettaMetrics::new(
                    "ICP".to_string(),
                    "ryjl3-tyaaa-aaaaa-aaaba-cai".to_string(),
                );
                let on_restart_callback: Option<Arc<dyn Fn() + Send + Sync>> =
                    Some(Arc::new(move || {
                        rosetta_metrics.inc_sync_thread_restarts();
                    }));
                let mut watchdog_thread = WatchdogThread::new(
                    Duration::from_secs(self.watchdog_timeout_seconds),
                    on_restart_callback,
                    skip_first_heartbeat_check,
                    None,
                );
                let server_handle = self.server_handle.clone();
                let ledger = self.ledger.clone();
                let stopped = self.stopped.clone();
                watchdog_thread.start(move |heartbeat| {
                    let ledger = ledger.clone();
                    let stopped = stopped.clone();
                    let server_handle = server_handle.clone();
                    start_sync_thread(
                        ledger,
                        stopped,
                        server_handle,
                        mainnet,
                        not_whitelisted,
                        exit_on_sync,
                        heartbeat,
                    )
                });
                server.await?;
                watchdog_thread.stop().await;
                ServerState::Started
            }
        };

        Ok(())
    }

    pub async fn stop(&self) {
        info!("Stopping server");
        self.stopped.store(true, SeqCst);
        self.server_handle.stop(true).await;
    }
}

fn start_sync_thread(
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
    stopped: Arc<AtomicBool>,
    server_handle: ServerHandle,
    mainnet: bool,
    not_whitelisted: bool,
    exit_on_sync: bool,
    heartbeat_fn: Box<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    // Every second start downloading new blocks, when that's done update the index
    tokio::task::spawn(async move {
        info!("Starting blockchain sync thread");
        let mut interval = interval(BLOCK_SYNC_INTERVAL);
        let mut synced_at = std::time::Instant::now();
        let mut first_sync_successful = false;
        let rosetta_metrics =
            RosettaMetrics::new("ICP".to_string(), "ryjl3-tyaaa-aaaaa-aaaba-cai".to_string());
        while !stopped.load(Relaxed) {
            interval.tick().await;
            if let Err(err) = ledger.sync_blocks(stopped.clone()).await {
                let msg_403 = if mainnet && !not_whitelisted && err.is_internal_error_403() {
                    ", You may not be whitelisted; please try running the Rosetta server again with the '--not_whitelisted' flag"
                } else {
                    ""
                };
                error!("Error in syncing blocks{}: {:?}", msg_403, err);
                rosetta_metrics.inc_sync_errors();
                rosetta_metrics
                    .set_out_of_sync_time(Instant::now().duration_since(synced_at).as_secs_f64());
            } else {
                let t = Instant::now().duration_since(synced_at).as_secs_f64();
                rosetta_metrics.set_out_of_sync_time(t);
                synced_at = std::time::Instant::now();
                first_sync_successful = true;
            }

            // Only call heartbeat after the first successful sync
            if first_sync_successful {
                heartbeat_fn();
            }

            if exit_on_sync {
                info!("Blockchain synced, exiting");
                server_handle.stop(true).await;
                info!("Stopping blockchain sync thread");
                break;
            }
        }
        ledger.cleanup().await;
        info!("Blockchain sync thread finished");
    })
}

#[derive(Default)]
pub struct RosettaApiServerOpt {
    pub exit_on_sync: bool,
    pub offline: bool,
    pub mainnet: bool,
    pub not_whitelisted: bool,
}
