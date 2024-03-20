use crate::{
    errors::{self, ApiError},
    ledger_client::LedgerAccess,
    models::*,
    request_handler::RosettaRequestHandler,
};
use actix_rt::time::interval;
use actix_web::{
    dev::{Server, ServerHandle},
    get, post, web, App, HttpResponse, HttpServer,
};

use prometheus::{
    register_gauge, register_histogram, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, Encoder, Gauge, Histogram, HistogramVec,
    IntCounter, IntCounterVec, IntGauge,
};
use std::{
    io,
    mem::replace,
    path::PathBuf,
    sync::{
        atomic::{
            AtomicBool,
            Ordering::{Relaxed, SeqCst},
        },
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use lazy_static::lazy_static;

struct RosettaEndpointsMetrics {
    request_duration: HistogramVec,
    rosetta_api_status_total: IntCounterVec,
}

impl RosettaEndpointsMetrics {
    pub fn new() -> Self {
        Self {
            request_duration: register_histogram_vec!(
                "http_request_duration",
                "HTTP request latency in seconds indexed by endpoint",
                &["endpoint"]
            )
            .unwrap(),
            rosetta_api_status_total: register_int_counter_vec!(
                "rosetta_api_status_total",
                "Response status for ic-rosetta-api endpoints",
                &["status_code"]
            )
            .unwrap(),
        }
    }
}

lazy_static! {
    static ref ENDPOINTS_METRICS: RosettaEndpointsMetrics = RosettaEndpointsMetrics::new();
    pub static ref VERIFIED_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_verified_block_height", "Verified block height").unwrap();
    pub static ref SYNCED_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_synched_block_height", "Synced block height").unwrap();
    pub static ref TARGET_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_target_block_height", "Target height (tip)").unwrap();
    pub static ref SYNC_ERR_COUNTER: IntCounter = register_int_counter!(
        "blockchain_sync_errors_total",
        "Number of times synchronization failed"
    )
    .unwrap();
    pub static ref OUT_OF_SYNC_TIME: Gauge = register_gauge!(
        "ledger_sync_attempt_duration_seconds",
        "Number of seconds since the last successful sync"
    )
    .unwrap();
    pub static ref OUT_OF_SYNC_TIME_HIST: Histogram = register_histogram!(
        "ledger_sync_attempt_duration_seconds_hist",
        "Number of seconds since last successful sync",
        vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 5.0, 10.0, 15.0]
    )
    .unwrap();
}

#[post("/account/balance")]
async fn account_balance(
    msg: web::Json<AccountBalanceRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = ENDPOINTS_METRICS
        .request_duration
        .with_label_values(&["account/balance"])
        .start_timer();
    let res = req_handler.account_balance(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/call")]
async fn call(
    msg: web::Json<CallRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.call(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block")]
async fn block(
    msg: web::Json<BlockRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = ENDPOINTS_METRICS
        .request_duration
        .with_label_values(&["block"])
        .start_timer();
    let res = req_handler.block(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block/transaction")]
async fn block_transaction(
    msg: web::Json<BlockTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.block_transaction(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/combine")]
async fn construction_combine(
    msg: web::Json<ConstructionCombineRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_combine(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/derive")]
async fn construction_derive(
    msg: web::Json<ConstructionDeriveRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_derive(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/hash")]
async fn construction_hash(
    msg: web::Json<ConstructionHashRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_hash(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/metadata")]
async fn construction_metadata(
    msg: web::Json<ConstructionMetadataRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_metadata(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/parse")]
async fn construction_parse(
    msg: web::Json<ConstructionParseRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_parse(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/payloads")]
async fn construction_payloads(
    msg: web::Json<ConstructionPayloadsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_payloads(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/preprocess")]
async fn construction_preprocess(
    msg: web::Json<ConstructionPreprocessRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_preprocess(msg.into_inner());
    to_rosetta_response(res)
}

#[post("/construction/submit")]
async fn construction_submit(
    msg: web::Json<ConstructionSubmitRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = ENDPOINTS_METRICS
        .request_duration
        .with_label_values(&["construction/submit"])
        .start_timer();
    let res = req_handler.construction_submit(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/list")]
async fn network_list(
    msg: web::Json<rosetta_core::request_types::MetadataRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_list(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/options")]
async fn network_options(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_options(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/status")]
async fn network_status(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_status(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool")]
async fn mempool(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool/transaction")]
async fn mempool_transaction(
    msg: web::Json<MempoolTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool_transaction(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/search/transactions")]
async fn search_transactions(
    msg: web::Json<SearchTransactionsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = ENDPOINTS_METRICS
        .request_duration
        .with_label_values(&["search/transactions"]);
    let res = req_handler.search_transactions(msg.into_inner()).await;
    to_rosetta_response(res)
}

fn to_rosetta_response<S: serde::Serialize>(result: Result<S, ApiError>) -> HttpResponse {
    match result {
        Ok(x) => match serde_json::to_string(&x) {
            Ok(resp) => {
                ENDPOINTS_METRICS
                    .rosetta_api_status_total
                    .with_label_values(&["200"])
                    .inc();
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(resp)
            }
            Err(_) => {
                ENDPOINTS_METRICS
                    .rosetta_api_status_total
                    .with_label_values(&["700"])
                    .inc();
                HttpResponse::InternalServerError()
                    .content_type("application/json")
                    .body(Error::serialization_error_json_str())
            }
        },
        Err(err) => {
            let err = errors::convert_to_error(&err);
            match serde_json::to_string(&err) {
                Ok(resp) => {
                    let err_code = format!("{}", err.0.code);
                    ENDPOINTS_METRICS
                        .rosetta_api_status_total
                        .with_label_values(&[&err_code])
                        .inc();
                    HttpResponse::InternalServerError()
                        .content_type("application/json")
                        .body(resp)
                }
                Err(_) => {
                    ENDPOINTS_METRICS
                        .rosetta_api_status_total
                        .with_label_values(&["700"])
                        .inc();
                    HttpResponse::InternalServerError()
                        .content_type("application/json")
                        .body(Error::serialization_error_json_str())
                }
            }
        }
    }
}

#[get("/metrics")]
async fn rosetta_metrics() -> HttpResponse {
    let metrics = prometheus::gather();
    let mut buffer = Vec::<u8>::new();
    let encoder = prometheus::TextEncoder::new();
    encoder.encode(&metrics, &mut buffer).unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(String::from_utf8(buffer).unwrap())
}

enum ServerState {
    Unstarted(Server),
    Started(tokio::task::JoinHandle<()>),
    OfflineStarted,
    Failed,
    Finished,
}

pub struct RosettaApiServer {
    stopped: Arc<AtomicBool>,
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
    server: Mutex<ServerState>,
    server_handle: ServerHandle,
}

impl RosettaApiServer {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(
        ledger: Arc<T>,
        req_handler: RosettaRequestHandler,
        addr: String,
        listen_port_file: Option<PathBuf>,
        expose_metrics: bool,
    ) -> io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let server = HttpServer::new(move || {
            let app = App::new()
                .app_data(web::Data::new(
                    web::JsonConfig::default()
                        .limit(4 * 1024 * 1024)
                        .error_handler(move |e, _| {
                            errors::convert_to_error(&ApiError::invalid_request(format!(
                                "{:#?}",
                                e
                            )))
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
                .service(search_transactions);
            if expose_metrics {
                app.service(rosetta_metrics)
            } else {
                app
            }
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
            std::fs::write(
                listen_port_file,
                server.addrs().first().unwrap().port().to_string(),
            )
            .unwrap_or_else(|e| panic!("Unable to write to listen_port_file! Error: {}", e));
        }

        let server = server.run();

        Ok(Self {
            stopped,
            ledger,
            server_handle: server.handle(),
            server: Mutex::new(ServerState::Unstarted(server)),
        })
    }

    pub async fn run(&self, options: RosettaApiServerOpt) -> io::Result<()> {
        let RosettaApiServerOpt {
            exit_on_sync,
            offline,
            mainnet,
            not_whitelisted,
        } = options;

        let mut server_lock = self.server.lock().await;
        info!("Starting Rosetta API server");
        *server_lock = match replace(&mut *server_lock, ServerState::Failed) {
            ServerState::Finished => ServerState::Finished,
            ServerState::Started(handle) => ServerState::Started(handle),
            ServerState::OfflineStarted => ServerState::OfflineStarted,
            ServerState::Failed => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "run previously failed!",
                ))
            }
            ServerState::Unstarted(server) if offline => {
                info!("Running in offline mode");
                server.await?;
                ServerState::OfflineStarted
            }
            ServerState::Unstarted(server) => {
                let ledger = self.ledger.clone();
                let stopped = self.stopped.clone();
                let server_handle = self.server_handle.clone();
                // Every second start downloading new blocks, when that's done update the index
                let join_handle = tokio::task::spawn(async move {
                    let mut interval = interval(Duration::from_secs(1));
                    let mut synced_at = std::time::Instant::now();
                    while !stopped.load(Relaxed) {
                        interval.tick().await;

                        if let Err(err) = ledger.sync_blocks(stopped.clone()).await {
                            let msg_403 = if mainnet
                                && !not_whitelisted
                                && err.is_internal_error_403()
                            {
                                ", You may not be whitelisted; please try running the Rosetta server again with the '--not_whitelisted' flag"
                            } else {
                                ""
                            };
                            error!("Error in syncing blocks{}: {:?}", msg_403, err);
                            SYNC_ERR_COUNTER.inc();
                            OUT_OF_SYNC_TIME
                                .set(Instant::now().duration_since(synced_at).as_secs_f64());
                        } else {
                            let t = Instant::now().duration_since(synced_at).as_secs_f64();
                            OUT_OF_SYNC_TIME.set(t);
                            OUT_OF_SYNC_TIME_HIST.observe(t);
                            synced_at = std::time::Instant::now();
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
                });

                server.await?;

                ServerState::Started(join_handle)
            }
        };

        Ok(())
    }

    pub async fn stop(&self) {
        info!("Stopping server");
        self.stopped.store(true, SeqCst);
        self.server_handle.stop(true).await;

        // wait for the sync_thread to finish
        let mut server_lock = self.server.lock().await;
        if let ServerState::Started(jh) = replace(&mut *server_lock, ServerState::Finished) {
            jh.await
                .expect("Error on waiting for sync thread to finish");
        }
        debug!("Joined with blockchain sync thread");
    }
}

#[derive(Default)]
pub struct RosettaApiServerOpt {
    pub exit_on_sync: bool,
    pub offline: bool,
    pub mainnet: bool,
    pub not_whitelisted: bool,
}
