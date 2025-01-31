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
    dev::{Server, ServerHandle},
    get, post, web, App, HttpResponse, HttpServer,
};

use rosetta_core::metrics::RosettaMetrics;
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

#[post("/account/balance")]
async fn account_balance(
    msg: web::Json<AccountBalanceRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let _timer = RosettaMetrics::start_request_duration_timer("account/balance");
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
    let _timer = RosettaMetrics::start_request_duration_timer("block");
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
    let _timer = RosettaMetrics::start_request_duration_timer("construction/submit");
    let res = req_handler.construction_submit(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/list")]
async fn network_list(req_handler: web::Data<RosettaRequestHandler>) -> HttpResponse {
    let res = req_handler.network_list().await;
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
    let _timer = RosettaMetrics::start_request_duration_timer("search/transactions");
    let res = req_handler.search_transactions(msg.into_inner()).await;
    to_rosetta_response(res)
}

fn to_rosetta_response<S: serde::Serialize>(result: Result<S, ApiError>) -> HttpResponse {
    match result {
        Ok(x) => match serde_json::to_string(&x) {
            Ok(resp) => {
                RosettaMetrics::inc_api_status_count("200");
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(resp)
            }
            Err(_) => {
                RosettaMetrics::inc_api_status_count("700");
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
                    RosettaMetrics::inc_api_status_count(&err_code);
                    HttpResponse::InternalServerError()
                        .content_type("application/json")
                        .body(resp)
                }
                Err(_) => {
                    RosettaMetrics::inc_api_status_count("700");
                    HttpResponse::InternalServerError()
                        .content_type("application/json")
                        .body(Error::serialization_error_json_str())
                }
            }
        }
    }
}

#[get("/status")]
async fn status(req_handler: web::Data<RosettaRequestHandler>) -> HttpResponse {
    let rosetta_blocks_mode = req_handler.rosetta_blocks_mode().await;
    to_rosetta_response(Ok(RosettaStatus {
        rosetta_blocks_mode,
    }))
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
        let http_metrics_wrapper = RosettaMetrics::http_metrics_wrapper(expose_metrics);
        let server = HttpServer::new(move || {
            App::new()
                .wrap(http_metrics_wrapper.clone())
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
                    info!("Starting blockchain sync thread");
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
                            RosettaMetrics::inc_sync_errors();
                            RosettaMetrics::set_out_of_sync_time(
                                Instant::now().duration_since(synced_at).as_secs_f64(),
                            );
                        } else {
                            let t = Instant::now().duration_since(synced_at).as_secs_f64();
                            RosettaMetrics::set_out_of_sync_time(t);
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
