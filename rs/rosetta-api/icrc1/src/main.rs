#![allow(clippy::disallowed_types)]
mod config;
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::Request,
    routing::{get, post},
};
use clap::Parser;
use ic_agent::{Agent, identity::AnonymousIdentity};
use ic_base_types::PrincipalId;
use ic_icrc_rosetta::common::storage::storage_client::TokenInfo;
use ic_icrc_rosetta::{
    AppState, Metadata, MultiTokenAppState,
    common::constants::{BLOCK_SYNC_WAIT_SECS, MAX_BLOCK_SYNC_WAIT_SECS},
    common::storage::{storage_client::StorageClient, types::MetadataEntry},
    construction_api::endpoints::*,
    data_api::endpoints::*,
    ledger_blocks_synchronization::blocks_synchronizer::{
        RecurrencyConfig, RecurrencyMode, start_synching_blocks,
    },
};
use ic_sys::fs::write_string_using_tmp_file;
use icrc_ledger_agent::{CallMode, Icrc1Agent};

use config::{Args, ParsedConfig, Store, TokenDef};
use rosetta_core::metrics::RosettaMetrics;
use rosetta_core::watchdog::WatchdogThread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, process, time::Duration};
use tokio::{net::TcpListener, sync::Mutex as AsyncMutex};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tower_request_id::{RequestId, RequestIdLayer};
use tracing::{Instrument, level_filters::LevelFilter};
use tracing::{Level, Span, debug, error, error_span, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

/// Domains that are considered mainnet
const MAINNET_DOMAINS: &[&str] = &["ic0.app", "icp0.io"];
const MAXIMUM_BLOCKS_PER_REQUEST: u64 = 2000;

/// Return the port to which Rosetta should bind to.
fn get_port(port: Option<u16>, port_file: &Option<PathBuf>) -> u16 {
    match (port, port_file) {
        (None, None) => 8080,
        (None, Some(_)) => 0,
        (Some(port), _) => port,
    }
}

fn init_logs(log_level: Level, log_file_path: &PathBuf) -> anyhow::Result<WorkerGuard> {
    let stdout_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_filter(LevelFilter::from_level(log_level));

    // rolling file
    std::fs::create_dir_all(log_file_path.parent().ok_or(anyhow::Error::msg(format!(
        "Could not find the parent directory of {}",
        log_file_path.display()
    )))?)?;
    let file_appender = rolling_file::RollingFileAppender::new(
        log_file_path,
        rolling_file::RollingConditionBasic::new().max_size(100_000_000),
        usize::MAX,
    )?;
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_writer(file_writer)
        .with_filter(LevelFilter::from_level(log_level));

    Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

type FnTraceLayer =
    TraceLayer<SharedClassifier<ServerErrorsAsFailures>, fn(&Request<Body>) -> Span>;

fn add_request_span() -> FnTraceLayer {
    // See tower-request-id crate and the example at
    // https://github.com/imbolc/tower-request-id/blob/fe372479a56bd540784b87812d4d78473e43c6d4/examples/logging.rs

    // Let's create a tracing span for each request
    TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
        // We get the request id from the extensions
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".into());
        // And then we put it along with other information into the `request` span
        error_span!(
            "request",
            id = %request_id,
            method = %request.method(),
            uri = %request.uri(),
        )
    })
}

async fn load_metadata(
    token_def: &TokenDef,
    icrc1_agent: &Icrc1Agent,
    storage: &StorageClient,
    is_offline: bool,
) -> anyhow::Result<Metadata> {
    if is_offline {
        let db_metadata_entries = storage.read_metadata()?;
        let are_metadata_set = token_def.are_metadata_args_set();
        // If metadata is empty and the args are not set, bail out.
        if db_metadata_entries.is_empty() && !are_metadata_set {
            bail!(
                "Metadata must be initialized by starting Rosetta in online mode first or by providing ICRC-1 metadata arguments."
            );
        }

        // If metadata is set in args and not entries are found in the database,
        // return the metadata from the args.
        if are_metadata_set && db_metadata_entries.is_empty() {
            return Ok(Metadata::from_args(
                token_def.icrc1_symbol.clone().unwrap(),
                token_def.icrc1_decimals.unwrap(),
            ));
        }

        // Populate a metadata object with the database entries.
        let db_metadata = Metadata::from_metadata_entries(&db_metadata_entries)?;
        // If the metadata args are not set, return using the db metadata.
        if !are_metadata_set {
            return Ok(db_metadata);
        }

        // Extract the symbol and decimals from the arguments.
        let symbol = token_def
            .icrc1_symbol
            .clone()
            .context("ICRC-1 symbol should be provided in offline mode.")?;
        let decimals = token_def
            .icrc1_decimals
            .context("ICRC-1 decimals should be provided in offline mode.")?;

        // If the database entries is empty, return the metadata as no validation
        // can be done.
        if db_metadata_entries.is_empty() {
            return Ok(Metadata::from_args(symbol, decimals));
        }

        // Populate a metadata object with the database entries.
        let db_metadata = Metadata::from_metadata_entries(&db_metadata_entries)?;

        // If the symbols do not match, bail out.
        if db_metadata.symbol != symbol {
            bail!(
                "Provided symbol does not match symbol retrieved in online mode. Expected: {}",
                db_metadata.symbol
            );
        }

        // If the decimals do not match, bail out.
        if db_metadata.decimals != decimals {
            bail!(
                "Provided decimals does not match symbol retrieved in online mode. Expected: {}",
                db_metadata.decimals
            );
        }

        return Ok(db_metadata);
    }

    let ic_metadata_entries = icrc1_agent
        .metadata(CallMode::Update)
        .await
        .with_context(|| "Failed to get metadata")?
        .iter()
        .map(|(key, value)| MetadataEntry::from_metadata_value(key, value))
        .collect::<Result<Vec<MetadataEntry>>>()?;

    storage.write_metadata(ic_metadata_entries.clone())?;

    Metadata::from_metadata_entries(&ic_metadata_entries)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = ParsedConfig::from_args(args)?;

    let _guard = init_logs(config.log_level, &config.log_file)?;

    // Initialize rosetta metrics with a default canister ID
    // This will be updated for specific token operations but is required for middleware setup
    let rosetta_metrics = RosettaMetrics::new("icrc1".to_string(), "icrc1_default".to_string());

    let token_defs = &config.tokens;
    let mut token_states = HashMap::new();

    let num_tokens = token_defs.len();
    let mut num_failed_tokens = 0;

    for token_def in token_defs.iter() {
        let network_url = &config.network_url;

        let ic_agent = Agent::builder()
            .with_identity(AnonymousIdentity)
            .with_url(network_url.clone())
            .with_http_client(reqwest::Client::new())
            .build()?;

        // Only fetch root key if the network is not the mainnet
        if !MAINNET_DOMAINS.contains(&config.network_url.domain().unwrap_or("")) {
            debug!("Network type is not mainnet --> Trying to fetch root key");
            ic_agent.fetch_root_key().await?;
        }

        debug!("Rosetta connects to : {}", network_url);

        debug!(
            "Network status is : {:?}",
            ic_agent.status().await?.replica_health_status
        );

        let icrc1_agent = Arc::new(Icrc1Agent {
            agent: ic_agent,
            ledger_canister_id: token_def.ledger_id.into(),
        });

        let mut storage = match &config.store {
            Store::InMemory => StorageClient::new_in_memory()?,
            Store::File { dir_path } => {
                let mut path = dir_path.clone();
                path.push(format!("{}.db", PrincipalId::from(token_def.ledger_id)));
                StorageClient::new_persistent_with_cache(
                    &path,
                    config.sqlite_max_cache_kb,
                    config.flush_cache_shrink_mem,
                )
                .unwrap_or_else(|err| panic!("error creating persistent storage '{path:?}': {err}"))
            }
        };

        let metadata = match load_metadata(token_def, &icrc1_agent, &storage, config.offline).await
        {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    "Failed to load metadata for token {}: {:?}",
                    token_def.ledger_id, err
                );
                num_failed_tokens += 1;
                continue;
            }
        };

        if token_def.icrc1_symbol.is_some()
            && metadata.symbol != token_def.icrc1_symbol.clone().unwrap()
        {
            bail!(
                "Provided symbol does not match symbol retrieved in online mode. Expected: {}, Got: {}",
                metadata.symbol,
                token_def.icrc1_symbol.clone().unwrap()
            );
        }

        info!(
            "ICRC Rosetta is connected to the ICRC-1 ledger: {}",
            token_def.ledger_id
        );
        info!(
            "The token symbol of the ICRC-1 ledger is: {}",
            metadata.symbol
        );

        let storage_metadata = metadata.clone();

        storage.initialize(TokenInfo::new(
            storage_metadata.symbol,
            storage_metadata.decimals,
            token_def.ledger_id,
        ));

        let shared_state = Arc::new(AppState {
            icrc1_agent: icrc1_agent.clone(),
            ledger_id: token_def.ledger_id,
            synched: Arc::new(Mutex::new(None)),
            storage: Arc::new(storage),
            archive_canister_ids: Arc::new(AsyncMutex::new(vec![])),
            metadata,
        });

        token_states.insert(token_def.ledger_id.to_string(), shared_state.clone());
    }

    let token_app_states = Arc::new(MultiTokenAppState {
        token_states: token_states.clone(),
    });

    if config.exit_on_sync {
        if config.offline {
            bail!("'exit-on-sync' and 'offline' parameters cannot be specified at the same time.");
        }

        info!("Starting to sync blocks");
        let futures = token_app_states
            .token_states
            .values()
            .map(|shared_state| async move {
                start_synching_blocks(
                    shared_state.icrc1_agent.clone(),
                    shared_state.storage.clone(),
                    MAXIMUM_BLOCKS_PER_REQUEST,
                    shared_state.archive_canister_ids.clone(),
                    RecurrencyMode::OneShot,
                    Box::new(|| {}), // <-- no-op heartbeat
                )
                .await
            });
        let results = futures::future::join_all(futures).await;

        for result in results {
            if let Err(err) = result {
                bail!("Failed to sync blocks: {}", err);
            }
        }
        process::exit(0);
    }

    if num_failed_tokens == num_tokens {
        warn!("Failed to load metadata for any token. Rosetta will exit.");
        bail!("No metadata loaded for any token.");
    } else if num_failed_tokens > 0 {
        warn!(
            "Failed to load metadata for {} out of {} tokens. Rosetta will continue with the rest.",
            num_failed_tokens, num_tokens
        );
    } else {
        info!(
            "Successfully loaded metadata for all {} tokens.",
            num_tokens
        );
    }

    // Create metrics middleware for Axum
    let metrics_layer = rosetta_metrics.metrics_layer();

    let app = Router::new()
        .route("/ready", get(ready))
        .route("/health", get(health))
        .route("/call", post(call))
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .route("/network/status", post(network_status))
        .route("/block", post(block))
        .route("/account/balance", post(account_balance))
        .route("/block/transaction", post(block_transaction))
        .route("/search/transactions", post(search_transactions))
        .route("/mempool", post(mempool))
        .route("/mempool/transaction", post(mempool_transaction))
        .route("/construction/derive", post(construction_derive))
        .route("/construction/preprocess", post(construction_preprocess))
        .route("/construction/metadata", post(construction_metadata))
        .route("/construction/combine", post(construction_combine))
        .route("/construction/submit", post(construction_submit))
        .route("/construction/hash", post(construction_hash))
        .route("/construction/payloads", post(construction_payloads))
        .route("/construction/parse", post(construction_parse))
        // Apply the metrics middleware
        .layer(metrics_layer)
        // This layer creates a span for each http request and attaches
        // the request_id, HTTP Method and path to it.
        .layer(add_request_span())
        // This layer creates a new id for each request and puts it into the
        // request extensions. Note that it should be added after the
        // Trace layer.
        .layer(RequestIdLayer)
        .with_state(token_app_states.clone());

    let rosetta_url = format!("0.0.0.0:{}", get_port(config.port, &config.port_file));
    let tcp_listener = TcpListener::bind(rosetta_url.clone()).await?;

    if let Some(port_file) = config.port_file {
        write_string_using_tmp_file(
            port_file,
            tcp_listener.local_addr()?.port().to_string().as_str(),
        )?;
    }

    if !config.offline {
        // For each token state, spawn a watchdog thread that repeatedly syncs blocks.
        for shared_state in token_app_states.token_states.values() {
            let token_name = shared_state.ledger_display_name();
            let shared_state = Arc::clone(shared_state);
            let span = tracing::info_span!("sync", token = %token_name);
            let span_watchdog = span.clone();

            info!(
                "Configuring watchdog for {} with timeout of {} seconds",
                token_name, config.watchdog_timeout_seconds
            );

            tokio::spawn(
                async move {
                    // First heartbeat might take hours until the ledger is initially synced,
                    // so we skip it to avoid the watchdog thread to restart the sync thread
                    // during the initial synchronization.
                    let skip_first_hearbeat = true;
                    let local_state = Arc::clone(&shared_state);
                    let mut watchdog = WatchdogThread::new(
                        Duration::from_secs(config.watchdog_timeout_seconds),
                        Some(Arc::new(move || {
                            local_state.storage.get_metrics().inc_sync_thread_restarts();
                            info!("Watchdog triggered restart for a sync thread");
                        })),
                        skip_first_hearbeat,
                        Some(span_watchdog.clone()),
                    );
                    let span_watchdog = span_watchdog.clone();
                    watchdog.start(move |heartbeat| {
                        let shared_state = Arc::clone(&shared_state);
                        let span_watchdog = span_watchdog.clone();
                        tokio::spawn(
                            async move {
                                if let Err(e) = start_synching_blocks(
                                    shared_state.icrc1_agent.clone(),
                                    shared_state.storage.clone(),
                                    MAXIMUM_BLOCKS_PER_REQUEST,
                                    shared_state.archive_canister_ids.clone(),
                                    RecurrencyMode::Recurrent(RecurrencyConfig {
                                        min_recurrency_wait: Duration::from_secs(
                                            BLOCK_SYNC_WAIT_SECS,
                                        ),
                                        max_recurrency_wait: Duration::from_secs(
                                            MAX_BLOCK_SYNC_WAIT_SECS,
                                        ),
                                        backoff_factor: 2,
                                    }),
                                    Box::new(heartbeat),
                                )
                                .await
                                {
                                    error!(
                                        "Sync error for token {:?}: {:?}",
                                        shared_state.ledger_id, e
                                    );
                                }
                            }
                            .instrument(span_watchdog),
                        )
                    });
                }
                .instrument(span),
            );
        }
    }

    info!("Starting Rosetta server");
    info!("Rosetta server is listening at: {}", rosetta_url);

    axum::serve(tcp_listener, app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
