//! IC Service Discovery for Prometheus

mod config;
mod metrics;
mod service_discovery;

use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use std::path::PathBuf;
use std::{collections::HashSet, convert::Infallible, sync::Arc};

use anyhow::{Context, Result};
use futures_util::FutureExt;
use hyper::{
    server::Server,
    service::{make_service_fn, service_fn},
    Body, Response,
};
use prometheus::{Encoder, TextEncoder};
use slog::{error, info, o};

use ecs::SetTo;
use elastic_common_schema::{self as ecs, process_fields::WithCurrentProcess};
use ic_async_utils::shutdown_signal;
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_nns_data_provider::create_nns_data_provider;

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let args: HashSet<&'static str> = gflags::parse().iter().cloned().collect();
    if args.contains("help") {
        gflags::print_help_and_exit(0);
    }

    let config = Config::new().context("unable to process configuration")?;

    if args.contains("dump_config") {
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(());
    }

    let logger = ic_p8s_service_discovery_log::LoggerImpl::new(&config.log, "main".to_string());
    let log = logger.root.new(o!());

    let mut event = ecs::Event::new(ecs::Kind::Event);
    event.event.set(ecs::Category::Process);
    event.event.set(ecs::Type::Info);
    event.process.with_current_process();

    info!(log, "Startup"; &event);

    let config = Arc::new(config.clone());

    let metrics_registry = MetricsRegistry::global();
    let metrics = Arc::new(metrics::Metrics::new(&metrics_registry));

    // Pay attention to when the service should shutdown
    let shutdown_signal = shutdown_signal(log.clone()).shared();

    let discovery_config = Arc::clone(&config);
    let discovery_log = log.clone();
    let discovery_metrics = Arc::clone(&metrics);
    let discovery_shutdown = shutdown_signal.clone();

    let nns_public_key = if !config.nns_public_key_path.is_empty() {
        Some(
            parse_threshold_sig_key(&PathBuf::from(&config.nns_public_key_path))
                .expect("unable to parse NNS public key"),
        )
    } else {
        None
    };

    let data_provider = create_nns_data_provider(
        tokio::runtime::Handle::current(),
        config.nns.urls.clone(),
        nns_public_key,
    );

    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(&metrics_registry),
    ));

    if let Err(e) = registry_client.try_polling_latest_version(100) {
        panic!("try_polling_latest_version failed {}", e);
    }

    if let Err(e) = registry_client.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    }

    let discovery = async move {
        let config = Arc::clone(&discovery_config);
        let log = discovery_log.clone();
        let metrics = Arc::clone(&discovery_metrics);
        let shutdown = discovery_shutdown.clone();
        service_discovery::service_discovery(config, registry_client, log, metrics, shutdown).await
    };

    // Set the IP and port for serving metrics.
    let metrics_svc = make_service_fn(move |_socket| {
        let metrics_registry = metrics_registry.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |_req| {
                let metrics_registry = metrics_registry.clone();
                let encoder = TextEncoder::new();

                async move {
                    let metric_families = metrics_registry.prometheus_registry().gather();
                    let mut buffer = vec![];
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    Ok::<_, Infallible>(Response::new(Body::from(buffer)))
                }
            }))
        }
    });

    // Prepare the servers
    let metrics_server = Server::bind(&config.metrics_addr)
        .serve(metrics_svc)
        .with_graceful_shutdown(shutdown_signal.clone());

    // Spawn them so that waking up one doesn't wake up the other
    let discovery_handle = tokio::spawn(discovery);
    let metrics_handle = tokio::spawn(metrics_server);

    info!(log, "Running server, metrics on {:?}", &config.metrics_addr);

    // Join on the servers, returning as soon as one of them completes
    if let Err(error) = tokio::try_join!(discovery_handle, metrics_handle) {
        error!(log, "server error: {}", error);
    }

    Ok(())
}
