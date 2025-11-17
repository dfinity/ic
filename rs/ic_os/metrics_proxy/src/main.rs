use axum_otel_metrics::{HttpMetricsLayerBuilder, PathSkipper};
use clap::Parser;
use opentelemetry::global;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use std::sync::Arc;
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct MetricsProxyArgs {
    config: std::path::PathBuf,
}

fn configure_metrics_provider() -> SdkMeterProvider {
    let registry = prometheus::Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry)
        .build()
        .unwrap();

    let provider = SdkMeterProvider::builder().with_reader(exporter).build();

    global::set_meter_provider(provider.clone());
    provider
}

pub async fn run() {
    let args = MetricsProxyArgs::parse();
    let maybecfg = metrics_proxy::config::Config::try_from(args.config.clone());
    if let Err(error) = maybecfg {
        eprintln!("Error parsing {}: {}", args.config.display(), error);
        std::process::exit(exitcode::CONFIG);
    }
    let mut set = JoinSet::new();

    simple_logger::init_with_level(log::Level::Info).unwrap();

    let meter_provider = configure_metrics_provider();

    let cfg = maybecfg.unwrap();
    let mut telemetry = cfg.metrics.clone().map(|listener| {
        (
            listener,
            HttpMetricsLayerBuilder::new()
                .with_provider(meter_provider)
                .with_skipper(PathSkipper::new_with_fn(Arc::new(move |_: &str| false)))
                .build(),
        )
    });

    let proxylist: Vec<metrics_proxy::config::HttpProxy> = cfg.into();

    for proxy in proxylist {
        let mut server = metrics_proxy::server::Server::from(proxy);
        telemetry = match telemetry {
            Some((t, m)) => {
                server = server.with_telemetry(m.clone());
                Some((t, m))
            }
            _ => None,
        };
        set.spawn(async move { server.serve().await });
    }
    if let Some((t, m)) = telemetry {
        let server = metrics_proxy::server::Server::for_service_metrics(t).with_telemetry(m);
        set.spawn(async move { server.serve().await });
    }

    while let Some(res) = set.join_next().await {
        if let Err(error) = res.unwrap() {
            eprintln!("HTTP server failed: {error}");
            std::process::exit(exitcode::OSERR);
        }
    }
}

#[tokio::main]
async fn main() {
    run().await
}
