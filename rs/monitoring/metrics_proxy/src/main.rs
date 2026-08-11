use axum_otel_metrics::{HttpMetricsLayerBuilder, PathSkipper};
use clap::Parser;
use std::sync::Arc;
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct MetricsProxyArgs {
    config: std::path::PathBuf,
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

    // rustls 0.23 requires a process-wide default crypto provider to be
    // installed before any `ServerConfig`/`ClientConfig` is built.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cfg = maybecfg.unwrap();
    let mut telemetry = cfg.metrics.clone().map(|listener| {
        // Since axum-otel-metrics 0.14 no longer bundles a Prometheus exporter
        // or serves the metrics endpoint itself, we own that here: build a
        // Prometheus registry, wire it into an OpenTelemetry meter provider,
        // and register that provider globally. The custom instruments in
        // `metrics.rs` obtain their meter from the global provider, so it must
        // be the very same provider the HTTP metrics layer records into --
        // otherwise custom metrics are silently not exported.
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .expect("failed to build Prometheus exporter");
        let resource = opentelemetry_sdk::Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_attribute(opentelemetry::KeyValue::new(
                "service.version",
                env!("CARGO_PKG_VERSION"),
            ))
            .build();
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(exporter)
            .build();
        opentelemetry::global::set_meter_provider(provider.clone());
        let layer = HttpMetricsLayerBuilder::new()
            .with_provider(provider)
            .with_skipper(PathSkipper::new_with_fn(Arc::new(move |_: &str| false)))
            .build();
        (listener, layer, registry)
    });

    let proxylist: Vec<metrics_proxy::config::HttpProxy> = cfg.into();

    for proxy in proxylist {
        let mut server = metrics_proxy::server::Server::from(proxy);
        telemetry = match telemetry {
            Some((t, m, r)) => {
                server = server.with_telemetry(m.clone());
                Some((t, m, r))
            }
            _ => None,
        };
        set.spawn(async move { server.serve().await });
    }
    if let Some((t, m, r)) = telemetry {
        let server = metrics_proxy::server::Server::for_service_metrics(t, r).with_telemetry(m);
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
