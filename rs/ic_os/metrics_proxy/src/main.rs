use axum_prometheus::PrometheusMetricLayerBuilder;
use clap::Parser;
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

    let cfg = maybecfg.unwrap();
    let mut telemetry = cfg.metrics.clone().map(|listener| {
        let (prometheus_layer, metrics_handle) = PrometheusMetricLayerBuilder::new()
            .with_ignore_patterns(&["/metrics"])
            .enable_response_body_size(true)
            .with_default_metrics()
            .build_pair();
        (listener, prometheus_layer, metrics_handle)
    });

    let proxylist: Vec<metrics_proxy::config::HttpProxy> = cfg.into();

    for proxy in proxylist {
        let mut server = metrics_proxy::server::Server::from(proxy);
        telemetry = match telemetry {
            Some((t, pl, mh)) => {
                server = server.with_telemetry(pl.clone());
                server = server.with_metrics_handle(mh.clone());
                Some((t, pl, mh))
            }
            _ => None,
        };
        set.spawn(async move { server.serve().await });
    }
    if let Some((t, pl, mh)) = telemetry {
        let server = metrics_proxy::server::Server::for_service_metrics(t)
            .with_telemetry(pl)
            .with_metrics_handle(mh);
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
