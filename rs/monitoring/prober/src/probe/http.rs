//! HTTP probe. May also be used to probe canister HTTP endpoints via boundary
//! nodes.

use super::{
    bad_request, duration_to, internal_server_error, set_once, unwrap_param, ParamIterator,
    ProbeResult,
};
use ic_metrics::{MetricsRegistry, Timer};
use lazy_static::lazy_static;
use prometheus::{Gauge, IntGauge};
use reqwest::Client;
use std::time::Instant;
use url::Url;

lazy_static! {
    /// HTTP client, reused across probes for efficiency.
    static ref CLIENT: Client = Client::builder().build().unwrap();
}

/// HTTP probe metrics.
struct Metrics {
    /// Duration of HTTP request.
    duration: Gauge,
    /// HTTP response status code.
    status_code: IntGauge,
    /// Length of HTTP response content.
    content_length: IntGauge,
    /// Whether the HTTP request timed out or not.
    timeout: IntGauge,
    /// Whether the HTTP request completed successfully or not.
    success: IntGauge,
}

impl Metrics {
    fn new(registry: &MetricsRegistry) -> Self {
        let duration = registry.gauge("probe_http_duration_seconds", "Duration of HTTP request.");
        let status_code =
            registry.int_gauge("probe_http_status_code", "HTTP response status code.");
        let content_length = registry.int_gauge(
            "probe_http_content_length",
            "Length of HTTP response content.",
        );
        let timeout = registry.int_gauge(
            "probe_http_timeout",
            "Whether the HTTP request timed out or not.",
        );
        let success = registry.int_gauge(
            "probe_http_success",
            "Whether the HTTP request completed successfully or not.",
        );

        // Default status code and content length to -1 (in case of any error).
        status_code.set(-1);
        content_length.set(-1);

        Self {
            duration,
            status_code,
            content_length,
            timeout,
            success,
        }
    }
}

const TARGET: &str = "target";

/// Probes the given HTTP target. Expects a `target` parameter containing a URL
/// (without the `http://` prefix) to query, e.g. `target=internetcomputer.org/education`.
pub async fn probe(params: ParamIterator<'_>, deadline: Instant) -> ProbeResult {
    let mut target = None;
    for (param, value) in params {
        match param.as_ref() {
            TARGET => set_once(&mut target, TARGET, value)?,
            _ => return Err(bad_request(format!("Unexpected query param: {}", param))),
        }
    }
    let target = unwrap_param(target, TARGET)?;

    let url =
        Url::parse(&format!("http://{}", target)).map_err(|err| bad_request(err.to_string()))?;

    let registry = MetricsRegistry::new();
    let metrics = Metrics::new(&registry);

    let timer = Timer::start();
    let result = CLIENT.get(url).timeout(duration_to(deadline)).send().await;

    match result {
        Ok(response) => {
            let status_code = response.status();
            metrics.status_code.set(status_code.as_u16() as i64);
            let content = response.text().await;

            // Only record the duration after having retrieved any content.
            metrics.duration.set(timer.elapsed());

            if let Ok(content) = content {
                metrics.content_length.set(content.len() as i64);
                metrics.success.set(status_code.is_success() as i64);
            };

            Ok(registry)
        }

        Err(err) if err.is_timeout() => {
            metrics.duration.set(timer.elapsed());
            metrics.timeout.set(1);

            Ok(registry)
        }

        Err(err) => Err(internal_server_error(err.to_string())),
    }
}
