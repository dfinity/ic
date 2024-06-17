use ic_adapter_metrics_service::adapter_metrics_service_client::AdapterMetricsServiceClient;
use ic_adapter_metrics_service::ScrapeRequest;
use ic_async_utils::ExecuteOnTokioRuntime;
use prometheus::proto::MetricFamily;
use protobuf::Message;
use std::{fmt, path::PathBuf, time::Duration};
use tokio::net::UnixStream;
use tonic::{
    transport::{Channel, Endpoint, Uri},
    Request, Status,
};
use tower::service_fn;

const ADAPTER_PREFIX: &str = "adapter";

/// Adapter metrics client
///
/// Fetches prometheus metrics from remote process adapters that provide UDS metrics endpoint.
#[derive(Clone)]
pub struct AdapterMetrics {
    /// Unique adapter name.
    name: String,
    channel: Channel,
}

impl fmt::Debug for AdapterMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterMetrics")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl AdapterMetrics {
    /// Creates new `AdapterMetrics`.
    ///
    /// Name needs to be a unique value for this adapter.
    // / A metrics server is expected to be listenting on the `uds_path`.
    /// `rt_handle` is the runtime used for fetching the metrics.
    pub fn new(name: &str, uds_path: PathBuf, rt_handle: tokio::runtime::Handle) -> Self {
        // We will ignore this uri because uds does not use it. If we are unable to connect
        // to the metrics endpoint the adapter metrics will be ignored.
        let endpoint = Endpoint::try_from("http://[::]:50152")
            .unwrap()
            .executor(ExecuteOnTokioRuntime(rt_handle));
        let channel = endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
            // Connect to a Uds socket
            UnixStream::connect(uds_path.clone())
        }));

        Self {
            name: name.to_string(),
            channel,
        }
    }

    /// Get adapter name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Scrapes metrics from remote adapter. Returns an error if unable to fetch metrics.
    pub async fn scrape(&self, timeout: Duration) -> Result<Vec<MetricFamily>, Status> {
        let mut client = AdapterMetricsServiceClient::new(self.channel.clone());
        let mut scrape_request = Request::new(ScrapeRequest {});
        scrape_request.set_timeout(timeout);
        match client.scrape(scrape_request).await {
            Err(err) => Err(err),
            Ok(resp) => {
                let resp = resp.into_inner();
                let metrics = resp
                    .metrics
                    .iter()
                    .map(|b| {
                        let mut mf = MetricFamily::parse_from_bytes(b).unwrap_or_default();
                        // Prepend unique adapter prefix to avoid prometheus duplicate.
                        // I.e adapter_btc_requests
                        mf.set_name(
                            ADAPTER_PREFIX.to_owned() + "_" + &self.name + "_" + mf.get_name(),
                        );
                        mf
                    })
                    .collect();
                Ok(metrics)
            }
        }
    }
}
