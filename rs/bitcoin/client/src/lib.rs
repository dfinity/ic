mod metrics;

use crate::metrics::{
    LABEL_GET_SUCCESSORS, LABEL_REQUEST_TYPE, LABEL_SEND_TRANSACTION, LABEL_STATUS, Metrics,
    OK_LABEL, REQUESTS_LABEL_NAMES, UNKNOWN_LABEL,
};
use ic_adapter_metrics_client::AdapterMetrics;
use ic_btc_replica_types::{
    AdapterClient, BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper,
    GetSuccessorsRequestInitial, GetSuccessorsResponseComplete, SendTransactionRequest,
    SendTransactionResponse,
};
use ic_btc_service::{
    BtcServiceGetSuccessorsRequest, BtcServiceSendTransactionRequest,
    btc_service_client::BtcServiceClient,
};
use ic_config::adapters::AdaptersConfig;
use ic_http_endpoints_async_utils::ExecuteOnTokioRuntime;
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError, RpcResult};
use ic_logger::{ReplicaLogger, error};
use ic_metrics::{MetricsRegistry, histogram_vec_timer::HistogramVecTimer};
use std::{convert::TryFrom, path::PathBuf};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::instrument;

fn convert_tonic_error(status: tonic::Status) -> RpcError {
    match status.code() {
        tonic::Code::Unavailable => RpcError::Unavailable(status.message().to_string()),
        tonic::Code::Cancelled => RpcError::Cancelled(status.message().to_string()),
        _ => RpcError::Unknown(status.message().to_string()),
    }
}

struct BitcoinAdapterClientImpl {
    rt_handle: tokio::runtime::Handle,
    client: BtcServiceClient<Channel>,
    metrics: Metrics,
}

impl BitcoinAdapterClientImpl {
    fn new(metrics: Metrics, rt_handle: tokio::runtime::Handle, channel: Channel) -> Self {
        let client = BtcServiceClient::new(channel);
        Self {
            rt_handle,
            client,
            metrics,
        }
    }
}

impl RpcAdapterClient<BitcoinAdapterRequestWrapper> for BitcoinAdapterClientImpl {
    type Response = BitcoinAdapterResponseWrapper;

    #[instrument(skip_all)]
    fn send_blocking(
        &self,
        request: BitcoinAdapterRequestWrapper,
        opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper> {
        let mut request_timer = HistogramVecTimer::start_timer(
            self.metrics.requests.clone(),
            &REQUESTS_LABEL_NAMES,
            [UNKNOWN_LABEL, UNKNOWN_LABEL],
        );
        let mut client = self.client.clone();
        self.rt_handle.block_on(async move {
            let response = match request {
                BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
                    transaction,
                    ..
                }) => {
                    request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_SEND_TRANSACTION);
                    let send_transaction_request = BtcServiceSendTransactionRequest { transaction };
                    let mut tonic_request = tonic::Request::new(send_transaction_request);
                    tonic_request.set_timeout(opts.timeout);

                    client
                        .send_transaction(tonic_request)
                        .await
                        .map(|tonic_response| {
                            let _inner = tonic_response.into_inner();
                            BitcoinAdapterResponseWrapper::SendTransactionResponse(
                                SendTransactionResponse {},
                            )
                        })
                        .map_err(convert_tonic_error)
                }
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
                    GetSuccessorsRequestInitial {
                        anchor,
                        processed_block_hashes,
                        ..
                    },
                ) => {
                    request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_GET_SUCCESSORS);
                    let get_successors_request = BtcServiceGetSuccessorsRequest {
                        anchor,
                        processed_block_hashes,
                    };

                    let mut tonic_request = tonic::Request::new(get_successors_request);
                    tonic_request.set_timeout(opts.timeout);

                    client
                        .get_successors(tonic_request)
                        .await
                        .map(|tonic_response| {
                            let inner = tonic_response.into_inner();
                            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                                GetSuccessorsResponseComplete {
                                    blocks: inner.blocks,
                                    next: inner.next,
                                },
                            )
                        })
                        .map_err(convert_tonic_error)
                }
            };
            let mut timer = request_timer;
            timer.set_label(
                LABEL_STATUS,
                match &response {
                    Err(err) => err.into(),
                    Ok(_) => OK_LABEL,
                },
            );
            response
        })
    }
}

struct BrokenConnectionBitcoinClient {
    metrics: Metrics,
}

impl BrokenConnectionBitcoinClient {
    fn new(metrics: Metrics) -> Self {
        Self { metrics }
    }
}

impl RpcAdapterClient<BitcoinAdapterRequestWrapper> for BrokenConnectionBitcoinClient {
    type Response = BitcoinAdapterResponseWrapper;

    fn send_blocking(
        &self,
        request: BitcoinAdapterRequestWrapper,
        _opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper> {
        let mut request_timer = HistogramVecTimer::start_timer(
            self.metrics.requests.clone(),
            &REQUESTS_LABEL_NAMES,
            [UNKNOWN_LABEL, UNKNOWN_LABEL],
        );
        match request {
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) => {
                request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_GET_SUCCESSORS)
            }
            BitcoinAdapterRequestWrapper::SendTransactionRequest(_) => {
                request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_SEND_TRANSACTION)
            }
        }
        request_timer.set_label(LABEL_STATUS, RpcError::ConnectionBroken.into());
        Err(RpcError::ConnectionBroken)
    }
}

fn setup_adapter_client(
    log: ReplicaLogger,
    metrics: Metrics,
    rt_handle: tokio::runtime::Handle,
    uds_path: Option<PathBuf>,
) -> AdapterClient {
    match uds_path {
        None => Box::new(BrokenConnectionBitcoinClient::new(metrics)),
        Some(uds_path) => {
            // We will ignore this uri because uds do not use it
            // if your connector does use the uri it will be provided
            // as the request to the `MakeConnection`.
            match Endpoint::try_from("http://[::]:50051") {
                Ok(endpoint) => {
                    let endpoint = endpoint.executor(ExecuteOnTokioRuntime(rt_handle.clone()));
                    let channel =
                        endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
                            let uds_path = uds_path.clone();
                            async move {
                                // Connect to a Uds socket
                                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                                    UnixStream::connect(uds_path).await?,
                                ))
                            }
                        }));
                    Box::new(BitcoinAdapterClientImpl::new(metrics, rt_handle, channel))
                }
                Err(_) => {
                    error!(log, "Could not create an endpoint.");
                    Box::new(BrokenConnectionBitcoinClient::new(metrics))
                }
            }
        }
    }
}

pub struct BitcoinAdapterClients {
    pub btc_testnet_client: AdapterClient,
    pub btc_mainnet_client: AdapterClient,
    pub doge_testnet_client: AdapterClient,
    pub doge_mainnet_client: AdapterClient,
}

pub fn setup_bitcoin_adapter_clients(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: tokio::runtime::Handle,
    adapters_config: AdaptersConfig,
) -> BitcoinAdapterClients {
    let metrics = Metrics::new(metrics_registry);

    // Register adapters metrics.
    if let Some(metrics_uds_path) = adapters_config.bitcoin_testnet_uds_metrics_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "btctestnet",
            metrics_uds_path,
            rt_handle.clone(),
        ));
    }
    if let Some(metrics_uds_path) = adapters_config.bitcoin_mainnet_uds_metrics_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "btcmainnet",
            metrics_uds_path,
            rt_handle.clone(),
        ));
    }
    if let Some(metrics_uds_path) = adapters_config.dogecoin_testnet_uds_metrics_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "dogetestnet",
            metrics_uds_path,
            rt_handle.clone(),
        ));
    }
    if let Some(metrics_uds_path) = adapters_config.dogecoin_mainnet_uds_metrics_path {
        metrics_registry.register_adapter(AdapterMetrics::new(
            "dogemainnet",
            metrics_uds_path,
            rt_handle.clone(),
        ));
    }

    BitcoinAdapterClients {
        btc_testnet_client: setup_adapter_client(
            log.clone(),
            metrics.clone(),
            rt_handle.clone(),
            adapters_config.bitcoin_testnet_uds_path,
        ),
        btc_mainnet_client: setup_adapter_client(
            log.clone(),
            metrics.clone(),
            rt_handle.clone(),
            adapters_config.bitcoin_mainnet_uds_path,
        ),
        doge_testnet_client: setup_adapter_client(
            log.clone(),
            metrics.clone(),
            rt_handle.clone(),
            adapters_config.dogecoin_testnet_uds_path,
        ),
        doge_mainnet_client: setup_adapter_client(
            log,
            metrics,
            rt_handle,
            adapters_config.dogecoin_mainnet_uds_path,
        ),
    }
}
