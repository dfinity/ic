mod metrics;

use crate::metrics::{
    Metrics, LABEL_GET_SUCCESSORS, LABEL_REQUEST_TYPE, LABEL_SEND_TRANSACTION, LABEL_STATUS,
    OK_LABEL, REQUESTS_LABEL_NAMES, UNKNOWN_LABEL,
};
use bitcoin::consensus::Decodable;
use ic_async_utils::ExecuteOnTokioRuntime;
use ic_btc_service::{
    btc_service_client::BtcServiceClient, BtcServiceGetSuccessorsRequest,
    BtcServiceSendTransactionRequest,
};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, Block as InternalBlock,
    BlockHeader as InternalBlockHeader, GetSuccessorsRequest as InternalGetSuccessorsRequest,
    GetSuccessorsResponse, OutPoint as InternalOutPoint,
    SendTransactionRequest as InternalSendTransactionRequest, SendTransactionResponse,
    Transaction as InternalTransaction, TxIn as InternalTxIn, TxOut as InternalTxOut,
    Txid as InternalTxid,
};
use ic_config::adapters::AdaptersConfig;
use ic_interfaces_bitcoin_adapter_client::{
    BitcoinAdapterClient, BitcoinAdapterClientError, Options, RpcResult,
};
use ic_logger::{error, ReplicaLogger};
use ic_metrics::{histogram_vec_timer::HistogramVecTimer, MetricsRegistry};
use std::{convert::TryFrom, path::PathBuf};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

fn convert_tonic_error(status: tonic::Status) -> BitcoinAdapterClientError {
    match status.code() {
        tonic::Code::Unavailable => {
            BitcoinAdapterClientError::Unavailable(status.message().to_string())
        }
        tonic::Code::Cancelled => {
            BitcoinAdapterClientError::Cancelled(status.message().to_string())
        }
        _ => BitcoinAdapterClientError::Unknown(status.message().to_string()),
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

fn to_internal_txin(txin: &bitcoin::TxIn) -> InternalTxIn {
    InternalTxIn {
        previous_output: InternalOutPoint {
            txid: InternalTxid::try_from(&txin.previous_output.txid[..])
                .expect("The len of the bitcoin::Txid hash is not 32 bytes."),
            vout: txin.previous_output.vout,
        },
        script_sig: txin.script_sig.as_bytes().to_vec(),
        sequence: txin.sequence,
        witness: txin
            .witness
            .iter()
            .map(|v| serde_bytes::ByteBuf::from(v.to_vec()))
            .collect(),
    }
}

fn to_internal_block(block: &bitcoin::Block) -> InternalBlock {
    InternalBlock {
        header: to_internal_block_header(&block.header),
        txdata: block
            .txdata
            .iter()
            .map(|x| InternalTransaction {
                version: x.version,
                lock_time: x.lock_time,
                input: x.input.iter().map(to_internal_txin).collect(),
                output: x
                    .output
                    .iter()
                    .map(|x| InternalTxOut {
                        value: x.value,
                        script_pubkey: x.script_pubkey.as_bytes().to_vec(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn to_internal_block_header(block_header: &bitcoin::BlockHeader) -> InternalBlockHeader {
    InternalBlockHeader {
        version: block_header.version,
        prev_blockhash: block_header.prev_blockhash.to_vec(),
        merkle_root: block_header.merkle_root.to_vec(),
        time: block_header.time,
        bits: block_header.bits,
        nonce: block_header.nonce,
    }
}

impl BitcoinAdapterClient for BitcoinAdapterClientImpl {
    fn send_request(
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
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
                    InternalGetSuccessorsRequest {
                        processed_block_hashes,
                        anchor,
                    },
                ) => {
                    request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_GET_SUCCESSORS);
                    let get_successors_request = BtcServiceGetSuccessorsRequest {
                        processed_block_hashes,
                        anchor,
                    };
                    let mut tonic_request = tonic::Request::new(get_successors_request);
                    if let Some(timeout) = opts.timeout {
                        tonic_request.set_timeout(timeout);
                    }

                    client
                        .get_successors(tonic_request)
                        .await
                        .map(|tonic_response| {
                            let inner = tonic_response.into_inner();

                            let mut blocks = vec![];
                            for b in inner.blocks.into_iter() {
                                let bitcoin_block =
                                    bitcoin::Block::consensus_decode(&*b).map_err(|e| {
                                        tonic::Status::internal(format!(
                                            "Deserialization of response failed: {}",
                                            e
                                        ))
                                    })?;
                                blocks.push(to_internal_block(&bitcoin_block));
                            }
                            let mut next = vec![];
                            for n in inner.next.into_iter() {
                                let bitcoin_block_header =
                                    bitcoin::BlockHeader::consensus_decode(&*n).unwrap();
                                next.push(to_internal_block_header(&bitcoin_block_header));
                            }
                            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                                GetSuccessorsResponse { blocks, next },
                            ))
                        })
                        .map_err(convert_tonic_error)?
                        .map_err(convert_tonic_error)
                }
                BitcoinAdapterRequestWrapper::SendTransactionRequest(
                    InternalSendTransactionRequest { transaction },
                ) => {
                    request_timer.set_label(LABEL_REQUEST_TYPE, LABEL_SEND_TRANSACTION);
                    let send_transaction_request = BtcServiceSendTransactionRequest { transaction };
                    let mut tonic_request = tonic::Request::new(send_transaction_request);
                    if let Some(timeout) = opts.timeout {
                        tonic_request.set_timeout(timeout);
                    }

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

impl BitcoinAdapterClient for BrokenConnectionBitcoinClient {
    fn send_request(
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
        request_timer.set_label(
            LABEL_STATUS,
            BitcoinAdapterClientError::ConnectionBroken.into(),
        );
        Err(BitcoinAdapterClientError::ConnectionBroken)
    }
}

fn setup_bitcoin_adapter_client(
    log: ReplicaLogger,
    metrics: Metrics,
    rt_handle: tokio::runtime::Handle,
    uds_path: Option<PathBuf>,
) -> Box<dyn BitcoinAdapterClient> {
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
                            // Connect to a Uds socket
                            UnixStream::connect(uds_path.clone())
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
    pub btc_testnet_client: Box<dyn BitcoinAdapterClient>,
    pub btc_mainnet_client: Box<dyn BitcoinAdapterClient>,
}

pub fn setup_bitcoin_adapter_clients(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: tokio::runtime::Handle,
    adapters_config: AdaptersConfig,
) -> BitcoinAdapterClients {
    let metrics = Metrics::new(metrics_registry);
    BitcoinAdapterClients {
        btc_testnet_client: setup_bitcoin_adapter_client(
            log.clone(),
            metrics.clone(),
            rt_handle.clone(),
            adapters_config.bitcoin_testnet_uds_path,
        ),
        btc_mainnet_client: setup_bitcoin_adapter_client(
            log,
            metrics,
            rt_handle,
            adapters_config.bitcoin_mainnet_uds_path,
        ),
    }
}
