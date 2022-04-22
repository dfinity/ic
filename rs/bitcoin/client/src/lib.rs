use bitcoin::consensus::Decodable;
use ic_btc_service::{
    btc_service_client::BtcServiceClient, BtcServiceGetSuccessorsRequest,
    BtcServiceSendTransactionRequest,
};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, Block as InternalBlock,
    BlockHeader as InternalBlockHeader, GetSuccessorsResponse, OutPoint as InternalOutPoint,
    SendTransactionResponse, Transaction as InternalTransaction, TxIn as InternalTxIn,
    TxOut as InternalTxOut, Txid as InternalTxid,
};
use ic_interfaces_bitcoin_adapter_client::{BitcoinAdapterClient, Options, RpcError, RpcResult};
use ic_logger::{error, ReplicaLogger};
use std::{convert::TryFrom, path::PathBuf, sync::Arc};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

fn convert_tonic_error(status: tonic::Status) -> RpcError {
    RpcError::ServerError {
        status_code: status.code() as u16,
        message: status.message().to_string(),
        source: Box::new(status),
    }
}

struct BitcoinAdapterClientImpl {
    rt_handle: tokio::runtime::Handle,
    client: BtcServiceClient<Channel>,
}

impl BitcoinAdapterClientImpl {
    fn new(rt_handle: tokio::runtime::Handle, channel: Channel) -> Self {
        let client = BtcServiceClient::new(channel);
        Self { rt_handle, client }
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
            .map(|v| serde_bytes::ByteBuf::from(v.clone()))
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
        let mut client = self.client.clone();
        self.rt_handle.block_on(async move {
            match request {
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(r) => {
                    let get_successors_request = BtcServiceGetSuccessorsRequest {
                        processed_block_hashes: r.processed_block_hashes,
                        anchor: r.anchor,
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
                                let bitcoin_block = bitcoin::Block::consensus_decode(&*b).unwrap();
                                blocks.push(to_internal_block(&bitcoin_block));
                            }
                            let mut next = vec![];
                            for n in inner.next.into_iter() {
                                let bitcoin_block_header =
                                    bitcoin::BlockHeader::consensus_decode(&*n).unwrap();
                                next.push(to_internal_block_header(&bitcoin_block_header));
                            }
                            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(
                                GetSuccessorsResponse { blocks, next },
                            )
                        })
                        .map_err(convert_tonic_error)
                }
                BitcoinAdapterRequestWrapper::SendTransactionRequest(r) => {
                    let send_transaction_request = BtcServiceSendTransactionRequest {
                        transaction: r.transaction,
                    };
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
            }
        })
    }
}

struct BrokenConnectionBitcoinClient();

impl BitcoinAdapterClient for BrokenConnectionBitcoinClient {
    fn send_request(
        &self,
        _request: BitcoinAdapterRequestWrapper,
        _opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper> {
        Err(RpcError::ConnectionBroken)
    }
}

pub fn setup_bitcoin_adapter_client(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    uds_path: Option<PathBuf>,
) -> Arc<dyn BitcoinAdapterClient> {
    match uds_path {
        None => Arc::new(BrokenConnectionBitcoinClient()),
        Some(uds_path) => {
            // We will ignore this uri because uds do not use it
            // if your connector does use the uri it will be provided
            // as the request to the `MakeConnection`.
            match Endpoint::try_from("http://[::]:50051") {
                Ok(endpoint) => {
                    match endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
                        // Connect to a Uds socket
                        UnixStream::connect(uds_path.clone())
                    })) {
                        Ok(channel) => Arc::new(BitcoinAdapterClientImpl::new(rt_handle, channel)),
                        Err(_) => {
                            error!(log, "Could not connect endpoint.");
                            Arc::new(BrokenConnectionBitcoinClient())
                        }
                    }
                }
                Err(_) => {
                    error!(log, "Could not create an endpoint.");
                    Arc::new(BrokenConnectionBitcoinClient())
                }
            }
        }
    }
}
