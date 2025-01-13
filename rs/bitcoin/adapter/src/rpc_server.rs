use crate::{
    blockchainstate::BlockchainState,
    config::{Config, IncomingSource},
    get_successors_handler::{GetSuccessorsRequest, GetSuccessorsResponse},
    metrics::{ServiceMetrics, LABEL_GET_SUCCESSOR, LABEL_SEND_TRANSACTION},
    BlockchainManagerRequest, GetSuccessorsHandler, TransactionManagerRequest,
};
use bitcoin::{consensus::Encodable, hashes::Hash, BlockHash};
use ic_btc_service::{
    btc_service_server::{BtcService, BtcServiceServer},
    BtcServiceGetSuccessorsRequest, BtcServiceGetSuccessorsResponse,
    BtcServiceSendTransactionRequest, BtcServiceSendTransactionResponse,
};
use ic_http_endpoints_async_utils::{incoming_from_nth_systemd_socket, incoming_from_path};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tonic::{transport::Server, Request, Response, Status};

struct BtcServiceImpl {
    last_received_tx: watch::Sender<Option<Instant>>,
    get_successors_handler: GetSuccessorsHandler,
    transaction_manager_tx: mpsc::Sender<TransactionManagerRequest>,
    logger: ReplicaLogger,
    metrics: ServiceMetrics,
}

impl TryFrom<BtcServiceGetSuccessorsRequest> for GetSuccessorsRequest {
    type Error = Status;

    fn try_from(request: BtcServiceGetSuccessorsRequest) -> Result<Self, Self::Error> {
        let anchor = BlockHash::from_slice(request.anchor.as_slice())
            .map_err(|_| Status::unknown("Failed to parse anchor hash!"))?;

        let processed_block_hashes = request
            .processed_block_hashes
            .iter()
            .map(|hash| {
                BlockHash::from_slice(hash.as_slice())
                    .map_err(|_| Status::unknown("Failed to read processed_block_hashes!"))
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(GetSuccessorsRequest {
            anchor,
            processed_block_hashes,
        })
    }
}

impl TryFrom<GetSuccessorsResponse> for BtcServiceGetSuccessorsResponse {
    type Error = Status;
    fn try_from(response: GetSuccessorsResponse) -> Result<Self, Self::Error> {
        let mut blocks = vec![];
        for block in response.blocks.iter() {
            let mut encoded_block = vec![];
            block
                .consensus_encode(&mut encoded_block)
                .map_err(|_| Status::unknown("Failed to encode block!"))?;
            blocks.push(encoded_block);
        }

        let mut next = vec![];
        for block_header in response.next.iter() {
            let mut encoded_block_header = vec![];
            block_header
                .consensus_encode(&mut encoded_block_header)
                .map_err(|_| Status::unknown("Failed to encode block header!"))?;
            next.push(encoded_block_header);
        }
        Ok(BtcServiceGetSuccessorsResponse { blocks, next })
    }
}

#[tonic::async_trait]
impl BtcService for BtcServiceImpl {
    async fn get_successors(
        &self,
        request: Request<BtcServiceGetSuccessorsRequest>,
    ) -> Result<Response<BtcServiceGetSuccessorsResponse>, Status> {
        let _timer = self
            .metrics
            .request_duration
            .with_label_values(&[LABEL_GET_SUCCESSOR])
            .start_timer();
        let _ = self.last_received_tx.send(Some(Instant::now()));
        let inner = request.into_inner();
        debug!(self.logger, "Received GetSuccessorsRequest: {:?}", inner);
        let request = inner.try_into()?;

        match BtcServiceGetSuccessorsResponse::try_from(
            self.get_successors_handler.get_successors(request).await?,
        ) {
            Ok(res) => {
                debug!(self.logger, "Sending GetSuccessorsResponse: {:?}", res);
                Ok(Response::new(res))
            }
            Err(err) => Err(err),
        }
    }

    async fn send_transaction(
        &self,
        request: Request<BtcServiceSendTransactionRequest>,
    ) -> Result<Response<BtcServiceSendTransactionResponse>, Status> {
        let _timer = self
            .metrics
            .request_duration
            .with_label_values(&[LABEL_SEND_TRANSACTION])
            .start_timer();
        let _ = self.last_received_tx.send(Some(Instant::now()));
        let transaction = request.into_inner().transaction;
        self.transaction_manager_tx
            .send(TransactionManagerRequest::SendTransaction(transaction))
            .await
            .expect(
                "Sending should not fail because we never close the receiving part of the channel.",
            );
        Ok(Response::new(BtcServiceSendTransactionResponse {}))
    }
}

/// Blocks until the server binds to the socket
pub fn start_grpc_server(
    config: Config,
    logger: ReplicaLogger,
    last_received_tx: watch::Sender<Option<Instant>>,
    blockchain_state: Arc<Mutex<BlockchainState>>,
    blockchain_manager_tx: mpsc::Sender<BlockchainManagerRequest>,
    transaction_manager_tx: mpsc::Sender<TransactionManagerRequest>,
    metrics_registry: &MetricsRegistry,
) {
    let get_successors_handler = GetSuccessorsHandler::new(
        &config,
        // The get successor handler should be low latency, and instead of not sharing state and
        // offloading the computation to an event loop here we directly access the shared state.
        blockchain_state,
        blockchain_manager_tx,
        metrics_registry,
    );

    let btc_adapter_impl = BtcServiceImpl {
        last_received_tx,
        get_successors_handler,
        transaction_manager_tx,
        logger,
        metrics: ServiceMetrics::new(metrics_registry),
    };

    match config.incoming_source {
        IncomingSource::Path(uds_path) => {
            let incoming = incoming_from_path(uds_path);
            let server_fut = Server::builder()
                .add_service(BtcServiceServer::new(btc_adapter_impl))
                .serve_with_incoming(incoming);
            tokio::spawn(async move {
                server_fut.await.expect("gRPC server crashed");
            });
        }
        IncomingSource::Systemd => {
            let incoming = unsafe { incoming_from_nth_systemd_socket(1) };
            let server_fut = Server::builder()
                .add_service(BtcServiceServer::new(btc_adapter_impl))
                // SAFETY: The process is managed by systemd and is configured to start with at least one socket.
                // Additionally this function is only called once here.
                // Systemd Socket config: ic-btc-<testnet,mainnet>-adapter.socket
                // Systemd Service config: ic-btc-<testnet,mainnet>-adapter.service
                .serve_with_incoming(incoming);
            tokio::spawn(async move {
                server_fut.await.expect("gRPC server crashed");
            });
        }
    };
}
