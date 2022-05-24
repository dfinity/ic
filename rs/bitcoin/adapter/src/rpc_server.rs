use crate::{
    config::{Config, IncomingSource},
    get_successors_handler::{GetSuccessorsRequest, GetSuccessorsResponse},
    AdapterState, GetSuccessorsHandler, TransactionManagerRequest,
};
use bitcoin::{consensus::Encodable, hashes::Hash, BlockHash};
use ic_async_utils::{
    ensure_single_systemd_socket, incoming_from_first_systemd_socket, incoming_from_path,
};
use ic_btc_service::{
    btc_service_server::{BtcService, BtcServiceServer},
    BtcServiceGetSuccessorsRequest, BtcServiceGetSuccessorsResponse,
    BtcServiceSendTransactionRequest, BtcServiceSendTransactionResponse,
};
use ic_logger::{debug, ReplicaLogger};
use std::convert::{TryFrom, TryInto};
use tokio::sync::mpsc::Sender;
use tonic::{transport::Server, Request, Response, Status};

struct BtcServiceImpl {
    adapter_state: AdapterState,
    get_successors_handler: GetSuccessorsHandler,
    transaction_manager_tx: Sender<TransactionManagerRequest>,
    logger: ReplicaLogger,
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
        self.adapter_state.received_now();
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
        self.adapter_state.received_now();
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

/// Spawns in a separate Tokio task the BTC adapter gRPC service.
pub fn spawn_grpc_server(
    config: Config,
    logger: ReplicaLogger,
    adapter_state: AdapterState,
    get_successors_handler: GetSuccessorsHandler,
    transaction_manager_tx: Sender<TransactionManagerRequest>,
) {
    // make sure we receive only one socket from systemd
    if config.incoming_source == IncomingSource::Systemd {
        ensure_single_systemd_socket();
    }
    let btc_adapter_impl = BtcServiceImpl {
        adapter_state,
        get_successors_handler,
        transaction_manager_tx,
        logger,
    };
    tokio::spawn(async move {
        match config.incoming_source {
            IncomingSource::Path(uds_path) => {
                Server::builder()
                    .add_service(BtcServiceServer::new(btc_adapter_impl))
                    .serve_with_incoming(incoming_from_path(uds_path))
                    .await
                    .expect("gRPC server crashed");
            }
            IncomingSource::Systemd => {
                Server::builder()
                    .add_service(BtcServiceServer::new(btc_adapter_impl))
                    .serve_with_incoming(incoming_from_first_systemd_socket())
                    .await
                    .expect("gRPC server crashed");
            }
        };
    });
}
