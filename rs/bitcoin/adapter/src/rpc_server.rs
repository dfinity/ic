use crate::{
    get_successors_handler::{GetSuccessorsRequest, GetSuccessorsResponse},
    AdapterState, Config, GetSuccessorsHandler, IncomingSource, TransactionManagerRequest,
};
use bitcoin::{consensus::Encodable, hashes::Hash, BlockHash};
use ic_async_utils::{
    ensure_single_systemd_socket, incoming_from_first_systemd_socket, incoming_from_path,
};
use ic_btc_adapter_service::{
    btc_adapter_server::{BtcAdapter, BtcAdapterServer},
    GetSuccessorsRpcRequest, GetSuccessorsRpcResponse, SendTransactionRpcRequest,
    SendTransactionRpcResponse,
};
use std::convert::{TryFrom, TryInto};
use tokio::sync::mpsc::UnboundedSender;
use tonic::{transport::Server, Request, Response, Status};

struct BtcAdapterImpl {
    adapter_state: AdapterState,
    get_successors_handler: GetSuccessorsHandler,
    transaction_manager_tx: UnboundedSender<TransactionManagerRequest>,
}

impl TryFrom<GetSuccessorsRpcRequest> for GetSuccessorsRequest {
    type Error = Status;

    fn try_from(request: GetSuccessorsRpcRequest) -> Result<Self, Self::Error> {
        let anchor = BlockHash::from_slice(request.anchor.as_slice())
            .map_err(|_| Status::internal("Failed to parse anchor hash!"))?;

        let processed_block_hashes = request
            .processed_block_hashes
            .iter()
            .map(|hash| {
                BlockHash::from_slice(hash.as_slice())
                    .map_err(|_| Status::internal("Failed to read processed_block_hashes!"))
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(GetSuccessorsRequest {
            anchor,
            processed_block_hashes,
        })
    }
}

impl TryFrom<GetSuccessorsResponse> for GetSuccessorsRpcResponse {
    type Error = Status;
    fn try_from(response: GetSuccessorsResponse) -> Result<Self, Self::Error> {
        let mut blocks = vec![];
        for block in response.blocks.iter() {
            let mut encoded_block = vec![];
            block
                .consensus_encode(&mut encoded_block)
                .map_err(|_| Status::internal("Failed to encode block!"))?;
            blocks.push(encoded_block);
        }

        let mut next = vec![];
        for block_header in response.next.iter() {
            let mut encoded_block_header = vec![];
            block_header
                .consensus_encode(&mut encoded_block_header)
                .map_err(|_| Status::internal("Failed to encode block header!"))?;
            next.push(encoded_block_header);
        }
        Ok(GetSuccessorsRpcResponse { blocks, next })
    }
}

#[tonic::async_trait]
impl BtcAdapter for BtcAdapterImpl {
    async fn get_successors(
        &self,
        request: Request<GetSuccessorsRpcRequest>,
    ) -> Result<Response<GetSuccessorsRpcResponse>, Status> {
        self.adapter_state.received_now();
        let request = request.into_inner().try_into()?;
        match GetSuccessorsRpcResponse::try_from(
            self.get_successors_handler.get_successors(request).await,
        ) {
            Ok(res) => Ok(Response::new(res)),
            Err(err) => Err(err),
        }
    }

    async fn send_transaction(
        &self,
        request: Request<SendTransactionRpcRequest>,
    ) -> Result<Response<SendTransactionRpcResponse>, Status> {
        self.adapter_state.received_now();
        let transaction = request.into_inner().transaction;
        self.transaction_manager_tx
            .send(TransactionManagerRequest::SendTransaction(transaction))
            .expect(
                "Sending should not fail because we never close the receiving part of the channel.",
            );
        Ok(Response::new(SendTransactionRpcResponse {}))
    }
}

/// Spawns in a separate Tokio task the BTC adapter gRPC service.
pub fn spawn_grpc_server(
    config: Config,
    adapter_state: AdapterState,
    get_successors_handler: GetSuccessorsHandler,
    transaction_manager_tx: UnboundedSender<TransactionManagerRequest>,
) {
    // make sure we receive only one socket from systemd
    if config.incoming_source == IncomingSource::Systemd {
        ensure_single_systemd_socket();
    }
    let btc_adapter_impl = BtcAdapterImpl {
        adapter_state,
        get_successors_handler,
        transaction_manager_tx,
    };
    tokio::spawn(async move {
        match config.incoming_source {
            IncomingSource::Path(uds_path) => {
                Server::builder()
                    .add_service(BtcAdapterServer::new(btc_adapter_impl))
                    .serve_with_incoming(incoming_from_path(uds_path))
                    .await
                    .expect("gRPC server crashed");
            }
            IncomingSource::Systemd => {
                Server::builder()
                    .add_service(BtcAdapterServer::new(btc_adapter_impl))
                    .serve_with_incoming(incoming_from_first_systemd_socket())
                    .await
                    .expect("gRPC server crashed");
            }
        };
    });
}
