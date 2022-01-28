use crate::{
    blockchainmanager::BlockchainManager,
    proto::btc_adapter_server::{BtcAdapter, BtcAdapterServer},
    proto::{
        GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest,
        SendTransactionResponse,
    },
    transaction_manager::TransactionManager,
    utils::block_to_proto,
    HandleClientRequest,
};
use bitcoin::{hashes::Hash, BlockHash};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};

#[derive(Debug)]
struct BtcAdapterImpl {
    blocks: Arc<Mutex<BlockchainManager>>,
    transactions: Arc<Mutex<TransactionManager>>,
}

impl BtcAdapterImpl {
    fn new(
        blocks: Arc<Mutex<BlockchainManager>>,
        transactions: Arc<Mutex<TransactionManager>>,
    ) -> BtcAdapterImpl {
        Self {
            blocks,
            transactions,
        }
    }
}

#[tonic::async_trait]
impl BtcAdapter for BtcAdapterImpl {
    async fn get_successors(
        &self,
        request: Request<GetSuccessorsRequest>,
    ) -> Result<Response<GetSuccessorsResponse>, Status> {
        let block_hashes = request
            .into_inner()
            .block_hashes
            .iter()
            .filter_map(|hash| BlockHash::from_slice(hash.as_slice()).ok())
            .collect();

        let mut blocks_guard = self.blocks.lock().unwrap();
        let blocks = blocks_guard.handle_client_request(block_hashes);

        Ok(Response::new(GetSuccessorsResponse {
            blocks: blocks.iter().map(|block| block_to_proto(block)).collect(),
        }))
    }

    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionResponse>, Status> {
        let transaction = request.into_inner().raw_tx;
        let mut transactions_guard = self.transactions.lock().unwrap();
        transactions_guard.send_transaction(&transaction);
        Ok(Response::new(SendTransactionResponse {}))
    }
}

/// Spawns in a separate Tokio task the BTC adapter gRPC service.
pub fn spawn_grpc_server(
    blockchain_manager: Arc<Mutex<BlockchainManager>>,
    transaction_manager: Arc<Mutex<TransactionManager>>,
) {
    // TODO: ER-2125: gRPC server needs configuration values
    let addr = "0.0.0.0:34254"
        .parse()
        .expect("Failed to parse gRPC address");
    tokio::spawn(async move {
        let btc_adapter_impl = BtcAdapterImpl::new(blockchain_manager, transaction_manager);

        Server::builder()
            .add_service(BtcAdapterServer::new(btc_adapter_impl))
            .serve(addr)
            .await
            .expect("gRPC server crashed");
    });
}
