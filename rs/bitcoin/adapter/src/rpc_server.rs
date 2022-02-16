use crate::{
    adapter::Adapter,
    proto::{
        self,
        btc_adapter_server::{BtcAdapter, BtcAdapterServer},
        GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest,
        SendTransactionResponse,
    },
};
use bitcoin::{hashes::Hash, Block, BlockHash};
use ic_async_utils::{ensure_single_named_systemd_socket, incoming_from_first_systemd_socket};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

struct BtcAdapterImpl {
    adapter: Arc<Mutex<Adapter>>,
}

/// Converts a `Block` into a protobuf struct.
fn block_to_proto(block: &Block) -> proto::Block {
    proto::Block {
        header: Some(proto::BlockHeader {
            version: block.header.version,
            prev_blockhash: block.header.prev_blockhash.to_vec(),
            merkle_root: block.header.merkle_root.to_vec(),
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        }),
        txdata: block
            .txdata
            .iter()
            .map(|t| proto::Transaction {
                version: t.version,
                lock_time: t.lock_time,
                input: t
                    .input
                    .iter()
                    .map(|i| proto::TxIn {
                        previous_output: Some(proto::OutPoint {
                            txid: i.previous_output.txid.to_vec(),
                            vout: i.previous_output.vout,
                        }),
                        script_sig: i.script_sig.to_bytes(),
                        sequence: i.sequence,
                        witness: i.witness.clone(),
                    })
                    .collect(),
                output: t
                    .output
                    .iter()
                    .map(|o| proto::TxOut {
                        value: o.value,
                        script_pubkey: o.script_pubkey.to_bytes(),
                    })
                    .collect(),
            })
            .collect(),
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
        let blocks = self.adapter.lock().await.get_successors(block_hashes);
        Ok(Response::new(GetSuccessorsResponse {
            blocks: blocks.iter().map(|block| block_to_proto(block)).collect(),
        }))
    }

    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionResponse>, Status> {
        let transaction = request.into_inner().raw_tx;
        self.adapter.lock().await.send_transaction(transaction);
        Ok(Response::new(SendTransactionResponse {}))
    }
}

const IC_BTC_ADAPTER_SOCKET_NAME: &str = "ic-btc-adapter.socket";

/// Spawns in a separate Tokio task the BTC adapter gRPC service.
pub fn spawn_grpc_server(adapter: Arc<Mutex<Adapter>>) {
    // make sure we receive the correct socket from systemd (and only one)
    ensure_single_named_systemd_socket(IC_BTC_ADAPTER_SOCKET_NAME);

    tokio::spawn(async move {
        let btc_adapter_impl = BtcAdapterImpl { adapter };

        Server::builder()
            .add_service(BtcAdapterServer::new(btc_adapter_impl))
            .serve_with_incoming(incoming_from_first_systemd_socket())
            .await
            .expect("gRPC server crashed");
    });
}
