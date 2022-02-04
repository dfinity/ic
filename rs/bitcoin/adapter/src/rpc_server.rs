use crate::{
    adapter::{AdapterRequest, AdapterRequestWithCallback, AdapterResponse},
    proto::{
        self,
        btc_adapter_server::{BtcAdapter, BtcAdapterServer},
        GetSuccessorsRequest, GetSuccessorsResponse, SendTransactionRequest,
        SendTransactionResponse,
    },
};
use bitcoin::{hashes::Hash, Block, BlockHash};
use std::fmt::Debug;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tonic::{transport::Server, Request, Response, Status};

#[derive(Debug)]
struct BtcAdapterImpl {
    sender: UnboundedSender<AdapterRequestWithCallback>,
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
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((AdapterRequest::GetSuccessors(block_hashes), tx))
            .map_err(|e| Status::internal(format!("{}", e)))?;
        let res = rx.await.map_err(|e| Status::internal(format!("{}", e)))?;
        match res {
            AdapterResponse::GetSuccessors(blocks) => Ok(Response::new(GetSuccessorsResponse {
                blocks: blocks.iter().map(|block| block_to_proto(block)).collect(),
            })),
            _ => Err(Status::internal("Adapter returned mismaching response?!")),
        }
    }

    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionResponse>, Status> {
        let transaction = request.into_inner().raw_tx;
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((AdapterRequest::SendTransaction(transaction), tx))
            .map_err(|e| Status::internal(format!("{}", e)))?;
        let res = rx.await.map_err(|e| Status::internal(format!("{}", e)))?;
        match res {
            AdapterResponse::SendTransaction => Ok(Response::new(SendTransactionResponse {})),
            _ => Err(Status::internal("Adapter returned mismaching response?!")),
        }
    }
}

/// Spawns in a separate Tokio task the BTC adapter gRPC service.
pub fn spawn_grpc_server(sender: UnboundedSender<AdapterRequestWithCallback>) {
    // TODO: ER-2125: gRPC server needs configuration values
    let addr = "0.0.0.0:34254"
        .parse()
        .expect("Failed to parse gRPC address");
    tokio::spawn(async move {
        let btc_adapter_impl = BtcAdapterImpl { sender };

        Server::builder()
            .add_service(BtcAdapterServer::new(btc_adapter_impl))
            .serve(addr)
            .await
            .expect("gRPC server crashed");
    });
}
