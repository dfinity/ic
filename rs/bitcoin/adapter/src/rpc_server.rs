use crate::{
    adapter::Adapter,
    blockchainmanager::{GetSuccessorsRequest, GetSuccessorsResponse},
};

use bitcoin::{hashes::Hash, Block, BlockHash, BlockHeader};
use ic_async_utils::{ensure_single_named_systemd_socket, incoming_from_first_systemd_socket};
use ic_btc_adapter_service::btc_adapter_server::{BtcAdapter, BtcAdapterServer};
use ic_protobuf::bitcoin::v1;
use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
};
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

struct BtcAdapterImpl {
    adapter: Arc<Mutex<Adapter>>,
}

fn header_to_proto(header: &BlockHeader) -> v1::BlockHeader {
    v1::BlockHeader {
        version: header.version,
        prev_blockhash: header.prev_blockhash.to_vec(),
        merkle_root: header.merkle_root.to_vec(),
        time: header.time,
        bits: header.bits,
        nonce: header.nonce,
    }
}

/// Converts a `Block` into a protobuf struct.
fn block_to_proto(block: &Block) -> v1::Block {
    v1::Block {
        header: Some(header_to_proto(&block.header)),
        txdata: block
            .txdata
            .iter()
            .map(|t| v1::Transaction {
                version: t.version,
                lock_time: t.lock_time,
                input: t
                    .input
                    .iter()
                    .map(|i| v1::TxIn {
                        previous_output: Some(v1::OutPoint {
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
                    .map(|o| v1::TxOut {
                        value: o.value,
                        script_pubkey: o.script_pubkey.to_bytes(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

impl TryFrom<v1::GetSuccessorsRequest> for GetSuccessorsRequest {
    type Error = Status;

    fn try_from(request: v1::GetSuccessorsRequest) -> Result<Self, Self::Error> {
        let anchor = BlockHash::from_slice(request.anchor.as_slice())
            .map_err(|_| Status::internal("Failed to parse anchor hash!"))?;

        let processed_block_hashes = request
            .processed_block_hashes
            .into_iter()
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

impl From<GetSuccessorsResponse> for v1::GetSuccessorsResponse {
    fn from(response: GetSuccessorsResponse) -> Self {
        v1::GetSuccessorsResponse {
            blocks: response.blocks.iter().map(block_to_proto).collect(),
            next: response.next.iter().map(header_to_proto).collect(),
        }
    }
}

#[tonic::async_trait]
impl BtcAdapter for BtcAdapterImpl {
    async fn get_successors(
        &self,
        request: Request<v1::GetSuccessorsRequest>,
    ) -> Result<Response<v1::GetSuccessorsResponse>, Status> {
        let request = request.into_inner().try_into()?;
        let response = self.adapter.lock().await.get_successors(request);
        Ok(Response::new(response.into()))
    }

    async fn send_transaction(
        &self,
        request: Request<v1::SendTransactionRequest>,
    ) -> Result<Response<v1::SendTransactionResponse>, Status> {
        let transaction = request.into_inner().transaction;
        self.adapter.lock().await.send_transaction(transaction);
        Ok(Response::new(v1::SendTransactionResponse {}))
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
