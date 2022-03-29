use std::{convert::TryFrom, path::PathBuf, time::Duration};

use bitcoin::{
    blockdata::constants::genesis_block, hashes::Hash, BlockHash, BlockHeader, TxMerkleNode,
};
use clap::Parser;
use ic_btc_adapter_service::btc_adapter_client::BtcAdapterClient;
use ic_protobuf::bitcoin::v1;
use tokio::{
    net::UnixStream,
    time::{sleep, Instant},
};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use ic_btc_adapter::{Cli, IncomingSource};

async fn setup_channel(uds_path: PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .expect("failed to make endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            UnixStream::connect(uds_path.clone())
        }))
        .await
        .expect("failed to connect to socket")
}

async fn setup_client(uds_path: PathBuf) -> BtcAdapterClient<Channel> {
    let channel = setup_channel(uds_path).await;
    BtcAdapterClient::new(channel)
}

fn proto_to_header(proto: v1::BlockHeader) -> BlockHeader {
    BlockHeader {
        version: proto.version,
        prev_blockhash: BlockHash::from_slice(&proto.prev_blockhash)
            .expect("failed to make hash from slice"),
        merkle_root: TxMerkleNode::from_slice(&proto.merkle_root)
            .expect("failed to make merkle node from slice"),
        time: proto.time,
        bits: proto.bits,
        nonce: proto.nonce,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = cli.get_config().expect("Error while reading config file.");
    let uds_path = if let IncomingSource::Path(uds_path) = config.incoming_source {
        uds_path
    } else {
        panic!("Cannot use systemd as a incoming source.");
    };

    let mut processed_block_hashes: Vec<BlockHash> = vec![];
    let block_0 = genesis_block(config.network);
    let mut current_anchor = block_0.block_hash();
    let mut rpc_client = setup_client(uds_path).await;

    loop {
        let request = tonic::Request::new(v1::GetSuccessorsRequest {
            processed_block_hashes: processed_block_hashes.iter().map(|h| h.to_vec()).collect(),
            anchor: current_anchor.to_vec(),
        });

        let instant = Instant::now();
        let response = rpc_client
            .get_successors(request)
            .await
            .expect("failed to receive response");
        let elapsed = instant.elapsed().as_millis();
        let inner = response.into_inner();
        println!(
            "{}ms,{},{},{}",
            elapsed,
            inner.blocks.len(),
            inner.next.len(),
            processed_block_hashes.len()
        );

        if !inner.blocks.is_empty() {
            let block_hashes = inner
                .blocks
                .into_iter()
                .map(|b| proto_to_header(b.header.expect("missing header")).block_hash())
                .collect::<Vec<_>>();

            current_anchor = *block_hashes.last().expect("failed to get last block hash");
            processed_block_hashes = block_hashes;
        }

        sleep(Duration::from_millis(1000)).await;
    }
}
