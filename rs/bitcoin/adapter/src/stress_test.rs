use std::{convert::TryFrom, path::PathBuf, time::Duration};

use bitcoin::{blockdata::constants::genesis_block, consensus::Decodable, Block, BlockHash};
use clap::Parser;
use ic_btc_service::{
    btc_service_client::BtcServiceClient, BtcServiceGetSuccessorsRequest,
    BtcServiceGetSuccessorsResponse,
};
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

async fn setup_client(uds_path: PathBuf) -> BtcServiceClient<Channel> {
    let channel = setup_channel(uds_path).await;
    BtcServiceClient::new(channel)
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
    let interval_sleep_ms = Duration::from_millis(1000);
    let request_timeout_ms = Duration::from_millis(50);

    let block_0 = genesis_block(config.network);
    let mut total_processed_block_hashes: usize = 0;
    let mut processed_block_hashes: Vec<BlockHash> = vec![];
    let mut current_anchor = block_0.block_hash();
    let mut rpc_client = setup_client(uds_path).await;
    let total_timer = Instant::now();

    loop {
        let mut request = tonic::Request::new(BtcServiceGetSuccessorsRequest {
            processed_block_hashes: processed_block_hashes.iter().map(|h| h.to_vec()).collect(),
            anchor: current_anchor.to_vec(),
        });
        request.set_timeout(request_timeout_ms);

        let instant = Instant::now();

        let response: Result<tonic::Response<BtcServiceGetSuccessorsResponse>, tonic::Status> =
            rpc_client.get_successors(request).await;
        let inner: BtcServiceGetSuccessorsResponse = match response {
            Ok(response) => response.into_inner(),
            Err(status) => match status.code() {
                tonic::Code::Cancelled => continue,
                _ => break,
            },
        };

        let elapsed = instant.elapsed().as_millis();
        if !inner.blocks.is_empty() {
            let block_hashes = inner
                .blocks
                .iter()
                .map(|b| Block::consensus_decode(b.as_slice()).unwrap().block_hash())
                .collect::<Vec<_>>();

            current_anchor = *block_hashes.last().expect("failed to get last block hash");
            total_processed_block_hashes += block_hashes.len();
            processed_block_hashes = block_hashes;
        }

        println!(
            "{}s,{}ms,{},{},{}",
            total_timer.elapsed().as_secs(),
            elapsed,
            inner.blocks.len(),
            inner.next.len(),
            total_processed_block_hashes
        );

        sleep(interval_sleep_ms).await;
    }
}
