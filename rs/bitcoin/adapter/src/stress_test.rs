use std::{convert::TryFrom, path::PathBuf, time::Duration};

use bitcoin::Network;
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

async fn setup_channel(uds_path: PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .expect("failed to make endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let uds_path = uds_path.clone();
            async move {
                // Connect to a Uds socket
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    UnixStream::connect(uds_path).await?,
                ))
            }
        }))
        .await
        .expect("failed to connect to socket")
}

async fn setup_client(uds_path: PathBuf) -> BtcServiceClient<Channel> {
    let channel = setup_channel(uds_path).await;
    BtcServiceClient::new(channel)
}

/// This struct is use to provide a command line interface to the adapter.
#[derive(Parser)]
#[clap(version = "0.0.0", author = "DFINITY team <team@dfinity.org>")]
pub struct Cli {
    /// This field contains the path to the config file.
    pub network: Network,
    pub uds_path: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let interval_sleep_ms = Duration::from_millis(1000);
    let request_timeout_ms = Duration::from_millis(50);

    let block_0 = genesis_block(cli.network);
    let mut total_processed_block_hashes: usize = 0;
    let mut processed_block_hashes: Vec<BlockHash> = vec![];
    let mut current_anchor = block_0.block_hash();
    let mut rpc_client = setup_client(cli.uds_path).await;
    let total_timer = Instant::now();

    loop {
        let mut request = tonic::Request::new(BtcServiceGetSuccessorsRequest {
            processed_block_hashes: processed_block_hashes
                .iter()
                .map(|h| h[..].to_vec())
                .collect(),
            anchor: current_anchor[..].to_vec(),
        });
        request.set_timeout(request_timeout_ms);

        let instant = Instant::now();

        let response: Result<tonic::Response<BtcServiceGetSuccessorsResponse>, tonic::Status> =
            rpc_client.get_successors(request).await;
        let inner: BtcServiceGetSuccessorsResponse = match response {
            Ok(response) => response.into_inner(),
            Err(status) => match status.code() {
                tonic::Code::Cancelled | tonic::Code::Unavailable => continue,
                _ => break,
            },
        };

        let elapsed = instant.elapsed().as_millis();
        if !inner.blocks.is_empty() {
            let block_hashes = inner
                .blocks
                .iter()
                .map(|b| {
                    Block::consensus_decode(&mut b.as_slice())
                        .unwrap()
                        .block_hash()
                })
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
