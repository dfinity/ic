use bitcoin::{blockdata::constants::genesis_block, BlockHash, BlockHeader, Network};
use criterion::{criterion_group, criterion_main, Criterion};
use ic_btc_adapter::config::Config;
use ic_btc_adapter::config::IncomingSource;
use ic_btc_adapter::start_server;
use ic_btc_adapter_client::setup_bitcoin_adapter_clients;
use ic_btc_adapter_test_utils::generate_headers;
use ic_btc_replica_types::BitcoinAdapterRequestWrapper;
use ic_btc_replica_types::BitcoinAdapterResponseWrapper;
use ic_btc_replica_types::GetSuccessorsRequestInitial;
use ic_config::adapters::AdaptersConfig;
use ic_config::bitcoin_payload_builder_config::Config as BitcoinPayloadBuilderConfig;
use ic_interfaces_adapter_client::Options;
use ic_interfaces_adapter_client::RpcAdapterClient;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use std::path::Path;
use tempfile::Builder;

type BitcoinAdapterClient = Box<
    dyn RpcAdapterClient<BitcoinAdapterRequestWrapper, Response = BitcoinAdapterResponseWrapper>,
>;

async fn start_client(uds_path: &Path) -> BitcoinAdapterClient {
    let adapters_config = AdaptersConfig {
        bitcoin_mainnet_uds_path: Some(uds_path.into()),
        ..Default::default()
    };

    setup_bitcoin_adapter_clients(
        no_op_logger(),
        &MetricsRegistry::default(),
        tokio::runtime::Handle::current(),
        adapters_config,
    )
    .btc_mainnet_client
}

fn prepare(
    processed_block_hashes: &mut Vec<BlockHash>,
    genesis: BlockHeader,
    forks_num: usize,
    fork_len: usize,
    processed_fork_len: usize,
) {
    let mut prev_hashes = vec![];
    for _ in 0..forks_num {
        let fork = generate_headers(
            genesis.block_hash(),
            genesis.time,
            fork_len as u32,
            &prev_hashes,
        );
        prev_hashes.extend(fork.iter().map(|h| h.block_hash()).collect::<Vec<_>>());
        processed_block_hashes.extend(
            fork[0..processed_fork_len]
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );
    }
}

fn e2e(criterion: &mut Criterion) {
    let mut config = Config {
        network: Network::Regtest,
        ..Default::default()
    };

    let mut processed_block_hashes = vec![];
    let genesis = genesis_block(config.network).header;

    prepare(&mut processed_block_hashes, genesis, 4, 2000, 1975);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (client, _temp) = Builder::new()
        .make(|uds_path| {
            Ok(rt.block_on(async {
                config.incoming_source = IncomingSource::Path(uds_path.to_path_buf());

                start_server(
                    &no_op_logger(),
                    &MetricsRegistry::default(),
                    rt.handle(),
                    config.clone(),
                );
                start_client(uds_path).await
            }))
        })
        .unwrap()
        .into_parts();

    // Request the last 25 blocks of each fork by marking the previous ones as processed.
    let get_successors_request: GetSuccessorsRequestInitial = GetSuccessorsRequestInitial {
        anchor: genesis.block_hash()[..].to_vec(),
        processed_block_hashes: processed_block_hashes
            .iter()
            .map(|h| h[..].to_vec())
            .collect::<Vec<Vec<u8>>>(),
        network: ic_btc_interface::Network::Regtest,
    };

    let wrapped = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(get_successors_request);

    // Benchmark from the sending of the deserialised request through to receiving the response and its deserialisation.
    criterion.bench_function("e2e", |bench| {
        bench.iter(|| {
            // The adapter will do a BFS, going through all the blocks in the forks until enough unprocessed blocks are collected.
            client
                .send_blocking(
                    wrapped.clone(),
                    Options {
                        timeout: BitcoinPayloadBuilderConfig::default().adapter_timeout,
                    },
                )
                .expect("Failed to send request.");
        })
    });
}

// This simulation constructs a blockchain comprising four forks, each of 2000 blocks.
// For an extended BFS execution, the initial 1975 blocks of every branch are marked in
// the request as being processed, with the aim to receive the last 25 blocks of each fork.
// Performance metrics are captured from the sending of the deserialised request through
// to receiving the response and its deserialisation.
criterion_group!(benches, e2e);

// The benchmark can be run using:
// bazel run //rs/bitcoin/adapter:e2e_bench
criterion_main!(benches);
