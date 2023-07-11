use bitcoin::{consensus::encode::deserialize, Address, Amount, Block};
use bitcoincore_rpc::{bitcoincore_rpc_json::CreateRawTransactionInput, Auth, Client, RpcApi};
use bitcoind::{BitcoinD, Conf, P2P};
use ic_btc_adapter::{
    config::{Config, IncomingSource},
    start_grpc_server_and_router, AdapterState,
};
use ic_btc_adapter_client::setup_bitcoin_adapter_clients;
use ic_btc_interface::Network;
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, GetSuccessorsRequestInitial,
    SendTransactionRequest,
};
use ic_config::adapters::AdaptersConfig;
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
    path::Path,
    str::FromStr,
};
use tempfile::{Builder, TempPath};
use tokio::runtime::Runtime;

type BitcoinAdapterClient = Box<
    dyn RpcAdapterClient<BitcoinAdapterRequestWrapper, Response = BitcoinAdapterResponseWrapper>,
>;

struct AdapterClientWrapper(BitcoinAdapterClient);

impl AdapterClientWrapper {
    async fn new(
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
        uds_path: &Path,
    ) -> Self {
        let client = start_client(metrics_registry, logger, uds_path).await;
        Self(client)
    }

    fn get_successors(
        &self,
        anchor: Vec<u8>,
        headers: Vec<Vec<u8>>,
    ) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
        let request =
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
                network: Network::Regtest,
                anchor,
                processed_block_hashes: headers,
            });

        self.0.send_blocking(request, Options::default())
    }

    fn send_tx(
        &self,
        raw_tx: &[u8],
    ) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
        let request =
            BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
                network: Network::Regtest,
                transaction: raw_tx.to_vec(),
            });

        self.0.send_blocking(request, Options::default())
    }
}

async fn start_adapter(
    logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    nodes: Vec<SocketAddr>,
    uds_path: &Path,
) {
    let config = Config {
        network: bitcoin::Network::Regtest,
        incoming_source: IncomingSource::Path(uds_path.to_path_buf()),
        nodes,
        ipv6_only: true,
        ..Default::default()
    };

    let adapter_state = AdapterState::new(config.idle_seconds);

    // make sure that the adapter is not idle
    adapter_state.received_now();

    start_grpc_server_and_router(&config, &metrics_registry, logger, adapter_state);
}

fn get_default_bitcoind() -> BitcoinD {
    let mut conf = Conf::default();
    conf.p2p = P2P::Yes;

    let path =
        std::env::var("BITCOIN_CORE_PATH").expect("Failed to get bitcoin core path env variable");

    bitcoind::BitcoinD::with_conf(path, &conf).unwrap()
}

async fn start_client(
    metrics_registry: MetricsRegistry,
    logger: ReplicaLogger,
    uds_path: &Path,
) -> BitcoinAdapterClient {
    let adapters_config = AdaptersConfig {
        bitcoin_mainnet_uds_path: Some(uds_path.into()),
        bitcoin_mainnet_uds_metrics_path: None,
        bitcoin_testnet_uds_path: None,
        bitcoin_testnet_uds_metrics_path: None,
        https_outcalls_uds_path: None,
        https_outcalls_uds_metrics_path: None,
        onchain_observability_enable_grpc_server: false,
        onchain_observability_uds_metrics_path: None,
    };

    setup_bitcoin_adapter_clients(
        logger,
        &metrics_registry,
        tokio::runtime::Handle::current(),
        adapters_config,
    )
    .btc_mainnet_client
}

fn check_received_blocks(client: &Client, blocks: &[Vec<u8>], start_index: usize) {
    for (h, block) in blocks.iter().enumerate() {
        assert_eq!(
            *block,
            client.get_block_hash((start_index + h + 1) as u64).unwrap()[..].to_vec()
        );
    }
}

fn get_bitcoind_url(bitcoind: &BitcoinD) -> Option<SocketAddrV4> {
    if let P2P::Connect(url, _) = bitcoind.p2p_connect(true).unwrap() {
        Some(url)
    } else {
        None
    }
}

fn sync_until_end_block(
    adapter_client: &AdapterClientWrapper,
    client: &Client,
    start_index: u64,
    headers: &mut Vec<Vec<u8>>,
) -> Vec<Block> {
    let mut blocks = vec![];
    let mut anchor = client.get_block_hash(start_index).unwrap()[..].to_vec();

    let end_hash = client.get_best_block_hash().unwrap()[..].to_vec();
    while anchor != end_hash {
        let res = adapter_client.get_successors(anchor.clone(), headers.clone());
        match res {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(res)) => {
                let new_blocks = res.blocks;
                if !new_blocks.is_empty() {
                    let new_headers: Vec<Vec<u8>> = new_blocks
                        .iter()
                        .map(|block| deserialize::<Block>(block).unwrap().block_hash()[..].to_vec())
                        .collect();

                    check_received_blocks(
                        client,
                        &new_headers,
                        start_index as usize + blocks.len(),
                    );

                    headers.extend(new_headers);

                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                    anchor = headers.last().unwrap().clone();
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) => (), // Adapter still syncing headers
            Err(err) => panic!("{:?}", err),
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

fn start_adapter_and_client(
    rt: &Runtime,
    urls: Vec<SocketAddr>,
    logger: ReplicaLogger,
) -> (AdapterClientWrapper, TempPath) {
    Builder::new()
        .make(|uds_path| {
            Ok(rt.block_on(async {
                let metrics_registry = MetricsRegistry::new();

                start_adapter(
                    logger.clone(),
                    metrics_registry.clone(),
                    urls.clone(),
                    uds_path,
                )
                .await;

                // Start the client
                AdapterClientWrapper::new(metrics_registry, logger.clone(), uds_path).await
            }))
        })
        .unwrap()
        .into_parts()
}

fn get_blackhole_address() -> Address {
    Address::from_str("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn").unwrap()
}

fn create_alice_and_bob_wallets(bitcoind: &BitcoinD) -> (Client, Client, Address, Address) {
    let alice_client = Client::new(
        format!("{}/wallet/{}", bitcoind.rpc_url(), "alice").as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();
    alice_client
        .create_wallet("alice", None, None, None, None)
        .unwrap();

    let bob_client = Client::new(
        format!("{}/wallet/{}", bitcoind.rpc_url(), "bob").as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();
    bob_client
        .create_wallet("bob", None, None, None, None)
        .unwrap();

    let alice_address = alice_client.get_new_address(None, None).unwrap();
    let bob_address = bob_client.get_new_address(None, None).unwrap();

    (alice_client, bob_client, alice_address, bob_address)
}

fn fund_with_btc(to_fund_client: &Client, to_fund_address: &Address) {
    let initial_amount = to_fund_client
        .get_received_by_address(to_fund_address, Some(0))
        .unwrap()
        .as_btc();

    to_fund_client
        .generate_to_address(1, to_fund_address)
        .unwrap();

    // Generate 100 blocks for coinbase maturity
    to_fund_client
        .generate_to_address(100, &get_blackhole_address())
        .unwrap();

    // The reward for mining a block is 50 bitcoins
    assert_eq!(
        to_fund_client
            .get_received_by_address(to_fund_address, Some(0))
            .unwrap(),
        Amount::from_btc(initial_amount + 50.0).unwrap()
    );
}

/// Checks that the client (replica) receives the mined blocks using the gRPC service.
#[test]
fn test_receives_blocks() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();
    let client = Client::new(
        bitcoind.rpc_url().as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();

    assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

    let address = client.get_new_address(None, None).unwrap();

    client.generate_to_address(150, &address).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let blocks = sync_until_end_block(&adapter_client, &client, 0, &mut vec![]);

    assert_eq!(blocks.len(), 150);
}

/// The client (replica) receives newly created transactions by 3rd parties using the gRPC service.
#[test]
fn test_receives_new_3rd_party_txs() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let (alice_client, bob_client, alice_address, bob_address) =
        create_alice_and_bob_wallets(&bitcoind);

    fund_with_btc(&alice_client, &alice_address);

    assert_eq!(101, alice_client.get_blockchain_info().unwrap().blocks);
    let txid = alice_client
        .send_to_address(
            &bob_address,
            Amount::from_btc(1.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("Failed to send to Bob");
    assert_eq!(101, alice_client.get_blockchain_info().unwrap().blocks);
    alice_client
        .generate_to_address(1, &get_blackhole_address())
        .unwrap();
    assert_eq!(102, alice_client.get_blockchain_info().unwrap().blocks);

    let alice_balance = alice_client.get_balance(None, None).unwrap();

    // Take the tx fee into consideration
    assert!(
        alice_balance < Amount::from_btc(49.0).unwrap()
            && alice_balance > Amount::from_btc(48.999).unwrap()
    );
    assert_eq!(
        bob_client.get_balance(None, None).unwrap(),
        Amount::from_btc(1.0).unwrap()
    );

    let blocks = sync_until_end_block(&adapter_client, &alice_client, 101, &mut vec![]);

    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].txdata.iter().any(|tx| tx.txid() == txid));
}

/// Ensures the client (replica) can send a transaction (1 BTC from Alice to Bob) using the gRPC service.
#[test]
fn test_send_tx() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let (alice_client, bob_client, alice_address, bob_address) =
        create_alice_and_bob_wallets(&bitcoind);

    fund_with_btc(&alice_client, &alice_address);

    let to_send = Amount::from_btc(1.0).unwrap();
    let tx_fee = Amount::from_btc(0.001).unwrap();

    let unspent = alice_client
        .list_unspent(None, None, None, None, None)
        .unwrap();
    let utxo = unspent
        .iter()
        .find(|utxo| utxo.amount > to_send + tx_fee)
        .expect("Not enough BTC in Alice's wallet");

    let raw_tx_input = CreateRawTransactionInput {
        txid: utxo.txid,
        vout: utxo.vout,
        sequence: None,
    };

    let mut outs = HashMap::new();
    let change = utxo.amount - to_send - tx_fee;
    outs.insert(bob_address.to_string(), to_send);
    if change > Amount::from_btc(0.0).unwrap() {
        outs.insert(alice_address.to_string(), change);
    }

    let raw_tx = alice_client
        .create_raw_transaction(&[raw_tx_input], &outs, None, Some(true))
        .expect("Failed to create raw transaction");

    let signed_tx = alice_client
        .sign_raw_transaction_with_wallet(&raw_tx, None, None)
        .unwrap();

    let res = adapter_client.send_tx(&signed_tx.hex);

    let mut tries = 0;
    while tries < 5
        && bob_client.get_balances().unwrap().mine.untrusted_pending
            == Amount::from_btc(0.0).unwrap()
    {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
    }

    if let BitcoinAdapterResponseWrapper::SendTransactionResponse(_) = res.unwrap() {
        assert_eq!(
            bob_client.get_balances().unwrap().mine.untrusted_pending,
            Amount::from_btc(1.0).unwrap()
        );
    } else {
        panic!("Failed to send transaction");
    }
}
