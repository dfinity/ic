use bitcoin::{Network as BtcNetwork, dogecoin::Network as DogeNetwork};
use candid::{Encode, Principal};
use canister_test::{Canister, Runtime, ic00::EcdsaKeyId};
use dfn_candid::candid;
use ic_base_types::{CanisterId, PrincipalId};
use ic_btc_adapter_test_utils::rpc_client::RpcClientType;
use ic_btc_checker::{
    CheckArg, CheckMode, InitArg as CheckerInitArg, UpgradeArg as CheckerUpgradeArg,
};
use ic_btc_interface::{Config, Fees, Flag, Network};
use ic_ckbtc_minter::{
    CKBTC_LEDGER_MEMO_SIZE,
    lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg, Mode},
};
use ic_config::{
    execution_environment::{BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID},
    subnet_config::ECDSA_SIGNATURE_FEE,
};
use ic_consensus_threshold_sig_system_test_utils::{
    get_public_key_with_logger, get_signature_with_logger, make_key, verify_signature,
};
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_management_canister_types::{CanisterIdRecord, ProvisionalCreateCanisterWithCyclesArgs};
use ic_management_canister_types_private::{BitcoinNetwork, EcdsaCurve, MasterPublicKeyId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::itest_helpers::install_rust_canister_from_path;
use ic_registry_subnet_features::{DEFAULT_ECDSA_MAX_QUEUE_SIZE, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            NnsInstallationBuilder, SshSession, SubnetSnapshot, get_dependency_path,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    util::{MessageCanister, assert_create_agent, block_on},
};
use ic_types::Height;
use icp_ledger::ArchiveOptions;
use slog::{Logger, info};
use std::{
    env,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

#[cfg(feature = "tla")]
use ic_ckbtc_minter::tla::perform_trace_check;

pub mod adapter;
pub mod utils;

/// For an, as of yet, unexplained reason the setup task of all the ckbtc system-tests often times out
/// after the default 10 minutes because creating the btc-node takes a long time.
/// So to reduce flakiness we bump the timeout to 15 minutes.
pub const TIMEOUT_PER_TEST: Duration = Duration::from_secs(15 * 60);
pub const OVERALL_TIMEOUT: Duration = Duration::from_secs(20 * 60);

pub const TEST_KEY_LOCAL: &str = "an_arbitrary_key_id";

pub const ADDRESS_LENGTH: usize = 44;

pub const TRANSFER_FEE: u64 = 1_000;

pub const RETRIEVE_BTC_MIN_AMOUNT: u64 = 10000;

pub const TIMEOUT_SHORT: Duration = Duration::from_secs(300);

/// Maximum time (in nanoseconds) spend in queue at 0 to make the minter treat requests right away
pub const MAX_NANOS_IN_QUEUE: u64 = 0;

pub const BTC_MIN_CONFIRMATIONS: u64 = 6;

pub const CHECK_FEE: u64 = 1001;

const UNIVERSAL_VM_NAME: &str = "btc-node";

#[cfg(feature = "tla")]
pub fn fetch_and_check_traces(minter_canister: Canister, runtime: &Runtime) {
    // Fetch traces from the canister
    let traces: Vec<tla_instrumentation::UpdateTrace> = runtime
        .block_on(minter_canister.query_("get_tla_traces", candid, ()))
        .expect("query get_tla_traces failed");

    perform_trace_check(traces);
}

#[cfg(feature = "tla")]
fn get_tla_module_path(module: &str) -> std::path::PathBuf {
    let modules = std::env::var("TLA_MODULES")
        .expect("TLA_MODULES must be set for TLA trace checking");
    modules
        .split_whitespace()
        .map(std::path::PathBuf::from)
        .find(|p| p.file_name().is_some_and(|f| f == module))
        .unwrap_or_else(|| panic!("Could not find TLA module {module} in TLA_MODULES"))
}

pub(crate) const BITCOIND_RPC_USER: &str = "btc-dev-preview";

pub(crate) const BITCOIND_RPC_PASSWORD: &str = "Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=";

const BITCOIND_RPC_AUTH: &str = "btc-dev-preview:8555f1162d473af8e1f744aa056fd728$afaf9cb17b8cf0e8e65994d1195e4b3a4348963b08897b4084d210e5ee588bcb";

const HTTPS_PORT: u16 = 20443;

pub trait IcRpcClientType: RpcClientType {
    const IMAGE_NAME: &str;
    const CONFIG_NAME: &str;
    const CONFIG_MAPPING: &str;
    const RPC_PORT: u16;
    const P2P_PORT: u16;
    const REGTEST_REPLICA: BitcoinNetwork;
    fn internet_computer(socket_addr: SocketAddr) -> InternetComputer;
}

impl IcRpcClientType for BtcNetwork {
    const IMAGE_NAME: &str = "bitcoind";
    const CONFIG_NAME: &str = "bitcoin.conf";
    const CONFIG_MAPPING: &str = "/tmp/bitcoin.conf:/bitcoin/.bitcoin/bitcoin.conf";
    const RPC_PORT: u16 = 8332;
    const P2P_PORT: u16 = 18444;
    const REGTEST_REPLICA: BitcoinNetwork = BitcoinNetwork::BitcoinRegtest;
    fn internet_computer(socket_addr: SocketAddr) -> InternetComputer {
        InternetComputer::new().with_bitcoind_addr(socket_addr)
    }
}

impl IcRpcClientType for DogeNetwork {
    const IMAGE_NAME: &str = "dogecoind";
    const CONFIG_NAME: &str = "dogecoin.conf";
    const CONFIG_MAPPING: &str = "/tmp/dogecoin.conf:/node/dogecoin-core/configs/config.conf";
    const RPC_PORT: u16 = 18332;
    const P2P_PORT: u16 = 18444;
    const REGTEST_REPLICA: BitcoinNetwork = BitcoinNetwork::DogecoinRegtest;
    fn internet_computer(socket_addr: SocketAddr) -> InternetComputer {
        InternetComputer::new().with_dogecoind_addr(socket_addr)
    }
}

fn ckbtc_config<Network: IcRpcClientType>(env: TestEnv) {
    let node_ipv6 = setup_bitcoind_uvm::<Network>(&env);
    let socket_addr = SocketAddr::new(IpAddr::V6(node_ipv6), Network::P2P_PORT);
    Network::internet_computer(socket_addr)
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(10))
                .with_chain_key_config(ic_registry_subnet_features::ChainKeyConfig {
                    key_configs: vec![ic_registry_subnet_features::KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: TEST_KEY_LOCAL.to_string(),
                        }),
                        pre_signatures_to_create_in_advance: 10,
                        max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                    }],
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(10))
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        )
        .use_specified_ids_allocation_range()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn adapter_test_config<Network: IcRpcClientType>(env: TestEnv) {
    let node_ipv6 = setup_bitcoind_uvm::<Network>(&env);
    let socket_addr = SocketAddr::new(IpAddr::V6(node_ipv6), Network::P2P_PORT);
    Network::internet_computer(socket_addr)
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(10))
                .add_nodes(1),
        )
        .use_specified_ids_allocation_range()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn setup_bitcoind_uvm<Network: IcRpcClientType>(env: &TestEnv) -> Ipv6Addr {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            env::var("CKBTC_UVM_CONFIG_PATH").expect("CKBTC_UVM_CONFIG_PATH not set"),
        ))
        .enable_ipv4()
        .start(env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;
    let rpc_port = Network::RPC_PORT;
    let p2p_port = Network::P2P_PORT;
    let config_name = Network::CONFIG_NAME;
    let image_name = Network::IMAGE_NAME;
    let config_mapping = Network::CONFIG_MAPPING;

    // Regtest bitcoin node listens on 18444
    // docker bitcoind image uses 8332 for the rpc server
    // https://en.bitcoinwiki.org/wiki/Running_Bitcoind
    // nginx auto proxy setups SSL reverse proxy and forwards HTTP request on 443 to 9332.
    println!("{}", deployed_universal_vm
        .block_on_bash_script(&format!(
            r#"
# Create SSL cert using minica. IC-OS already supports the CA cert used here.
mkdir /tmp/certs
cd /tmp/certs
cp /config/cert.pem minica.pem
cp /config/key.pem minica-key.pem
echo "Making certs directory in $(pwd) ..."
docker load -i /config/minica.tar
docker run -v "$(pwd)":/output minica:image -ip-addresses="{btc_node_ipv6}"
sudo mv "{btc_node_ipv6}"/cert.pem localhost.crt
sudo mv "{btc_node_ipv6}"/key.pem localhost.key
sudo chmod 644 localhost*

# Run nginx auto proxy
docker load -i /config/nginx-proxy.tar
docker run -d --name=proxy -e ENABLE_IPV6=true -e DEFAULT_HOST=localhost -p 80:80 -p {HTTPS_PORT}:443 \
           -v /tmp/certs:/etc/nginx/certs -v /var/run/docker.sock:/tmp/docker.sock:ro \
           nginx-proxy:image

# Setup config file and run the image
# The following variable assignment prevents the dollar sign in Rust's BITCOIND_RPC_AUTH string
# from being interpreted by shell.
BITCOIND_RPC_AUTH='{BITCOIND_RPC_AUTH}'
cat >/tmp/{config_name} <<END
    regtest=1
    debug=1
    rpcallowip=0.0.0.0/0
    whitelist=::/0
    fallbackfee=0.0002
    rpcuser={BITCOIND_RPC_USER}
    rpcpasswd={BITCOIND_RPC_PASSWORD}
    rpcauth=$BITCOIND_RPC_AUTH
END
docker load -i /config/{image_name}.tar
docker run  --name={image_name}-node -d \
  -e VIRTUAL_HOST=localhost -e VIRTUAL_PORT={rpc_port} -v {config_mapping} \
  -p {p2p_port}:{p2p_port} -p {rpc_port}:{rpc_port} \
  {image_name}:image

# docker load -i /config/httpbin.tar
# docker run --rm -d -p {HTTPS_PORT}:80 -v /tmp/certs:/certs --name httpbin httpbin:image \
#      --cert-file /certs/localhost.crt --key-file /certs/localhost.key --port 80
"#
        ))
        .unwrap());
    btc_node_ipv6
}

pub fn ckbtc_setup(env: TestEnv) {
    // Use the ckbtc integration setup.
    ckbtc_config::<BtcNetwork>(env.clone());
    check_nodes_health(&env);
    check_ecdsa_works(&env);
    install_nns_canisters_at_ids(&env);
}

pub fn adapter_test_setup<T: IcRpcClientType>(env: TestEnv) {
    // Use the adapter test integration setup.
    adapter_test_config::<T>(env.clone());
    check_nodes_health(&env);
}

pub fn install_nns_canisters_at_ids(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .at_ids()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

fn check_nodes_health(env: &TestEnv) {
    info!(
        &env.logger(),
        "Checking readiness of all nodes after the IC setup ..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&env.logger(), "All nodes are ready, IC setup succeeded.");
}

fn check_ecdsa_works(env: &TestEnv) {
    // Check that ECDSA signatures work
    let sys_node = subnet_sys(env)
        .nodes()
        .next()
        .expect("No node in sys subnet.");
    block_on(async {
        assert_ecdsa_signatures_work(sys_node, TEST_KEY_LOCAL, &env.logger()).await;
    });
    info!(&env.logger(), "Ecdsa signatures are operational");
}

pub async fn assert_ecdsa_signatures_work(
    sys_node: IcNodeSnapshot,
    key_name: &str,
    logger: &Logger,
) {
    let key_id = MasterPublicKeyId::Ecdsa(make_key(key_name));
    let sys_agent = assert_create_agent(sys_node.get_public_url().as_str()).await;

    // Wait for key creation and verify signature (as it's done in tecdsa tests).
    let msg_can = MessageCanister::new(&sys_agent, sys_node.effective_canister_id()).await;
    let public_key = get_public_key_with_logger(&key_id, &msg_can, logger)
        .await
        .unwrap();
    let message_hash = vec![0xabu8; 32];
    let signature = get_signature_with_logger(
        message_hash.clone(),
        ECDSA_SIGNATURE_FEE,
        &key_id,
        &msg_can,
        logger,
    )
    .await
    .unwrap();
    verify_signature(&key_id, &message_hash, &public_key, &signature);
}

pub fn subnet_sys(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
}

pub fn subnet_app(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
}

pub async fn create_canister_at_id(runtime: &Runtime, specified_id: PrincipalId) -> Canister<'_> {
    let canister_id_record: CanisterIdRecord = runtime
        .get_management_canister()
        .update_(
            "provisional_create_canister_with_cycles",
            candid,
            (ProvisionalCreateCanisterWithCyclesArgs {
                amount: None,
                settings: None,
                specified_id: Some(specified_id.into()),
                sender_canister_version: None,
            },),
        )
        .await
        .expect("Fail");
    let canister_id = canister_id_record.canister_id;
    assert_eq!(canister_id, specified_id.into());
    Canister::new(
        runtime,
        CanisterId::try_from_principal_id(PrincipalId(canister_id)).unwrap(),
    )
}

/// Create an empty canister.
pub async fn create_canister(runtime: &Runtime) -> Canister<'_> {
    runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister")
}

pub async fn install_ledger(
    canister: &mut Canister<'_>,
    minting_user: PrincipalId,
    logger: &Logger,
) -> CanisterId {
    info!(&logger, "Installing ledger ...");
    let init_args = LedgerArgument::Init(
        InitArgsBuilder::with_symbol_and_name("ckBTC", "Wrapped Bitcoin")
            .with_minting_account(minting_user.0)
            .with_transfer_fee(TRANSFER_FEE)
            .with_max_memo_length(CKBTC_LEDGER_MEMO_SIZE)
            .with_archive_options(ArchiveOptions {
                trigger_threshold: 1000,
                num_blocks_to_archive: 1000,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: minting_user,
                more_controller_ids: None,
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            })
            .build(),
    );
    install_icrc1_ledger(canister, &init_args).await;
    canister.canister_id()
}

pub async fn install_minter(
    canister: &mut Canister<'_>,
    ledger_id: CanisterId,
    logger: &Logger,
    max_time_in_queue_nanos: u64,
    btc_checker_canister_id: CanisterId,
) -> CanisterId {
    info!(&logger, "Installing minter ...");
    #[allow(deprecated)]
    let args = CkbtcMinterInitArgs {
        btc_network: ic_ckbtc_minter::Network::Regtest,
        ecdsa_key_name: TEST_KEY_LOCAL.parse().unwrap(),
        retrieve_btc_min_amount: RETRIEVE_BTC_MIN_AMOUNT,
        ledger_id,
        max_time_in_queue_nanos,
        min_confirmations: Some(BTC_MIN_CONFIRMATIONS as u32),
        mode: Mode::GeneralAvailability,
        check_fee: Some(CHECK_FEE),
        btc_checker_principal: Some(btc_checker_canister_id),
        kyt_principal: None,
        kyt_fee: None,
        get_utxos_cache_expiration_seconds: None,
    };

    let minter_arg = MinterArg::Init(args);

    install_rust_canister_from_path(
        canister,
        get_dependency_path(
            env::var("IC_CKBTC_MINTER_WASM_PATH").expect("IC_CKBTC_MINTER_WASM_PATH not set"),
        ),
        Some(Encode!(&minter_arg).unwrap()),
    )
    .await;
    canister.canister_id()
}

pub async fn install_btc_checker(
    btc_checker_canister: &mut Canister<'_>,
    env: &TestEnv,
) -> CanisterId {
    let logger = env.logger();
    info!(logger, "Installing btc checker canister ...");
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;
    let json_rpc_url = format!(
        "https://{BITCOIND_RPC_USER}:{BITCOIND_RPC_PASSWORD}@[{btc_node_ipv6}]:{HTTPS_PORT}",
    );
    let init_args = CheckArg::InitArg(CheckerInitArg {
        btc_network: ic_btc_checker::BtcNetwork::Regtest { json_rpc_url },
        check_mode: CheckMode::Normal,
        num_subnet_nodes: 1,
    });

    install_rust_canister_from_path(
        btc_checker_canister,
        get_dependency_path(
            env::var("IC_BTC_CHECKER_WASM_PATH").expect("IC_BTC_CHECKER_WASM_PATH not set"),
        ),
        Some(Encode!(&init_args).unwrap()),
    )
    .await;
    btc_checker_canister.canister_id()
}

pub async fn upgrade_btc_checker(
    btc_checker_canister: &mut Canister<'_>,
    mode: CheckMode,
) -> CanisterId {
    let upgrade_arg = CheckArg::UpgradeArg(Some(CheckerUpgradeArg {
        check_mode: Some(mode),
        ..CheckerUpgradeArg::default()
    }));

    btc_checker_canister
        .upgrade_to_self_binary(Encode!(&upgrade_arg).unwrap())
        .await
        .expect("failed to upgrade the canister");
    btc_checker_canister.canister_id()
}

pub async fn install_bitcoin_canister(runtime: &Runtime, logger: &Logger) -> CanisterId {
    install_bitcoin_canister_with_network(runtime, logger, Network::Regtest).await
}

pub async fn install_bitcoin_canister_with_network(
    runtime: &Runtime,
    logger: &Logger,
    network: Network,
) -> CanisterId {
    info!(&logger, "Installing bitcoin canister ...");
    let canister_id = match network {
        Network::Mainnet => BITCOIN_MAINNET_CANISTER_ID,
        Network::Regtest | Network::Testnet => BITCOIN_TESTNET_CANISTER_ID,
    };
    let mut bitcoin_canister =
        create_canister_at_id(runtime, PrincipalId::from_str(canister_id).unwrap()).await;

    let args = Config {
        stability_threshold: 6,
        network,
        blocks_source: Principal::management_canister(),
        syncing: Flag::Enabled,
        fees: Fees {
            get_utxos_base: 0,
            get_utxos_cycles_per_ten_instructions: 0,
            get_utxos_maximum: 0,
            get_balance: 0,
            get_balance_maximum: 0,
            get_current_fee_percentiles: 0,
            get_current_fee_percentiles_maximum: 0,
            send_transaction_base: 0,
            send_transaction_per_byte: 0,
            get_block_headers_base: 0,
            get_block_headers_cycles_per_ten_instructions: 0,
            get_block_headers_maximum: 0,
        },
        api_access: Flag::Enabled,
        disable_api_if_not_fully_synced: Flag::Disabled,
        watchdog_canister: None,
        burn_cycles: Flag::Enabled,
        lazily_evaluate_fee_percentiles: Flag::Enabled,
    };

    install_rust_canister_from_path(
        &mut bitcoin_canister,
        get_dependency_path(env::var("BTC_WASM_PATH").expect("BTC_WASM_PATH not set")),
        Some(Encode!(&args).unwrap()),
    )
    .await;

    bitcoin_canister
        .set_controller_with_retries(ROOT_CANISTER_ID.get())
        .await
        .unwrap();

    bitcoin_canister.canister_id()
}

pub async fn install_icrc1_ledger(canister: &mut Canister<'_>, args: &LedgerArgument) {
    install_rust_canister_from_path(
        canister,
        get_dependency_path(env::var("LEDGER_WASM_PATH").expect("LEDGER_WASM_PATH not set")),
        Some(Encode!(&args).unwrap()),
    )
    .await
}
