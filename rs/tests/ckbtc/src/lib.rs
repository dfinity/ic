use candid::{Encode, Principal};
use canister_test::{ic00::EcdsaKeyId, Canister, Runtime};
use dfn_candid::candid;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_checker::{
    BtcNetwork, CheckArg, CheckMode, InitArg as CheckerInitArg, UpgradeArg as CheckerUpgradeArg,
};
use ic_btc_interface::{Config, Fees, Flag, Network};
use ic_canister_client::Sender;
use ic_ckbtc_minter::{
    lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg, Mode},
    CKBTC_LEDGER_MEMO_SIZE,
};
use ic_config::{
    execution_environment::{BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID},
    subnet_config::ECDSA_SIGNATURE_FEE,
};
use ic_consensus_threshold_sig_system_test_utils::{
    get_public_key_with_logger, get_signature_with_logger, make_key, verify_signature,
};
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_management_canister_types::{
    CanisterIdRecord, MasterPublicKeyId, ProvisionalCreateCanisterWithCyclesArgs,
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    governance::submit_external_update_proposal, itest_helpers::install_rust_canister_from_path,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            IcNodeSnapshot, NnsInstallationBuilder, SshSession, SubnetSnapshot,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    nns::vote_and_execute_proposal,
    util::{assert_create_agent, runtime_from_url, MessageCanister},
};
use ic_types::Height;
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::ArchiveOptions;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{debug, info, Logger};
use std::{
    env,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

pub mod utils;

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

pub(crate) const BITCOIND_RPC_USER: &str = "btc-dev-preview";

pub(crate) const BITCOIND_RPC_PASSWORD: &str = "Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=";

const BITCOIND_RPC_AUTH : &str = "btc-dev-preview:8555f1162d473af8e1f744aa056fd728$afaf9cb17b8cf0e8e65994d1195e4b3a4348963b08897b4084d210e5ee588bcb";

const BITCOIND_RPC_PORT: u16 = 8332;

const BITCOIN_CLI_PORT: u16 = 18444;

const HTTPS_PORT: u16 = 20443;

pub fn btc_config(env: TestEnv) {
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            env::var("CKBTC_UVM_CONFIG_PATH").expect("CKBTC_UVM_CONFIG_PATH not set"),
        ))
        .enable_ipv4()
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;

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

# Setup bitcoin.conf and run bitcoind
# The following variable assignment prevents the dollar sign in Rust's BITCOIND_RPC_AUTH string
# from being interpreted by shell.
BITCOIND_RPC_AUTH='{BITCOIND_RPC_AUTH}'
cat >/tmp/bitcoin.conf <<END
    regtest=1
    debug=1
    whitelist=::/0
    fallbackfee=0.0002
    rpcauth=$BITCOIND_RPC_AUTH
END
docker load -i /config/bitcoind.tar
docker run  --name=bitcoind-node -d \
  -e VIRTUAL_HOST=localhost -e VIRTUAL_PORT={BITCOIND_RPC_PORT} -v /tmp:/bitcoin/.bitcoin \
  -p {BITCOIN_CLI_PORT}:{BITCOIN_CLI_PORT} -p {BITCOIND_RPC_PORT}:{BITCOIND_RPC_PORT} \
  bitcoind:image

# docker load -i /config/httpbin.tar
# docker run --rm -d -p {HTTPS_PORT}:80 -v /tmp/certs:/certs --name httpbin httpbin:image \
#      --cert-file /certs/localhost.crt --key-file /certs/localhost.key --port 80
"#
        ))
        .unwrap());

    InternetComputer::new()
        .with_bitcoind_addr(SocketAddr::new(IpAddr::V6(btc_node_ipv6), BITCOIN_CLI_PORT))
        .add_subnet(
            Subnet::new(SubnetType::System)
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

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn setup(env: TestEnv) {
    // Use the btc integration setup.
    btc_config(env.clone());
    check_nodes_health(&env);
    install_nns_canisters_at_ids(&env);
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

// By default ECDSA signature is not activated, we need to activate it explicitly.
pub async fn activate_ecdsa_signature(
    sys_node: IcNodeSnapshot,
    app_subnet_id: SubnetId,
    key_name: &str,
    logger: &Logger,
) {
    debug!(
        logger,
        "Activating ECDSA signature with key {:?} on subnet {:?}", key_name, app_subnet_id
    );
    let nns = runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
    let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
    let ecdsa_key_id = make_key(key_name);
    let key_id = MasterPublicKeyId::Ecdsa(ecdsa_key_id.clone());
    enable_ecdsa_signing(&governance, app_subnet_id, ecdsa_key_id).await;
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

async fn enable_ecdsa_signing(governance: &Canister<'_>, subnet_id: SubnetId, key_id: EcdsaKeyId) {
    // The ECDSA key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_config: Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![key_id.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;

    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![key_id]),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;
}

async fn execute_update_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: UpdateSubnetPayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateConfigOfSubnet,
        proposal_payload,
        "<proposal created by ckbtc minter test>".to_string(),
        "Test summary".to_string(),
    )
    .await;
    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
}

fn empty_subnet_update() -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id: subnet_test_id(0),
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
        chain_key_config: None,
        chain_key_signing_disable: None,
        chain_key_signing_enable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: Default::default(),
    }
}

pub fn subnet_sys(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
}

pub async fn create_canister_at_id(runtime: &Runtime, specified_id: PrincipalId) -> Canister<'_> {
    let canister_id_record: CanisterIdRecord = runtime
        .get_management_canister()
        .update_(
            ic_management_canister_types::Method::ProvisionalCreateCanisterWithCycles.to_string(),
            candid,
            (ProvisionalCreateCanisterWithCyclesArgs::new(
                None,
                Some(specified_id),
            ),),
        )
        .await
        .expect("Fail");
    let canister_id = canister_id_record.get_canister_id();
    assert_eq!(canister_id.get(), specified_id);
    Canister::new(runtime, canister_id)
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
        btc_network: Network::Regtest.into(),
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
        "https://{}:{}@[{}]:{}",
        BITCOIND_RPC_USER, BITCOIND_RPC_PASSWORD, btc_node_ipv6, HTTPS_PORT,
    );
    let init_args = CheckArg::InitArg(CheckerInitArg {
        btc_network: BtcNetwork::Regtest { json_rpc_url },
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
