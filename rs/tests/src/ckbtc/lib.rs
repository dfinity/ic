use crate::icrc1_agent_test::install_icrc1_ledger;
use candid::{Encode, Principal};
use canister_test::{ic00::EcdsaKeyId, Canister, Runtime};
use dfn_candid::candid;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_interface::{Config, Fees, Flag, Network};
use ic_canister_client::Sender;
use ic_ckbtc_kyt::{
    InitArg as KytInitArg, KytMode, LifecycleArg, SetApiKeyArg, UpgradeArg as KytUpgradeArg,
};
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
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            IcNodeSnapshot, NnsInstallationBuilder, SubnetSnapshot,
        },
    },
    nns::vote_and_execute_proposal,
    util::{assert_create_agent, runtime_from_url, MessageCanister},
};
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::ArchiveOptions;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{debug, info, Logger};
use std::{env, str::FromStr, time::Duration};

pub(crate) const TEST_KEY_LOCAL: &str = "dfx_test_key";

pub(crate) const ADDRESS_LENGTH: usize = 44;

pub(crate) const TRANSFER_FEE: u64 = 1_000;

pub(crate) const RETRIEVE_BTC_MIN_AMOUNT: u64 = 10000;

pub const TIMEOUT_SHORT: Duration = Duration::from_secs(300);

// const KYT_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

/// Maximum time (in nanoseconds) spend in queue at 0 to make the minter treat requests right away
pub const MAX_NANOS_IN_QUEUE: u64 = 0;

pub const BTC_MIN_CONFIRMATIONS: u64 = 6;

pub const KYT_FEE: u64 = 1001;

pub fn config(env: TestEnv) {
    // Use the btc integration setup.
    crate::ckbtc::btc_config::config(env.clone());
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
pub(crate) async fn activate_ecdsa_signature(
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

pub(crate) fn subnet_sys(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
}

pub(crate) async fn create_canister_at_id(
    runtime: &Runtime,
    specified_id: PrincipalId,
) -> Canister<'_> {
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
pub(crate) async fn create_canister(runtime: &Runtime) -> Canister<'_> {
    runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister")
}

pub(crate) async fn install_ledger(
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

pub(crate) async fn install_minter(
    canister: &mut Canister<'_>,
    ledger_id: CanisterId,
    logger: &Logger,
    max_time_in_queue_nanos: u64,
    kyt_canister_id: CanisterId,
) -> CanisterId {
    info!(&logger, "Installing minter ...");
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest.into(),
        // The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        // a testing key for testnet and mainnet
        ecdsa_key_name: TEST_KEY_LOCAL.parse().unwrap(),
        // ecdsa_key_name: "test_key_1".parse().unwrap(),
        retrieve_btc_min_amount: RETRIEVE_BTC_MIN_AMOUNT,
        ledger_id,
        max_time_in_queue_nanos,
        min_confirmations: Some(BTC_MIN_CONFIRMATIONS as u32),
        mode: Mode::GeneralAvailability,
        kyt_fee: Some(KYT_FEE),
        kyt_principal: Some(kyt_canister_id),
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

pub(crate) async fn install_kyt(
    kyt_canister: &mut Canister<'_>,
    logger: &Logger,
    minter_id: Principal,
    maintainers: Vec<Principal>,
) -> CanisterId {
    info!(&logger, "Installing kyt canister ...");
    let kyt_init_args = LifecycleArg::InitArg(KytInitArg {
        minter_id,
        maintainers,
        mode: KytMode::AcceptAll,
    });

    install_rust_canister_from_path(
        kyt_canister,
        get_dependency_path(
            env::var("IC_CKBTC_KYT_WASM_PATH").expect("IC_CKBTC_KYT_WASM_PATH not set"),
        ),
        Some(Encode!(&kyt_init_args).unwrap()),
    )
    .await;
    kyt_canister.canister_id()
}

pub(crate) async fn set_kyt_api_key(
    agent: &ic_agent::Agent,
    kyt_canister: &Principal,
    api_key: String,
) {
    agent
        .update(kyt_canister, "set_api_key")
        .with_arg(candid::Encode!(&SetApiKeyArg { api_key }).unwrap())
        .call_and_wait()
        .await
        .expect("failed to set api key");
}

pub(crate) async fn upgrade_kyt(kyt_canister: &mut Canister<'_>, mode: KytMode) -> CanisterId {
    let kyt_upgrade_arg = LifecycleArg::UpgradeArg(KytUpgradeArg {
        mode: Some(mode),
        maintainers: None,
        minter_id: None,
    });

    kyt_canister
        .upgrade_to_self_binary(Encode!(&kyt_upgrade_arg).unwrap())
        .await
        .expect("failed to upgrade the canister");
    kyt_canister.canister_id()
}

pub(crate) async fn install_bitcoin_canister(runtime: &Runtime, logger: &Logger) -> CanisterId {
    install_bitcoin_canister_with_network(runtime, logger, Network::Regtest).await
}

pub(crate) async fn install_bitcoin_canister_with_network(
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
        get_dependency_path("external/btc_canister/file/ic-btc-canister.wasm.gz"),
        Some(Encode!(&args).unwrap()),
    )
    .await;

    bitcoin_canister
        .set_controller_with_retries(ROOT_CANISTER_ID.get())
        .await
        .unwrap();

    bitcoin_canister.canister_id()
}
