use crate::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            NnsInstallationExt, SubnetSnapshot,
        },
    },
    icrc1_agent_test::install_icrc1_ledger,
    nns::vote_and_execute_proposal,
    tecdsa::tecdsa_signature_test::{
        get_public_key_with_logger, get_signature_with_logger, make_key, verify_signature,
    },
    util::{assert_create_agent, runtime_from_url, MessageCanister},
};
use candid::Encode;
use candid::{CandidType, Deserialize};
use canister_test::{ic00::EcdsaKeyId, Canister, Runtime};
use dfn_candid::candid;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_types::Network;
use ic_canister_client::Sender;
use ic_cdk::export::Principal;
use ic_ckbtc_minter::lifecycle::init::{InitArgs as CkbtcMinterInitArgs, Mode};
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_ic00_types::CanisterIdRecord;
use ic_ic00_types::ProvisionalCreateCanisterWithCyclesArgs;
use ic_icrc1::Account;
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    governance::submit_external_update_proposal, ids::TEST_NEURON_1_ID,
    itest_helpers::install_rust_canister_from_path,
};
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::ArchiveOptions;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use serde::Serialize;
use slog::{debug, info, Logger};
use std::str::FromStr;
use std::time::Duration;

pub(crate) const TEST_KEY_LOCAL: &str = "dfx_test_key";

pub(crate) const ADDRESS_LENGTH: usize = 44;

pub(crate) const TRANSFER_FEE: u64 = 1_000;

pub(crate) const RETRIEVE_BTC_MIN_AMOUNT: u64 = 100;

pub const TIMEOUT_SHORT: Duration = Duration::from_secs(300);

const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

/// Maximum time (in nanoseconds) spend in queue at 0 to make the minter treat requests rigth away
pub const MAX_NANOS_IN_QUEUE: u64 = 0;

pub const BTC_MIN_CONFIRMATIONS: u32 = 6;

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
    nns_node
        .install_nns_canisters_at_ids()
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
    enable_ecdsa_signing(&governance, app_subnet_id, make_key(key_name)).await;
    let sys_agent = assert_create_agent(sys_node.get_public_url().as_str()).await;

    // Wait for key creation and verify signature (as it's done in tecdsa tests).
    let msg_can = MessageCanister::new(&sys_agent, sys_node.effective_canister_id()).await;
    let public_key = get_public_key_with_logger(make_key(TEST_KEY_LOCAL), &msg_can, logger)
        .await
        .unwrap();
    let message_hash = [0xabu8; 32];
    let signature = get_signature_with_logger(
        &message_hash,
        ECDSA_SIGNATURE_FEE,
        make_key(TEST_KEY_LOCAL),
        &msg_can,
        logger,
    )
    .await
    .unwrap();
    verify_signature(&message_hash, &public_key, &signature);
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
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        max_instructions_per_message: None,
        max_instructions_per_round: None,
        max_instructions_per_install_code: None,
        features: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
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
            ic_ic00_types::Method::ProvisionalCreateCanisterWithCycles.to_string(),
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
    env: &TestEnv,
    canister: &mut Canister<'_>,
    minting_user: PrincipalId,
    logger: &Logger,
) -> CanisterId {
    info!(&logger, "Installing ledger ...");
    let minting_account = Account {
        owner: minting_user,
        subaccount: None,
    };
    let init_args = LedgerArgument::Init(InitArgs {
        minting_account,
        initial_balances: vec![],
        transfer_fee: TRANSFER_FEE,
        token_name: "Wrapped Bitcoin".to_string(),
        token_symbol: "ckBTC".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 1000,
            num_blocks_to_archive: 1000,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: minting_user,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
    });
    install_icrc1_ledger(env, canister, &init_args).await;
    canister.canister_id()
}

pub(crate) async fn install_minter(
    env: &TestEnv,
    canister: &mut Canister<'_>,
    ledger_id: CanisterId,
    logger: &Logger,
    max_time_in_queue_nanos: u64,
) -> CanisterId {
    info!(&logger, "Installing minter ...");
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        /// a testing key for testnet and mainnet
        ecdsa_key_name: TEST_KEY_LOCAL.parse().unwrap(),
        // ecdsa_key_name: "test_key_1".parse().unwrap(),
        retrieve_btc_min_amount: RETRIEVE_BTC_MIN_AMOUNT,
        ledger_id,
        max_time_in_queue_nanos,
        min_confirmations: Some(BTC_MIN_CONFIRMATIONS),
        mode: Mode::GeneralAvailability,
    };

    install_rust_canister_from_path(
        canister,
        env.get_dependency_path("rs/bitcoin/ckbtc/minter/ckbtc_minter_debug.wasm"),
        Some(Encode!(&args).unwrap()),
    )
    .await;
    canister.canister_id()
}

pub(crate) async fn install_bitcoin_canister(
    runtime: &Runtime,
    logger: &Logger,
    env: &TestEnv,
) -> CanisterId {
    info!(&logger, "Installing bitcoin canister ...");
    let mut bitcoin_canister = create_canister_at_id(
        runtime,
        PrincipalId::from_str(BITCOIN_TESTNET_CANISTER_ID).unwrap(),
    )
    .await;

    let args = Config {
        stability_threshold: 6,
        network: NetworkInPayload::Regtest,
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
        },
        api_access: Flag::Enabled,
    };

    install_rust_canister_from_path(
        &mut bitcoin_canister,
        env.get_dependency_path("external/btc_canister/file/ic-btc-canister.wasm.gz"),
        Some(Encode!(&args).unwrap()),
    )
    .await;
    bitcoin_canister.canister_id()
}

#[derive(CandidType, Deserialize)]
pub struct Config {
    pub stability_threshold: u128,
    pub network: NetworkInPayload,

    /// The principal from which blocks are retrieved.
    ///
    /// Setting this source to the management canister means that the blocks will be
    /// fetched directly from the replica, and that's what is used in production.
    pub blocks_source: Principal,

    pub syncing: Flag,

    pub fees: Fees,

    /// Flag to control access to the apis provided by the canister.
    pub api_access: Flag,
}

#[derive(CandidType, Serialize, Deserialize)]
pub enum Flag {
    #[serde(rename = "enabled")]
    Enabled,
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(CandidType, Serialize, Deserialize)]
pub enum NetworkInPayload {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "regtest")]
    Regtest,
}

#[derive(CandidType, Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct Fees {
    /// The base fee to charge for all `get_utxos` requests.
    pub get_utxos_base: u128,

    /// The number of cycles to charge per 10 instructions.
    pub get_utxos_cycles_per_ten_instructions: u128,

    /// The maximum amount of cycles that can be charged in a `get_utxos` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_utxos_maximum: u128,

    /// The flat fee to charge for a `get_balance` request.
    pub get_balance: u128,

    /// The maximum amount of cycles that can be charged in a `get_balance` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_balance_maximum: u128,

    /// The flat fee to charge for a `get_current_fee_percentiles` request.
    pub get_current_fee_percentiles: u128,

    /// The maximum amount of cycles that can be charged in a `get_current_fee_percentiles` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_current_fee_percentiles_maximum: u128,

    /// The base fee to charge for all `send_transaction` requests.
    pub send_transaction_base: u128,

    /// The number of cycles to charge for each byte in the transaction.
    pub send_transaction_per_byte: u128,
}
