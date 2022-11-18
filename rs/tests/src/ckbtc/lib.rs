use crate::{
    btc_integration,
    canister_http::lib::install_nns_canisters,
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            SubnetSnapshot,
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
use canister_test::{ic00::EcdsaKeyId, Canister, Runtime};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_types::Network;
use ic_canister_client::Sender;
use ic_ckbtc_minter::lifecycle::init::InitArgs as CkbtcMinterInitArgs;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_fondue::pot::log::Logger;
use ic_icrc1::Account;
use ic_icrc1_ledger::InitArgs;
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
use slog::{debug, info};

pub(crate) const TEST_KEY_LOCAL: &str = "dfx_test_key";

pub(crate) const ADDRESS_LENGTH: usize = 44;

pub(crate) const TRANSFER_FEE: u64 = 1_000;

pub(crate) const RETRIEVE_BTC_MIN_AMOUNT: u64 = 100;

pub fn config(env: TestEnv) {
    // Use the btc integration setup.
    btc_integration::btc::config(env.clone());
    check_nodes_health(&env);
    install_nns_canisters(&env);
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
    let nns = runtime_from_url(sys_node.get_public_url());
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
        advert_best_effort_percentage: None,
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

pub(crate) fn subnet_app(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
}

// Print subnets to facilitate debugging.
pub(crate) fn print_subnets(env: &TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    debug!(
        logger,
        "-- List of {} subnets --",
        topology.subnets().count()
    );
    topology
        .subnets()
        .for_each(|s| debug!(logger, "Subnet {:?}", s.subnet_id));
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
    let init_args = InitArgs {
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
    };
    install_icrc1_ledger(env, canister, &init_args).await;
    canister.canister_id()
}

pub(crate) async fn install_minter(
    env: &TestEnv,
    canister: &mut Canister<'_>,
    ledger_id: CanisterId,
    logger: &Logger,
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
    };
    install_rust_canister_from_path(
        canister,
        env.get_dependency_path("rs/bitcoin/ckbtc/minter/ckbtc_minter.wasm"),
        Some(Encode!(&args).unwrap()),
    )
    .await;
    canister.canister_id()
}
