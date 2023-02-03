use std::time::Instant;
#[allow(unused)]
use std::time::{Duration, SystemTime};

use candid::{Decode, Encode, Nat, Principal};
use ic_agent::{Agent, AgentError, Identity, Signature};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_canister_client_sender::ed25519_public_key_to_der;
use ic_crypto_sha::Sha256;
use ic_icrc1::Account;

use ic_icrc1_agent::{Icrc1Agent, TransferArg};
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::proposal::Action;
use ic_nns_governance::pb::v1::{NnsFunction, OpenSnsTokenSwap, Proposal};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;

use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_swap::pb::v1::params::NeuronBasketConstructionParameters;
use ic_sns_swap::pb::v1::{
    GetBuyerStateRequest, GetBuyerStateResponse, GetStateRequest, GetStateResponse, Lifecycle,
    Params, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
};
use ic_sns_swap::swap::principal_to_subaccount;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, DeployNewSnsRequest, DeployNewSnsResponse, SnsCanisterIds, SnsCanisterType,
    SnsWasm, UpdateAllowedPrincipalsRequest, UpdateSnsSubnetListRequest,
};
use ic_types::crypto::UserPublicKey;
use ic_types::{Cycles, Height};
use serde::{Deserialize, Serialize};
use slog::info;

use crate::driver::farm::HostFeature;
use crate::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot,
    SnsCanisterEnvVars,
};
use crate::nns::{
    get_governance_canister, submit_external_proposal_with_test_id,
    vote_execute_proposal_assert_executed,
};
use crate::orchestrator::utils::rw_message::install_nns_and_check_progress;
use crate::util::{
    assert_create_agent, assert_create_agent_with_identity, block_on, delay, runtime_from_url,
    to_principal_id, UniversalCanister,
};

use crate::workload::{CallSpec, Request, RoundRobinPlan, Workload};

use ic_nns_governance::pb::v1::{
    manage_neuron::Command, manage_neuron_response::Command as CommandResp, ManageNeuron,
    ManageNeuronResponse,
};

use canister_test::{Project, Runtime};
use dfn_candid::candid_one;

use crate::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use crate::driver::test_env::TestEnvAttribute;
use ic_canister_client::{Ed25519KeyPair, Sender};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER1_PUBKEY,
};
use ic_nns_constants::{LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_registry_subnet_type::SubnetType;

const WORKLOAD_GENERATION_DURATION: Duration = Duration::from_secs(60);

const DKG_INTERVAL: u64 = 199;
const SUBNET_SIZE: usize = 4;
const UVM_NUM_CPUS: NrOfVCPUs = NrOfVCPUs::new(2);
const UVM_MEMORY_SIZE: AmountOfMemoryKiB = AmountOfMemoryKiB::new(16777216); // 16 GiB
const UVM_BOOT_IMAGE_MIN_SIZE: ImageSizeGiB = ImageSizeGiB::new(4);

const DAYS: Duration = Duration::from_secs(24 * 60 * 60);

const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(5); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnsClient {
    sns_canisters: SnsCanisterIds,
    wallet_canister_id: PrincipalId,
}

impl TestEnvAttribute for SnsClient {
    fn attribute_name() -> String {
        "sns_client".to_string()
    }
}

impl SnsClient {
    pub fn get_wallet_canister_principal(&self) -> Principal {
        Principal::try_from(self.wallet_canister_id).unwrap()
    }

    fn get_wallet_canister<'a>(&self, agent: &'a Agent) -> UniversalCanister<'a> {
        UniversalCanister::from_canister_id(agent, self.get_wallet_canister_principal())
    }

    pub fn assert_state(&self, env: &TestEnv, state: Lifecycle) {
        let log = env.logger();
        let swap_id = self.sns_canisters.swap();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = app_node.build_default_agent();
        let wallet_canister = self.get_wallet_canister(&agent);
        info!(log, r#"Sending "get_state" to SNS swap"#);
        let res = block_on(get_swap_state(&wallet_canister, swap_id))
            .expect("get_state failed")
            .swap
            .expect("No swap");
        info!(log, "Received {res:?}");
        assert_eq!(res.lifecycle(), state);
    }

    pub fn initiate_token_swap(&self, env: &TestEnv) {
        let log = env.logger();
        let swap_id = self.sns_canisters.swap();
        info!(log, "Sending open token swap proposal");
        let payload = open_sns_token_swap_payload_for_tests(swap_id.get());
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        block_on(open_sns_token_swap(&runtime, payload));
    }

    pub fn install_sns_and_check_healthy(env: &TestEnv) -> SnsClient {
        add_all_wasms_to_sns_wasm(env);

        let log = env.logger();
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let app_node = env.get_first_healthy_application_node_snapshot();
        let subnet_id = app_node.subnet_id().unwrap();
        let agent = app_node.build_default_agent();

        info!(log, "Creating new canister with cycles");
        let wallet_canister = block_on(UniversalCanister::new_with_cycles_with_retries(
            &agent,
            app_node.effective_canister_id(),
            900_000_000_000_000_000u64,
            &log,
        ));
        let principal_id = PrincipalId(wallet_canister.canister_id());

        info!(log, "Adding canister principal to SNS deploy whitelist");
        block_on(add_principal_to_sns_deploy_whitelist(
            &runtime,
            principal_id,
        ));

        info!(log, "Adding subnet {subnet_id} to SNS deploy whitelist");
        block_on(add_subnet_to_sns_deploy_whitelist(&runtime, subnet_id));

        info!(log, "Sending deploy_new_sns to SNS WASM canister");
        let init = SnsInitPayload::with_valid_values_for_testing();
        let res = block_on(deploy_new_sns(&wallet_canister, init)).expect("Deploy new SNS failed");
        info!(log, "Received {res:?}");
        if let Some(error) = res.error {
            panic!("DeployNewSnsResponse returned error: {error:?}");
        }
        assert_eq!(res.subnet_id.expect("No subnet ID"), subnet_id.get());
        let sns_canisters = res.canisters.expect("No canister IDs");
        let wallet_canister_id = to_principal_id(&wallet_canister.canister_id());

        let sns_client = SnsClient {
            sns_canisters,
            wallet_canister_id,
        };
        sns_client.write_attribute(env);
        sns_client.assert_state(env, Lifecycle::Pending);
        sns_client
    }
}

pub fn sns_setup(env: TestEnv) {
    env.ensure_group_setup_created();

    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .with_required_host_features(vec![
            HostFeature::SnsLoadTest,
            HostFeature::Host("fr1-dll07.fr1.dfinity.network".to_string()),
        ])
        .with_default_vm_resources(VmResources {
            vcpus: Some(UVM_NUM_CPUS),
            memory_kibibytes: Some(UVM_MEMORY_SIZE),
            boot_image_minimal_size_gibibytes: Some(UVM_BOOT_IMAGE_MIN_SIZE),
        })
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.sync_prometheus_config_with_topology();

    install_nns(&env);

    install_sns(&env);
}

pub fn install_nns(env: &TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    install_nns_and_check_progress(env.topology_snapshot());
    info!(
        log,
        "=========== The NNS has been successfully installed in {:?} ==========",
        start_time.elapsed()
    );
}

pub fn install_sns(env: &TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    SnsClient::install_sns_and_check_healthy(env);
    info!(
        log,
        "========== The SNS has been installed successfully in {:?} ===========",
        start_time.elapsed()
    );
}

pub fn initiate_token_swap(env: TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    let sns_client = SnsClient::read_attribute(&env);
    sns_client.initiate_token_swap(&env);
    sns_client.assert_state(&env, Lifecycle::Open);
    info!(
        log,
        "==== The SNS token sale has been initialized successfully in {:?} ====",
        start_time.elapsed()
    );
}

pub struct SnsRequestProvider {
    // The Principal of the canister issuing the request
    pub sender: Principal,
    pub sns_canisters: SnsCanisterIds,
}

impl SnsRequestProvider {
    pub fn from_sns_client(sns_client: &SnsClient) -> Self {
        let wallet_canister = sns_client.get_wallet_canister_principal();
        Self {
            sender: wallet_canister,
            sns_canisters: sns_client.sns_canisters,
        }
    }

    pub fn from_env(env: &TestEnv) -> Self {
        let sns_client = SnsClient::read_attribute(env);
        Self::from_sns_client(&sns_client)
    }

    pub fn get_state(&self) -> Request {
        let swap_canister = self.sns_canisters.swap().get().into();
        Request::Query(CallSpec::new(
            swap_canister,
            "get_state",
            Encode!(&GetStateRequest {}).unwrap(),
        ))
    }

    pub fn get_buyer_state(&self, buyer: PrincipalId) -> Request {
        let swap_canister = self.sns_canisters.swap().get().into();
        Request::Query(CallSpec::new(
            swap_canister,
            "get_buyer_state",
            Encode!(&GetBuyerStateRequest {
                principal_id: Some(buyer)
            })
            .unwrap(),
        ))
    }

    pub fn refresh_buyer_tokens(&self, buyer: Option<PrincipalId>) -> Request {
        let swap_canister = self.sns_canisters.swap().get().into();
        Request::Update(CallSpec::new(
            swap_canister,
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: buyer
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "".to_string())
            })
            .unwrap(),
        ))
    }
}

#[derive(Clone)]
pub struct SnsAgent {
    pub agent: Agent,
}

impl SnsAgent {
    async fn query(&self, request: Request) -> Result<Vec<u8>, AgentError> {
        let spec = request.spec();
        self.agent
            .query(&spec.canister_id, spec.method_name.clone())
            .with_arg(spec.payload.clone())
            .call()
            .await
    }

    async fn update(&self, request: Request) -> Result<Vec<u8>, AgentError> {
        let spec = request.spec();
        self.agent
            .update(&spec.canister_id, spec.method_name.clone())
            .with_arg(spec.payload.clone())
            .call_and_wait(delay())
            .await
    }
}

#[derive(Debug, Clone)]
pub struct SaleParticipant {
    principal_id: PrincipalId,
    user_public_key: UserPublicKey,
    key_pair: Ed25519KeyPair,
}

impl SaleParticipant {
    fn public_key_der(&self) -> Vec<u8> {
        let pk = self.user_public_key.key.clone();
        ed25519_public_key_to_der(pk)
    }
}

impl Identity for SaleParticipant {
    fn sender(&self) -> Result<Principal, String> {
        let pk_der = self.public_key_der();
        Ok(Principal::self_authenticating(pk_der))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let signature = self.key_pair.sign(msg.as_ref());
        let pk_der = self.public_key_der();
        Ok(Signature {
            signature: Some(signature.as_ref().to_vec()),
            public_key: Some(pk_der),
        })
    }
}

pub fn add_one_participant(env: TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();

    // Obtain the SNS client and the SNS request provider
    let sns_client = SnsClient::read_attribute(&env);
    let request_provider = SnsRequestProvider::from_sns_client(&sns_client);

    // Set up the wealthy users' account (this one has 200_000 ICP at start; see `install_nns_canisters`)
    let wealthy_user_identity = SaleParticipant {
        principal_id: *TEST_USER1_PRINCIPAL,
        user_public_key: (*TEST_USER1_PUBKEY).clone(),
        key_pair: *TEST_USER1_KEYPAIR,
    };

    info!(log, "Obtaining an agent to talk to the ICP Ledger ...");
    let wealthy_ledger_agent = {
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let agent = block_on(assert_create_agent_with_identity(
            nns_node.get_public_url().as_str(),
            wealthy_user_identity.clone(),
        ));
        let ledger_canister_id = Principal::try_from(LEDGER_CANISTER_ID.get()).unwrap();
        Icrc1Agent {
            agent,
            ledger_canister_id,
        }
    };
    info!(
        log,
        "Obtaining two alternative agents to talk to the SNS sale canister ..."
    );
    let default_sns_agent = {
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = block_on(assert_create_agent(app_node.get_public_url().as_str()));
        SnsAgent { agent }
    };
    let wealthy_sns_agent = {
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = block_on(assert_create_agent_with_identity(
            app_node.get_public_url().as_str(),
            wealthy_user_identity.clone(),
        ));
        SnsAgent { agent }
    };
    info!(
        log,
        "All three agents are ready (elapsed {:?})",
        start_time.elapsed()
    );

    info!(log, "Checking that buyer identity is correctly set up by calling `sns_sale.refresh_buyer_tokens` in two different ways ...");
    // Use the default identity to call refresh_buyer_tokens for the wealthy user
    let res_1 = {
        let request =
            request_provider.refresh_buyer_tokens(Some(wealthy_user_identity.principal_id));
        block_on(default_sns_agent.update(request))
    };
    info!(
        log,
        "First update call to `sns_sale.refresh_buyer_tokens` returned {res_1:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert!(res_1.is_err());
    // Use the wealthy user's identity refresh_buyer_tokens for "self"
    let res_2 = {
        let request = request_provider.refresh_buyer_tokens(None);
        block_on(wealthy_sns_agent.update(request))
    };
    info!(
        log,
        "Second update call to `sns_sale.refresh_buyer_tokens` returned {res_2:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert!(res_2.is_err());

    info!(
        log,
        "Validating the pre-transfer state via the `get_buyer_state` endpoint ..."
    );
    let res_3 = {
        let request = request_provider.get_buyer_state(wealthy_user_identity.principal_id);
        let res = block_on(default_sns_agent.query(request)).unwrap();
        Decode!(res.as_slice(), GetBuyerStateResponse).expect("failed to decode")
    };
    info!(
        log,
        "Query call to `sns_sale.get_buyer_state` returned {res_3:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert!(res_3.buyer_state.is_none());
    info!(
        log,
        "Validated pre-transfer state {:?} (elapsed {:?})",
        res_3.buyer_state,
        start_time.elapsed()
    );

    info!(
        log,
        "Transferring tokens in two transactions, 2_000 and 2_500 ICP, resp"
    );
    let sns_sale_canister_id = sns_client.sns_canisters.swap().get();
    let sns_subaccount = Some(principal_to_subaccount(&wealthy_user_identity.principal_id));
    let sns_account = Account {
        owner: sns_sale_canister_id,
        subaccount: sns_subaccount,
    };
    let block_idx_1 = {
        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: sns_account.clone(),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(3 * E8),
        };
        let block_idx = block_on(wealthy_ledger_agent.transfer(transfer_arg))
            .unwrap()
            .unwrap();
        info!(log, "Transaction 1: from {:?} to {sns_sale_canister_id:?} (subaccount {sns_subaccount:?}) returned block_idx={block_idx:?}", wealthy_user_identity.principal_id);
        block_idx
    };
    info!(
        log,
        "First update call to `icp_ledger.transfer` returned {block_idx_1:?} (elapsed {:?})",
        start_time.elapsed()
    );
    let block_idx_2 = {
        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: sns_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(2 * E8),
        };
        let block_idx = block_on(wealthy_ledger_agent.transfer(transfer_arg))
            .unwrap()
            .unwrap();
        info!(log, "Transaction 2: from {:?} to {sns_sale_canister_id:?} (subaccount {sns_subaccount:?}) returned block_idx={block_idx:?}", wealthy_user_identity.principal_id);
        block_idx
    };
    info!(
        log,
        "Second update call to `icp_ledger.transfer` returned {block_idx_2:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert_eq!(block_idx_1 + 1, block_idx_2);

    info!(log, "Validating the participation setup by calling `sns_sale.refresh_buyer_tokens` in two different ways ...");
    // Use the default identity to call refresh_buyer_tokens for the wealthy user
    let res_4 = {
        let request =
            request_provider.refresh_buyer_tokens(Some(wealthy_user_identity.principal_id));
        let res = block_on(default_sns_agent.update(request)).unwrap();
        Decode!(res.as_slice(), RefreshBuyerTokensResponse).expect("failed to decode")
    };
    info!(
        log,
        "Third update call to `sns_sale.refresh_buyer_tokens` returned {res_4:?} (elapsed {:?})",
        start_time.elapsed()
    );
    // Use the wealthy user's identity refresh_buyer_tokens for "self"
    let res_5 = {
        let request = request_provider.refresh_buyer_tokens(None);
        let res = block_on(wealthy_sns_agent.update(request)).unwrap();
        Decode!(res.as_slice(), RefreshBuyerTokensResponse).expect("failed to decode")
    };
    info!(
        log,
        "Fourth update call to `sns_sale.refresh_buyer_tokens` returned {res_5:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert_eq!(res_4, res_5, "sns_sale.refresh_buyer_tokens(Some({:?})) = {res_4:?}, but sns_sale.refresh_buyer_tokens(None) = {res_5:?}", wealthy_user_identity.principal_id);
    info!(log, "After setting up sale participation, the response from `sns_sale.refresh_buyer_tokens` is {res_1:?}");

    info!(
        log,
        "Validating the participation setup via the `get_buyer_state` endpoint ..."
    );
    let res_6 = {
        let request = request_provider.get_buyer_state(wealthy_user_identity.principal_id);
        let res = block_on(default_sns_agent.query(request)).unwrap();
        Decode!(res.as_slice(), GetBuyerStateResponse).expect("failed to decode")
    };
    info!(
        log,
        "Query call to `sns_sale.get_buyer_state` returned {res_6:?} (elapsed {:?})",
        start_time.elapsed()
    );
    assert!(res_6.buyer_state.is_some());
    info!(log, "Established buyer state {:?}", res_6.buyer_state);

    info!(
        log,
        "==== Successfully added {:?} to the token sale participants (elapsed {:?}) ====",
        wealthy_user_identity.principal_id,
        start_time.elapsed()
    );
}

pub fn workload_rps400_get_state_query(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).get_state();
    generate_sns_workload(env, 400, WORKLOAD_GENERATION_DURATION, req);
}

pub fn workload_rps800_get_state_query(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).get_state();
    generate_sns_workload(env, 800, WORKLOAD_GENERATION_DURATION, req);
}

pub fn workload_rps1200_get_state_query(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).get_state();
    generate_sns_workload(env, 1_200, WORKLOAD_GENERATION_DURATION, req);
}

pub fn workload_rps400_refresh_buyer_tokens(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).refresh_buyer_tokens(None);
    generate_sns_workload(env, 400, WORKLOAD_GENERATION_DURATION, req);
}

pub fn workload_rps800_refresh_buyer_tokens(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).refresh_buyer_tokens(None);
    generate_sns_workload(env, 800, WORKLOAD_GENERATION_DURATION, req);
}

pub fn workload_rps1200_refresh_buyer_tokens(env: TestEnv) {
    let req = SnsRequestProvider::from_env(&env).refresh_buyer_tokens(None);
    generate_sns_workload(env, 1_200, WORKLOAD_GENERATION_DURATION, req);
}

pub fn generate_sns_workload(env: TestEnv, rps: usize, duration: Duration, request: Request) {
    let log = env.logger();

    let plan = RoundRobinPlan::new(vec![request]);

    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = block_on(assert_create_agent(app_node.get_public_url().as_str()));

    // --- Generate workload ---
    let workload = Workload::new(vec![agent], rps, duration, plan, log.clone())
        .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
        .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);

    let metrics = block_on(workload.execute()).expect("Workload execution has failed.");

    env.emit_report(format!("{metrics}"));
}

/// Send and execute 6 proposals to add all SNS canister WASMs to the SNS WASM canister
pub fn add_all_wasms_to_sns_wasm(env: &TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let sns_wasms = vec![
        (SnsCanisterType::Root, "sns-root-canister"),
        (SnsCanisterType::Governance, "sns-governance-canister"),
        (SnsCanisterType::Ledger, "ic-icrc1-ledger"),
        (SnsCanisterType::Swap, "sns-swap-canister"),
        (SnsCanisterType::Archive, "ic-icrc1-archive"),
        (SnsCanisterType::Index, "ic-icrc1-index"),
    ];
    info!(logger, "Setting SNS canister environment variables");
    env.set_sns_canisters_env_vars().unwrap();
    sns_wasms.into_iter().for_each(|(canister_type, bin_name)| {
        info!(logger, "Adding {bin_name} wasm to SNS wasms");
        block_on(add_wasm_to_sns_wasm(&runtime, canister_type, bin_name));
    });
}

/// Send and execute a proposal to add the given canister WASM
/// to the SNS WASM canister
pub async fn add_wasm_to_sns_wasm(
    nns_api: &'_ Runtime,
    canister_type: SnsCanisterType,
    bin_name: &str,
) {
    let governance_canister = get_governance_canister(nns_api);

    let wasm = Project::cargo_bin_maybe_from_env(bin_name, &[]);
    let wasm_hash = Sha256::hash(&wasm.clone().bytes()).to_vec();
    let proposal_payload = AddWasmRequest {
        wasm: Some(SnsWasm {
            wasm: wasm.bytes(),
            canister_type: canister_type.into(),
        }),
        hash: wasm_hash,
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddSnsWasm,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Send and execute a proposal to add the given principal ID to the SNS deploy whitelist
pub async fn add_principal_to_sns_deploy_whitelist(
    nns_api: &'_ Runtime,
    principal_id: PrincipalId,
) {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = UpdateAllowedPrincipalsRequest {
        added_principals: vec![principal_id],
        removed_principals: vec![],
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::UpdateAllowedPrincipals,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Send and execute a proposal to add the given subnet ID to the SNS subnet list
pub async fn add_subnet_to_sns_deploy_whitelist(nns_api: &'_ Runtime, subnet_id: SubnetId) {
    let governance_canister = get_governance_canister(nns_api);
    let proposal_payload = UpdateSnsSubnetListRequest {
        sns_subnet_ids_to_add: vec![subnet_id.get()],
        sns_subnet_ids_to_remove: vec![],
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::UpdateSnsWasmSnsSubnetIds,
        proposal_payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}

/// Send a "deploy_new_sns" request to the SNS WASM canister by forwarding it
/// with cycles through the given canister.
pub async fn deploy_new_sns(
    canister: &UniversalCanister<'_>,
    init: SnsInitPayload,
) -> Result<DeployNewSnsResponse, AgentError> {
    let sns_deploy = DeployNewSnsRequest {
        sns_init_payload: Some(init),
    };
    canister
        .forward_with_cycles_to(
            &SNS_WASM_CANISTER_ID.get().into(),
            "deploy_new_sns",
            Encode!(&sns_deploy).unwrap(),
            Cycles::from(180_000_000_000_000u64),
        )
        .await
        .map(|res| Decode!(res.as_slice(), DeployNewSnsResponse).expect("failed to decode"))
}

/// Call "get_state" on the SNS swap canister with the given ID by forwarding it
/// through the given canister.
pub async fn get_swap_state(
    canister: &UniversalCanister<'_>,
    swap_id: CanisterId,
) -> Result<GetStateResponse, AgentError> {
    canister
        .forward_to(
            &swap_id.get().into(),
            "get_state",
            Encode!(&GetStateRequest {}).unwrap(),
        )
        .await
        .map(|res| Decode!(res.as_slice(), GetStateResponse).expect("failed to decode"))
}

pub fn two_days_from_now_in_secs() -> u64 {
    SystemTime::now()
        .checked_add(2 * DAYS)
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn open_sns_token_swap_payload_for_tests(
    sns_swap_canister_id: PrincipalId,
) -> OpenSnsTokenSwap {
    OpenSnsTokenSwap {
        target_swap_canister_id: Some(sns_swap_canister_id),
        params: Some(Params {
            min_participants: 1,
            min_icp_e8s: 20 * E8,
            max_icp_e8s: 50 * E8,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 12 * E8,
            swap_due_timestamp_seconds: two_days_from_now_in_secs(),
            sns_token_e8s: 100 * E8,
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 1,
                dissolve_delay_interval_seconds: 30 * DAYS.as_secs(),
            }),
            sale_delay_seconds: None,
        }),
        community_fund_investment_e8s: Some(0),
    }
}

/// Send open sns token swap proposal to governance and wait until it is executed.
pub async fn open_sns_token_swap(nns_api: &'_ Runtime, payload: OpenSnsTokenSwap) {
    let governance_canister = get_governance_canister(nns_api);
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let manage_neuron_payload = ManageNeuron {
        id: Some(neuron_id),
        neuron_id_or_subaccount: None,
        command: Some(Command::MakeProposal(Box::new(Proposal {
            title: Some("title".to_string()),
            summary: "summary".to_string(),
            url: "https://forum.dfinity.org/t/x/".to_string(),
            action: Some(Action::OpenSnsTokenSwap(payload)),
        }))),
    };
    let proposer = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let res: ManageNeuronResponse = governance_canister
        .update_from_sender(
            "manage_neuron",
            candid_one,
            manage_neuron_payload,
            &proposer,
        )
        .await
        .unwrap();

    match res.command.unwrap() {
        CommandResp::MakeProposal(resp) => {
            vote_execute_proposal_assert_executed(
                &governance_canister,
                resp.proposal_id.unwrap().into(),
            )
            .await
        }
        other => panic!("Unexpected proposal response {other:?}"),
    }
}
