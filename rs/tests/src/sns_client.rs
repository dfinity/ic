use std::str::FromStr;
use std::time::{Duration, SystemTime};

use candid::{Decode, Encode, Principal};
use canister_test::{Project, Runtime};
use dfn_candid::candid_one;
use ic_agent::{Agent, AgentError};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_governance::pb::v1::proposal::Action;
use ic_nns_governance::pb::v1::{
    manage_neuron::Command, manage_neuron_response::Command as CommandResp, ManageNeuron,
    ManageNeuronResponse, NnsFunction, OpenSnsTokenSwap, Proposal,
};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_sns_init::pb::v1::{
    sns_init_payload::InitialTokenDistribution, AirdropDistribution, DeveloperDistribution,
    FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload, SwapDistribution,
    TreasuryDistribution,
};
use ic_sns_swap::pb::v1::{GetStateRequest, GetStateResponse, Init, Lifecycle, Params};
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, DeployNewSnsRequest, DeployNewSnsResponse, SnsCanisterIds, SnsCanisterType,
    SnsWasm, UpdateAllowedPrincipalsRequest, UpdateSnsSubnetListRequest,
};
use ic_types::Cycles;
use serde::{Deserialize, Serialize};
use slog::info;

use crate::driver::test_env::TestEnvAttribute;
use crate::driver::test_env_api::{HasDependencies, NnsCanisterWasmStrategy};
use crate::{
    driver::{
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl, SnsCanisterEnvVars},
    },
    nns::{
        get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_executed,
    },
    util::{block_on, runtime_from_url, to_principal_id, UniversalCanister},
};

pub const SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S: u64 = E8;
pub const SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S: u64 = 150_000 * E8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnsClient {
    pub sns_canisters: SnsCanisterIds,
    pub wallet_canister_id: PrincipalId,
    pub sns_wasm_canister_id: PrincipalId,
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

    pub fn initiate_token_swap(
        &self,
        env: &TestEnv,
        params: Params,
        community_fund_investment_e8s: u64,
    ) {
        let log = env.logger();
        let swap_id = self.sns_canisters.swap();
        info!(log, "Sending open token swap proposal");
        let payload =
            open_sns_token_swap_payload(swap_id.get(), params, community_fund_investment_e8s);
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        block_on(open_sns_token_swap(&runtime, payload));
    }

    pub fn install_sns_and_check_healthy(
        env: &TestEnv,
        canister_wasm_strategy: NnsCanisterWasmStrategy,
    ) -> Self {
        add_all_wasms_to_sns_wasm(env, canister_wasm_strategy);

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
        let mut init = SnsInitPayload::with_valid_values_for_testing();
        // let mut init = SnsInitPayload::with_default_values();
        // Taken from https://github.com/open-ic/open-chat/blob/master/sns.yml
        init.transaction_fee_e8s = Some(100_000);
        init.proposal_reject_cost_e8s = Some(1_000_000_000);
        init.neuron_minimum_stake_e8s = Some(400_000_000);
        init.neuron_minimum_dissolve_delay_to_vote_seconds = Some(2_629_800);
        init.reward_rate_transition_duration_seconds = Some(0);
        // init.initial_reward_rate_percentage = Some(2.5);
        // init.final_reward_rate_percentage = Some(2.5);
        init.max_dissolve_delay_seconds = Some(31_557_600);
        init.max_neuron_age_seconds_for_age_bonus = Some(15_778_800);
        // init.max_dissolve_delay_bonus_multiplier = Some(2.0);
        // init.max_age_bonus_multiplier = Some(1.25);
        init.fallback_controller_principal_ids = vec![TEST_NEURON_1_OWNER_PRINCIPAL.to_string()];
        init.initial_voting_period_seconds = Some(345_600);
        init.wait_for_quiet_deadline_increase_seconds = Some(86_400);
        init.initial_token_distribution =
            Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
                FractionalDeveloperVotingPower {
                    developer_distribution: Some(DeveloperDistribution {
                        developer_neurons: vec![NeuronDistribution {
                            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                            stake_e8s: 230000000000000, // 23%
                            memo: 0,
                            dissolve_delay_seconds: 2629800,
                            vesting_period_seconds: Some(0),
                        }],
                    }),
                    treasury_distribution: Some(TreasuryDistribution {
                        total_e8s: 5200000000000000, // 52%
                    }),
                    swap_distribution: Some(SwapDistribution {
                        total_e8s: 2500000000000000, // 25%
                        initial_swap_amount_e8s: 2500000000000000,
                    }),
                    airdrop_distribution: Some(AirdropDistribution {
                        airdrop_neurons: Default::default(),
                    }),
                },
            ));

        let res = block_on(deploy_new_sns(&wallet_canister, init)).expect("Deploy new SNS failed");
        info!(log, "Received {res:?}");
        if let Some(error) = res.error {
            panic!("DeployNewSnsResponse returned error: {error:?}");
        }
        assert_eq!(res.subnet_id.expect("No subnet ID"), subnet_id.get());
        let sns_canisters = res.canisters.expect("No canister IDs");
        let wallet_canister_id = to_principal_id(&wallet_canister.canister_id());

        let sns_client = Self {
            sns_canisters,
            wallet_canister_id,
            sns_wasm_canister_id: SNS_WASM_CANISTER_ID.get(),
        };
        sns_client.assert_state(env, Lifecycle::Pending);
        sns_client.write_attribute(env);
        sns_client
    }

    pub fn get_sns_client_for_static_testnet(env: &TestEnv) -> SnsClient {
        let sns_canisters_str =
            std::env::var("SNS_CANISTERS").expect("variable SNS_CANISTERS not specified");
        let sns_canisters: ic_sns_init::SnsCanisterIds = serde_json::from_str(&sns_canisters_str)
            .unwrap_or_else(|_| panic!("cannot parse string as JSON: `{sns_canisters_str}`"));

        // Transform from a json-parsable representation to the protobuf representation which is
        // used to init the sns canisters.
        let sns_canisters = SnsCanisterIds {
            governance: sns_canisters.governance.into(),
            ledger: sns_canisters.ledger.into(),
            root: sns_canisters.root.into(),
            swap: sns_canisters.swap.into(),
            index: sns_canisters.index.into(),
        };

        let sns_client = SnsClient {
            sns_canisters,
            /// TODO: Provide a wallet canister for static testnet?
            wallet_canister_id: PrincipalId::from_str("aaaaa-aa").unwrap(),
            sns_wasm_canister_id: SNS_WASM_CANISTER_ID.get(),
        };
        sns_client.write_attribute(env);
        sns_client
    }
}

/// Send and execute 6 proposals to add all SNS canister WASMs to the SNS WASM canister
fn add_all_wasms_to_sns_wasm(env: &TestEnv, canister_wasm_strategy: NnsCanisterWasmStrategy) {
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
    match canister_wasm_strategy {
        NnsCanisterWasmStrategy::TakeBuiltFromSources => {
            info!(
                logger,
                "Adding SNS canisters build from the tip of the current branch ..."
            );
            env.set_sns_canisters_env_vars().unwrap();
        }
        NnsCanisterWasmStrategy::TakeLatestMainnetDeployments => {
            info!(logger, "Adding mainnet SNS canisters ...");
            env.set_mainnet_sns_canisters_env_vars().unwrap();
        }
        NnsCanisterWasmStrategy::NnsReleaseQualification => {
            let qual = env
                .read_dependency_to_string(
                    "rs/tests/qualifying-sns-canisters/selected-qualifying-sns-canisters.json",
                )
                .unwrap();
            info!(logger, "Adding qualification SNS canisters ({qual}) ...");
            env.set_qualifying_sns_canisters_env_vars().unwrap();
        }
    }
    sns_wasms.into_iter().for_each(|(canister_type, bin_name)| {
        info!(logger, "Adding {bin_name} wasm to SNS wasms");
        block_on(add_wasm_to_sns_wasm(&runtime, canister_type, bin_name));
    });
}

/// Send and execute a proposal to add the given canister WASM
/// to the SNS WASM canister
async fn add_wasm_to_sns_wasm(
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
async fn add_principal_to_sns_deploy_whitelist(nns_api: &'_ Runtime, principal_id: PrincipalId) {
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
async fn add_subnet_to_sns_deploy_whitelist(nns_api: &'_ Runtime, subnet_id: SubnetId) {
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
async fn deploy_new_sns(
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
async fn get_swap_state(
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
        .checked_add(Duration::from_secs(2 * 24 * 60 * 60)) // two days
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const fn open_sns_token_swap_payload(
    sns_swap_canister_id: PrincipalId,
    params: Params,
    community_fund_investment_e8s: u64,
) -> OpenSnsTokenSwap {
    OpenSnsTokenSwap {
        target_swap_canister_id: Some(sns_swap_canister_id),
        // Taken (mostly) from https://github.com/open-ic/open-chat/blob/master/sns_proposal.sh
        params: Some(params),
        community_fund_investment_e8s: Some(community_fund_investment_e8s),
    }
}

/// Send open sns token swap proposal to governance and wait until it is executed.
async fn open_sns_token_swap(nns_api: &'_ Runtime, payload: OpenSnsTokenSwap) {
    // Sanity check that params is valid
    let params = payload.params.as_ref().unwrap().clone();
    let () = params
        .validate(&Init {
            nns_governance_canister_id: "".to_string(),
            sns_governance_canister_id: "".to_string(),
            sns_ledger_canister_id: "".to_string(),
            icp_ledger_canister_id: "".to_string(),
            sns_root_canister_id: "".to_string(),
            fallback_controller_principal_ids: vec![],
            transaction_fee_e8s: Some(0),
            neuron_minimum_stake_e8s: Some(0),
            confirmation_text: None,
            restricted_countries: None,
        })
        .unwrap();

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
