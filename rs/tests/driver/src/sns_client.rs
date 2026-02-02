use crate::{
    canister_agent::HasCanisterAgentCapability,
    canister_api::{CallMode, ListDeployedSnsesRequest, SnsRequestProvider},
    driver::{
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
    },
    nns::{
        get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_executed,
    },
    util::{UniversalCanister, block_on, deposit_cycles, runtime_from_url, to_principal_id},
};
use anyhow::{Context, bail};
use candid::{Decode, Encode, Principal};
use canister_test::{Project, Runtime};
use dfn_candid::candid_one;
use ic_agent::{Agent, AgentError};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_canister_client::Sender;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL,
};
use ic_nervous_system_proto::pb::v1::{Duration, Image, Percentage, Tokens};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_governance_api::{
    CreateServiceNervousSystem, MakeProposalRequest, ManageNeuronCommandRequest,
    ManageNeuronRequest, ManageNeuronResponse, NnsFunction, ProposalActionRequest,
    create_service_nervous_system::{
        GovernanceParameters, InitialTokenDistribution, LedgerParameters, SwapParameters,
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            DeveloperDistribution, SwapDistribution, TreasuryDistribution,
            developer_distribution::NeuronDistribution,
        },
        swap_parameters::NeuronBasketConstructionParameters,
    },
    manage_neuron_response::Command as CommandResp,
};
use ic_nns_test_utils::sns_wasm::ensure_sns_wasm_gzipped;
use ic_sns_governance::pb::v1::governance::Mode;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_swap::pb::v1::{GetStateRequest, GetStateResponse, Lifecycle};
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, SnsCanisterIds, SnsCanisterType, SnsWasm, UpdateSnsSubnetListRequest,
};
use ic_types::Cycles;
use serde::{Deserialize, Serialize};
use slog::info;
use std::{str::FromStr, time::SystemTime};

pub const SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S: u64 = E8;
pub const SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S: u64 = 250_000 * E8;

#[derive(Clone, Debug, Deserialize, Serialize)]
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
        Principal::from(self.wallet_canister_id)
    }

    fn get_wallet_canister<'a>(&self, agent: &'a Agent) -> UniversalCanister<'a> {
        UniversalCanister::from_canister_id(agent, self.get_wallet_canister_principal())
    }

    pub async fn assert_state(&self, env: &TestEnv, swap_state: Lifecycle, governance_mode: Mode) {
        let log = env.logger();
        let swap_id = self.sns_canisters.swap();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let sns_agent = app_node.build_canister_agent().await;
        let wallet_canister = self.get_wallet_canister(&sns_agent.agent);

        // Check Swap state
        info!(log, r#"Sending "get_state" to SNS swap"#);
        let res = get_swap_state(&wallet_canister, swap_id)
            .await
            .expect("get_state failed")
            .swap
            .expect("No swap");
        info!(log, "Received {res:?}");
        assert_eq!(res.lifecycle(), swap_state);

        // Check Governance mode
        info!(log, r#"Sending "get_mode" to SNS governance"#);
        let sns_request_provider = SnsRequestProvider::from_sns_client(self);
        let request = sns_request_provider.get_sns_governance_mode();
        let res = sns_agent.call_and_parse(&request).await.result().unwrap();
        info!(log, "Received {res:?}");
        let actual_mode = Mode::try_from(res.mode.unwrap()).unwrap();
        assert_eq!(governance_mode, actual_mode);
    }

    /// Installs the SNS using the one-proposal flow
    pub fn install_sns_and_check_healthy(
        env: &TestEnv,
        create_service_nervous_system_proposal: CreateServiceNervousSystem,
    ) -> Self {
        add_all_wasms_to_sns_wasm(env);

        let log = env.logger();
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let app_node = env.get_first_healthy_application_node_snapshot();
        let subnet_id = app_node.subnet_id().unwrap();
        let canister_agent = block_on(app_node.build_canister_agent());

        info!(log, "Adding subnet {subnet_id} to SNS deploy whitelist");
        block_on(add_subnet_to_sns_deploy_whitelist(&runtime, subnet_id));

        // TODO: Check cycles balance before depositing, after depositing, and
        // after creating the SNS, to make sure it changes like we expect.
        // Currently blocked on NNS1-2302.

        info!(log, "Creating new canister with cycles");
        let wallet_canister = block_on(UniversalCanister::new_with_cycles_with_retries(
            &canister_agent.agent,
            app_node.effective_canister_id(),
            // Mint a very large amount of cycles, to make sure nothing fails
            // because this canister doesn't have enough cycles.
            900_000_000_000_000_000u64,
            &log,
        ));
        block_on(deposit_cycles(
            &wallet_canister,
            &candid::Principal::from(SNS_WASM_CANISTER_ID.get()),
            Cycles::new(200_000_000_000_000), // cost is 180T cycles, send 200T for a small buffer
        ));

        info!(
            log,
            "Submitting and executing CreateServiceNervousSystem proposal"
        );
        let sns_canisters = block_on(deploy_new_sns_via_proposal(
            env,
            create_service_nervous_system_proposal,
        ))
        .context("creating a new SNS")
        .unwrap();

        // Create SNS client and write it to the environment
        let wallet_canister_id = to_principal_id(&wallet_canister.canister_id());
        let sns_client = Self {
            sns_canisters,
            wallet_canister_id,
            sns_wasm_canister_id: SNS_WASM_CANISTER_ID.get(),
        };
        sns_client.write_attribute(env);

        info!(
            log,
            "Verifying that the SNS is healthy by calling `get_sns_canisters_summary`."
        );
        {
            let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
            let request = sns_request_provider.get_sns_canisters_summary();
            let actual_sns_canister_ids = SnsCanisterIds::from(
                block_on(canister_agent.call_and_parse(&request))
                    .result()
                    .unwrap(),
            );
            assert_eq!(sns_canisters, actual_sns_canister_ids);
        }

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
            // TODO: Provide a wallet canister for static testnet?
            wallet_canister_id: PrincipalId::from_str("aaaaa-aa").unwrap(),
            sns_wasm_canister_id: SNS_WASM_CANISTER_ID.get(),
        };
        sns_client.write_attribute(env);
        sns_client
    }
}

/// An CreateServiceNervousSystem request with "openchat-ish" parameters.
/// (Not guaranteed to be exactly the same as the actual parameters used by
/// OpenChat, especially since OpenChat was launched before
/// CreateServiceNervousSystem existed.)
///
/// These parameters should be the one used "by default" for most tests, to ensure
/// that the tests are using realistic parameters.
pub fn openchat_create_service_nervous_system_proposal() -> CreateServiceNervousSystem {
    let init: SnsInitPayload = SnsInitPayload::with_valid_values_for_testing_post_execution();
    CreateServiceNervousSystem {
        name: init.name,
        description: init.description,
        url: init.url,
        logo: Some(Image {
            base64_encoding: init.logo,
        }),
        fallback_controller_principal_ids: vec![*TEST_NEURON_1_OWNER_PRINCIPAL],
        dapp_canisters: vec![],
        initial_token_distribution: Some(InitialTokenDistribution {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake: Some(Tokens::from_e8s(230_000_000_000_000)), // 23%
                    memo: Some(0),
                    dissolve_delay: Some(Duration::from_secs(2_629_800)),
                    vesting_period: Some(Duration::from_secs(0)),
                }],
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total: Some(Tokens::from_e8s(5_200_000_000_000_000)), // 52%
            }),
            swap_distribution: Some(SwapDistribution {
                total: Some(Tokens::from_e8s(2_500_000_000_000_000)), // 25%
            }),
        }),
        swap_parameters: Some(SwapParameters {
            minimum_participants: Some(100),
            minimum_direct_participation_icp: Some(Tokens::from_tokens(500_000)),
            maximum_direct_participation_icp: Some(Tokens::from_tokens(1_000_000)),
            minimum_participant_icp: Some(Tokens::from_e8s(SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S)),
            maximum_participant_icp: Some(Tokens::from_e8s(SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S)),
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: Some(5),
                dissolve_delay_interval: Some(Duration::from_secs(7_889_400)),
            }),
            confirmation_text: None,
            restricted_countries: None,
            // With a start time of None, NNS Governance in the test configuration should start the swap immediately.
            start_time: None,
            duration: Some(Duration::from_secs(60 * 60 * 24 * 7)),
            neurons_fund_participation: Some(false),
            // Deprecated fields
            minimum_icp: None,
            maximum_icp: None,
            neurons_fund_investment_icp: None,
        }),
        ledger_parameters: Some(LedgerParameters {
            transaction_fee: Some(Tokens::from_e8s(100_000)),
            token_name: Some("MySnsToken".to_string()),
            token_symbol: Some("MST".to_string()),
            token_logo: Some(Image {
                base64_encoding: init.token_logo,
            }),
        }),
        governance_parameters: Some(GovernanceParameters {
            proposal_rejection_fee: Some(Tokens::from_e8s(1_000_000_000)),
            proposal_initial_voting_period: Some(Duration::from_secs(345_600)),
            proposal_wait_for_quiet_deadline_increase: Some(Duration::from_secs(86_400)),
            neuron_minimum_stake: Some(Tokens::from_e8s(400_000_000)),
            neuron_minimum_dissolve_delay_to_vote: Some(Duration::from_secs(2_629_800)),
            neuron_maximum_dissolve_delay: Some(Duration::from_secs(31_557_600)),
            neuron_maximum_dissolve_delay_bonus: Some(Percentage::from_percentage(100.0)),
            neuron_maximum_age_for_age_bonus: Some(Duration::from_secs(15_778_800)),
            neuron_maximum_age_bonus: Some(Percentage::from_percentage(25.0)),
            voting_reward_parameters: Some(VotingRewardParameters {
                initial_reward_rate: Some(Percentage::from_percentage(2.5)),
                final_reward_rate: Some(Percentage::from_percentage(2.5)),
                reward_rate_transition_duration: Some(Duration::from_secs(0)),
            }),
        }),
    }
}

/// A reasonable starting point for create_service_nervous_system proposals,
/// based on the openchat SNS parameters.
pub fn test_create_service_nervous_system_proposal(
    min_participants: u64,
) -> CreateServiceNervousSystem {
    let openchat_parameters = openchat_create_service_nervous_system_proposal();
    let swap_parameters = openchat_parameters
        .swap_parameters
        .as_ref()
        .unwrap()
        .clone();
    CreateServiceNervousSystem {
        swap_parameters: Some(
            ic_nns_governance_api::create_service_nervous_system::SwapParameters {
                minimum_participants: Some(min_participants),
                minimum_participant_icp: Some(Tokens::from_e8s(
                    SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
                )),
                maximum_participant_icp: Some(Tokens::from_e8s(
                    SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
                )),
                ..swap_parameters
            },
        ),
        ..openchat_parameters
    }
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
        (SnsCanisterType::Index, "ic-icrc1-index-ng"),
    ];
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
    let sns_wasm = SnsWasm {
        wasm: wasm.bytes(),
        canister_type: canister_type.into(),
        // Will be automatically filled in by SNS Governance
        proposal_id: None,
    };
    let sns_wasm = ensure_sns_wasm_gzipped(sns_wasm);
    let wasm_hash = sns_wasm.sha256_hash();
    let proposal_payload = AddWasmRequest {
        wasm: Some(sns_wasm),
        hash: wasm_hash.to_vec(),
        skip_update_latest_version: Some(false),
    };

    let proposal_id = submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddSnsWasm,
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

/// Create SNS with CreateServiceNervousSystem proposal.
async fn deploy_new_sns_via_proposal(
    env: &TestEnv,
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
) -> anyhow::Result<SnsCanisterIds> {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let nns_agent = nns_node.build_canister_agent().await;

    // Check that there are no SNSes
    let sns_wasm_canister_id = SNS_WASM_CANISTER_ID.get();
    let list_deployed_snses_request = {
        let mode = CallMode::Query;
        ListDeployedSnsesRequest::new(sns_wasm_canister_id.into(), mode)
    };
    {
        let current_snses = nns_agent
            .call_and_parse(&list_deployed_snses_request)
            .await
            .result()
            .context(format!("Listing deployed SNSes (by calling {sns_wasm_canister_id}) to make sure none already exist"))?;
        if current_snses.instances != vec![] {
            bail!("cannot create an sns as one already exists: {current_snses:?}")
        }
    }

    let governance_canister = get_governance_canister(&runtime);
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let manage_neuron_payload = ManageNeuronRequest {
        id: Some(neuron_id),
        neuron_id_or_subaccount: None,
        command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
            MakeProposalRequest {
                title: Some("title".to_string()),
                summary: "summary".to_string(),
                url: "https://forum.dfinity.org/t/x/".to_string(),
                action: Some(ProposalActionRequest::CreateServiceNervousSystem(
                    create_service_nervous_system_proposal,
                )),
            },
        ))),
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

    // Return the information about the deployed SNS
    let current_snses = nns_agent
            .call_and_parse(&list_deployed_snses_request)
            .await
            .result()
            .context(format!("Listing deployed SNSes (by calling {sns_wasm_canister_id}) to make sure none already exist"))?;
    if current_snses.instances.len() != 1 {
        bail!("not exactly one sns exists: {current_snses:?}")
    }
    Ok(SnsCanisterIds::from(current_snses.instances[0].clone()))
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
        .checked_add(std::time::Duration::from_secs(2 * 24 * 60 * 60)) // two days
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
