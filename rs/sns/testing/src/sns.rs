use std::{fs::File, io::Write};

use candid::{CandidType, Encode};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_agent::{
    pocketic_impl::PocketIcAgent,
    sns::{swap::SwapCanister, Sns},
    CallCanisters, ProgressNetwork,
};
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_ID;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    nervous_system_agent_helpers::{
        await_with_timeout,
        cycles_ledger::convert_icp_to_cycles,
        nns::{governance::propose_to_deploy_sns_and_wait, ledger::transfer},
        sns::{
            governance::{get_caller_neuron, wait_for_proposal_execution},
            swap::{await_swap_lifecycle, participate_in_swap},
        },
    },
    pocket_ic_helpers::{
        install_canister_on_subnet,
        nns::ledger::mint_icp,
        sns::{
            governance::EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
            swap::{is_auto_finalization_status_committed_or_err, swap_direct_participations},
        },
    },
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance_api::pb::v1::create_service_nervous_system::{
    initial_token_distribution::developer_distribution::NeuronDistribution, SwapParameters,
};

use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_sns_cli::{
    neuron_id_to_candid_subaccount::ParsedSnsNeuron,
    upgrade_sns_controlled_canister::{
        self, UpgradeSnsControlledCanisterArgs, UpgradeSnsControlledCanisterInfo,
    },
};
use ic_sns_governance_api::pb::v1::manage_neuron::Follow;
use ic_sns_swap::pb::v1::Lifecycle;
use icp_ledger::{AccountIdentifier, Memo, Tokens, TransferArgs, DEFAULT_TRANSFER_FEE};
use pocket_ic::nonblocking::PocketIc;
use tempfile::TempDir;
use url::Url;

// As per https://internetcomputer.org/docs/current/developer-docs/defi/rosetta/icp_rosetta/construction_api/staking/#dissolve-delay
const MINIMUM_DISSOLVE_DELAY_TO_VOTE: u32 = 15778800;

// TODO @rvem: I don't like the fact that this struct definition is copy-pasted from 'canister/canister.rs'.
// We should extract it into a separate crate and reuse in both canister and this crates.
#[derive(CandidType)]
pub struct TestCanisterInitArgs {
    pub greeting: Option<String>,
}

pub async fn install_test_canister(pocket_ic: &PocketIc, args: TestCanisterInitArgs) -> CanisterId {
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let features = &[];
    let test_canister_wasm =
        Wasm::from_location_specified_by_env_var("sns_testing_canister", features).unwrap();
    install_canister_on_subnet(
        pocket_ic,
        application_subnet_id,
        Encode!(&args).unwrap(),
        Some(test_canister_wasm),
        vec![ROOT_CANISTER_ID.get()],
    )
    .await
}

// PocketIC-specific version of 'create_sns' function.
// Generates all required identities internally
// Takes the list of IDs of the DApps that will be added to the SNS as an argument.
//
// Returns SNS canisters IDs and the dev participant ID.
pub async fn create_sns_pocket_ic(
    pocket_ic: &PocketIc,
    dev_participant_id: PrincipalId,
    dapp_canister_ids: Vec<CanisterId>,
) -> Sns {
    let dev_participant = PocketIcAgent::new(pocket_ic, dev_participant_id);

    let swap_treasury_id = PrincipalId::new_user_test_id(322);
    mint_icp(
        pocket_ic,
        swap_treasury_id.into(),
        Tokens::from_tokens(10_000_000_u64).unwrap(),
        None,
    )
    .await;
    let swap_treasury_agent = PocketIcAgent::new(pocket_ic, swap_treasury_id);
    let swap_partipants_agents = (1..20)
        .map(|i| PocketIcAgent::new(pocket_ic, PrincipalId::new_user_test_id(1000 + i as u64)))
        .collect();
    create_sns(
        &dev_participant,
        NeuronId {
            id: TEST_NEURON_1_ID,
        },
        &dev_participant,
        &swap_treasury_agent,
        swap_partipants_agents,
        dapp_canister_ids,
    )
    .await
}

// Creates SNS using agents provided as arguments:
// 1) neuron_agent - agent that controlls 'neuron_id'.
// 2) neuron_id - ID of the neuron that has a sufficient amount of stake to propose the SNS creation and adopt the proposal.
// 2) dev_participant_agent - Agent that will be used as an initial neuron in a newly created SNS. All other
//    neurons will follow the dev neuron.
// 3) swap_treasury_agent - Agent for the identity that has sufficient amout of ICP tokens to close the swap and
//    pay for cycles needed canister upgrade as well as all associated costs.
// 4) swap_participants_agents - Agents for the identities that will participate in the swap. The actual number of participants
//    is determined by the swap parameters. So only some of these agents might be used. Each agent participates in the swap,
//    follows the dev neuron for 'UpgradeSnsControlledCanister' proposals and increases its dissolve delay to be able to vote.
// 5) dapp_canister_ids - Canister IDs of the DApps that will be added to the SNS.
//
// Returns SNS canisters IDs.
pub async fn create_sns<C: CallCanisters + ProgressNetwork>(
    neuron_agent: &C,
    neuron_id: NeuronId,
    dev_participant_agent: &C,
    swap_treasury_agent: &C,
    swap_participants_agents: Vec<C>,
    dapp_canister_ids: Vec<CanisterId>,
) -> Sns {
    let sns_proposal_id = "1";
    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .with_dapp_canisters(dapp_canister_ids)
        .build();

    // Ugly hack to set developer identity to have initial neuron eligeble for voting
    create_service_nervous_system.initial_token_distribution = create_service_nervous_system
        .initial_token_distribution
        .map(|mut token_distribution| {
            token_distribution.developer_distribution = token_distribution
                .developer_distribution
                .map(|mut developer_distribution| {
                    developer_distribution.developer_neurons = vec![NeuronDistribution {
                        controller: Some(dev_participant_agent.caller().unwrap().into()),
                        dissolve_delay: Some(ic_nervous_system_proto::pb::v1::Duration::from_secs(
                            MINIMUM_DISSOLVE_DELAY_TO_VOTE as u64,
                        )),
                        memo: Some(400000),
                        stake: Some(ic_nervous_system_proto::pb::v1::Tokens { e8s: Some(400000) }),
                        vesting_period: Some(ic_nervous_system_proto::pb::v1::Duration::from_secs(
                            0,
                        )),
                    }];
                    developer_distribution
                });
            token_distribution
        });
    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();
    let mininum_participants = swap_parameters.minimum_participants.unwrap_or_default() as usize;
    assert_eq!(
        swap_parameters.start_time, None,
        "Expecting the swap start time to be None to start the swap immediately"
    );
    let (sns, _proposal_id) = propose_to_deploy_sns_and_wait(
        neuron_agent,
        neuron_id,
        create_service_nervous_system,
        sns_proposal_id,
    )
    .await;
    let sns_swap = sns.swap;
    await_swap_lifecycle(swap_treasury_agent, sns_swap, Lifecycle::Open, true)
        .await
        .expect("Expecting the swap to be open after creation");
    complete_sns_swap(
        swap_treasury_agent,
        &swap_participants_agents,
        swap_parameters,
        sns_swap,
    )
    .await;

    let sns_governance = sns.governance;

    let dev_participant_neuron_id = get_caller_neuron(dev_participant_agent, sns_governance)
        .await
        .unwrap();

    for swap_participant_agent in swap_participants_agents[0..mininum_participants].iter() {
        let swap_participant_neuron_id = get_caller_neuron(swap_participant_agent, sns_governance)
            .await
            .expect("Failed to get the caller neuron");
        let follow = Follow {
            followees: vec![dev_participant_neuron_id.clone()],
            // UpgradeSnsControlledCanister
            function_id: 3,
        };
        sns_governance
            .follow(
                swap_participant_agent,
                swap_participant_neuron_id.clone(),
                follow,
            )
            .await
            .expect("Failed to follow the dev neuron");

        sns_governance
            .increase_dissolve_delay(
                swap_participant_agent,
                swap_participant_neuron_id,
                MINIMUM_DISSOLVE_DELAY_TO_VOTE,
            )
            .await
            .unwrap();
    }

    sns
}

// Completes the swap by transferring the required amount of ICP from the "treasury" account
// and participating in the swap for each participant using agents provided as arguments:
// 1) swap_treasury_agent - Agent for the identity that has sufficient amout of ICP tokens to close the swap.
// 2) swap_participants_agents - Agents for the identities that will participate in the swap.
// 3) swap_parameters - Swap parameters that define the swap.
// 4) swap_canister - SNS Swap canister on which the swap will be completed.
async fn complete_sns_swap<C: CallCanisters + ProgressNetwork>(
    swap_treasury_agent: &C,
    swap_participants_agents: &[C],
    swap_parameters: SwapParameters,
    swap_canister: SwapCanister,
) {
    let swap_participations = swap_direct_participations(swap_parameters);
    for (swap_participant_amount, swap_participant_agent) in swap_participations
        .iter()
        .zip(swap_participants_agents.iter())
    {
        let transfer_args = TransferArgs {
            to: AccountIdentifier::new(swap_participant_agent.caller().unwrap().into(), None)
                .to_address(),
            amount: (*swap_participant_amount).saturating_add(DEFAULT_TRANSFER_FEE),
            fee: DEFAULT_TRANSFER_FEE,
            memo: Memo(0),
            from_subaccount: None,
            created_at_time: None,
        };
        transfer(swap_treasury_agent, transfer_args).await.unwrap();
        participate_in_swap(
            swap_participant_agent,
            swap_canister,
            *swap_participant_amount,
        )
        .await;
    }
    await_swap_lifecycle(
        swap_treasury_agent,
        swap_canister,
        Lifecycle::Committed,
        true,
    )
    .await
    .expect("Expecting the swap to be commited after creation and swap completion");
    await_with_timeout(
        swap_treasury_agent,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |agent| async {
            let auto_finalization_status = swap_canister
                .get_auto_finalization_status(agent)
                .await
                .expect("Failed to get auto finalization status");
            is_auto_finalization_status_committed_or_err(&auto_finalization_status)
        },
        &Ok(true),
    )
    .await
    .unwrap();
}

// PocketIC-specific version of 'upgrade_sns_controlled_test_canister' function.
// Upgrades the test canister controlled by the SNS using arguments:
// 1) pocket_ic - PocketIC instance.
// 2) dev_participant_id - ID of the identity that will be used to submit the proposal to upgrade the canister.
//    It is expected that neuron associated with this identity has sufficient amount of voting power to adopt the proposal
//    or it is followed by sufficient number of other neurons to have the proposal adopted using their voting power.
// 3) sns - SNS canisters.
// 4) canister_id - ID of the canister that will be upgraded.
// 5) upgrade_arg - Arguments that will be passed to the canister during the upgrade.
pub async fn upgrade_sns_controlled_test_canister_pocket_ic(
    pocket_ic: &PocketIc,
    dev_participant_id: PrincipalId,
    sns: Sns,
    canister_id: CanisterId,
    upgrade_arg: TestCanisterInitArgs,
) {
    let dev_participant_agent = PocketIcAgent::new(pocket_ic, dev_participant_id);
    mint_icp(
        pocket_ic,
        dev_participant_id.into(),
        Tokens::from_tokens(10_u64)
            .unwrap()
            .saturating_add(DEFAULT_TRANSFER_FEE),
        None,
    )
    .await;

    upgrade_sns_controlled_test_canister(&dev_participant_agent, sns, canister_id, upgrade_arg)
        .await;
}

// Upgrades the test canister controlled by the SNS using arguments:
// 1) dev_participant_agent - Agent for the identity that will be used to submit the proposal to upgrade the canister.
//    It is expected that neuron associated with this identity has sufficient amount of voting power to adopt the proposal
//    or it is followed by sufficient number of other neurons to have the proposal adopted using their voting power.
// 2) sns - SNS canisters.
// 3) canister_id - ID of the canister that will be upgraded.
// 4) upgrade_arg - Arguments that will be passed to the canister during the upgrade.
pub async fn upgrade_sns_controlled_test_canister<C: CallCanisters + ProgressNetwork>(
    dev_participant_agent: &C,
    sns: Sns,
    canister_id: CanisterId,
    upgrade_arg: TestCanisterInitArgs,
) {
    // For now, we're using the same wasm module, but different init arguments used in 'post_upgrade' hook.
    let features = &[];
    let test_canister_wasm =
        Wasm::from_location_specified_by_env_var("sns_testing_canister", features).unwrap();
    let modified_test_canister_wasm = modify_wasm_bytes(&test_canister_wasm.bytes(), 42);
    let temp_dir = TempDir::new().unwrap();
    let new_wasm_path = temp_dir.path().join("new_test_canister.wasm");
    {
        let mut new_wasm_file = File::create(&new_wasm_path).unwrap();
        new_wasm_file
            .write_all(&modified_test_canister_wasm)
            .unwrap();
        new_wasm_file.flush().unwrap();
    }

    let icp = Tokens::from_tokens(10).unwrap();
    convert_icp_to_cycles(dev_participant_agent, icp).await;

    let neuron_id = get_caller_neuron(dev_participant_agent, sns.governance)
        .await
        .unwrap();
    let candid_arg = (candid::IDLArgs {
        args: vec![candid::IDLValue::try_from_candid_type(&upgrade_arg).unwrap()],
    })
    .to_string();
    let upgrade_args = UpgradeSnsControlledCanisterArgs {
        sns_neuron_id: Some(ParsedSnsNeuron(neuron_id)),
        target_canister_id: canister_id,
        wasm_path: new_wasm_path,
        candid_arg: Some(candid_arg),
        proposal_url: Url::try_from("https://github.com/dfinity/ic").unwrap(),
        summary: "Upgrade Test canister".to_string(),
    };
    let UpgradeSnsControlledCanisterInfo { proposal_id, .. } =
        upgrade_sns_controlled_canister::exec(upgrade_args, dev_participant_agent)
            .await
            .expect("Failed to upgrade the canister");
    let proposal_id = proposal_id.unwrap();

    wait_for_proposal_execution(dev_participant_agent, sns.governance, proposal_id)
        .await
        .expect("Failed to execute the proposal");
    // Wait for the canister to become available
    await_with_timeout(
        dev_participant_agent,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |agent: &C| async {
            let canister_status = sns
                .root
                .get_sns_controlled_canister_status(agent, canister_id)
                .await
                .map(|result| result.status);
            println!("Canister status: {:?}", canister_status);
            canister_status
                .map(|status| status == CanisterStatusType::Running)
                .unwrap_or_default()
        },
        &true,
    )
    .await
    .expect("Test canister failed to get into the 'Running' state after upgrade");
}
