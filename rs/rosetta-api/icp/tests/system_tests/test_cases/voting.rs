use crate::common::{
    governance_client::GovernanceClient, system_test_environment::RosettaTestingEnvironment,
    utils::test_identity,
};
use candid::Principal;
use futures::future::join_all;
use ic_agent::{identity::BasicIdentity, Identity};
use ic_icp_rosetta_client::{
    RosettaCreateNeuronArgs, RosettaRegisterVoteArgs, RosettaSetNeuronDissolveDelayArgs,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::Motion;
use ic_nns_governance_api::pb::v1::ProposalInfo;
use ic_nns_governance_api::pb::v1::Vote;
use ic_nns_governance_api::pb::v1::{proposal::Action, Proposal};
use ic_rosetta_api::models::ConstructionSubmitResponse;
use icp_ledger::AccountIdentifier;
use lazy_static::lazy_static;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Runtime;
use tracing_subscriber;

// Seems trivial but helps with readability when using indexes.
const NEURON_INDEX: [u64; 4] = [0, 1, 2, 3];
const VOTE_YES: i32 = Vote::Yes as i32;
const VOTE_NO: i32 = Vote::No as i32;
const VOTE_UNSPECIFIED: i32 = Vote::Unspecified as i32;

const DISSOLVE_DELAY_6_MONTHS: u64 = 60 * 60 * 24 * 31 * 6 + 100;
const INITIAL_BALANCE: u64 = 100_000_000_000;

lazy_static! {
    pub static ref TEST_IDENTITY: Arc<BasicIdentity> = Arc::new(test_identity());
}

/// Test neuron voting and proposal resolution.
#[test]
fn test_neuron_voting() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = setup_environment().await;

        let governance_client = GovernanceClient::new(
            env.get_test_agent().await,
            Principal::from(GOVERNANCE_CANISTER_ID),
        );

        // Create neurons
        let neuron_ids = create_neurons(&env, INITIAL_BALANCE / 10, DISSOLVE_DELAY_6_MONTHS).await;

        // Ensure no proposals exist initially
        assert!(env
            .rosetta_client
            .get_pending_proposals(env.network_identifier.clone())
            .await
            .unwrap()
            .is_empty());

        // Submit multiple proposals
        for i in 0..3 {
            governance_client
                .submit_proposal(
                    TEST_IDENTITY.sender().unwrap(),
                    neuron_ids[0].into(),
                    &format!("dummy title {}", i),
                    &format!("test summary {}", i),
                    &format!("dummy text {}", i),
                )
                .await;
        }

        // Ensure all proposals are pending and have the expected details
        let all_proposals = env
            .rosetta_client
            .get_pending_proposals(env.network_identifier.clone())
            .await
            .unwrap();
        let all_proposals_from_governance = governance_client.get_pending_proposals().await;

        assert_eq!(all_proposals.len(), 3);
        assert_eq!(all_proposals_from_governance.len(), 3);

        let expected_proposals = vec![
            Proposal {
                title: Some("dummy title 0".to_string()),
                summary: "test summary 0".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "dummy text 0".to_string(),
                })),
                url: "".to_string(),
            },
            Proposal {
                title: Some("dummy title 1".to_string()),
                summary: "test summary 1".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "dummy text 1".to_string(),
                })),
                url: "".to_string(),
            },
            Proposal {
                title: Some("dummy title 2".to_string()),
                summary: "test summary 2".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "dummy text 2".to_string(),
                })),
                url: "".to_string(),
            },
        ];

        // Verify all proposals are pending and have the expected details both from
        // Rosetta and the governance canister directly.
        assert_eq!(all_proposals, expected_proposals);
        for (i, proposal) in all_proposals_from_governance.iter().enumerate() {
            assert_eq!(proposal.proposal.clone().unwrap(), expected_proposals[i]);
        }

        let proposal_ids = all_proposals_from_governance
            .iter()
            .map(|proposal| proposal.id.unwrap().id)
            .collect::<Vec<u64>>();

        // Vote on the first proposal and verify the YES vote was correctly registered
        register_vote(&env, proposal_ids[0], NEURON_INDEX[1], Vote::Yes)
            .await
            .unwrap();
        let voted_proposal_info = governance_client
            .get_proposal_info(all_proposals_from_governance[0].id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            extract_votes(&voted_proposal_info, &neuron_ids),
            vec![VOTE_YES, VOTE_YES, VOTE_UNSPECIFIED, VOTE_UNSPECIFIED]
        );

        // Register remaining votes for the first proposal
        register_vote(&env, proposal_ids[0], NEURON_INDEX[2], Vote::No)
            .await
            .unwrap();
        register_vote(&env, proposal_ids[0], NEURON_INDEX[3], Vote::No)
            .await
            .unwrap();
        let voted_proposal_info = governance_client
            .get_proposal_info(all_proposals_from_governance[0].id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            extract_votes(&voted_proposal_info, &neuron_ids),
            vec![VOTE_YES, VOTE_YES, VOTE_NO, VOTE_NO]
        );

        // Verify the first proposal is no longer pending
        let pending_proposals = env
            .rosetta_client
            .get_pending_proposals(env.network_identifier.clone())
            .await
            .unwrap();
        let pending_proposals_from_governance = governance_client.get_pending_proposals().await;
        assert_eq!(
            pending_proposals_from_governance,
            vec![
                all_proposals_from_governance[1].clone(),
                all_proposals_from_governance[2].clone()
            ]
        );
        assert_eq!(
            pending_proposals,
            vec![all_proposals[1].clone(), all_proposals[2].clone()]
        );

        // Vote on the second proposal and verify the No vote was correctly registered
        register_vote(&env, proposal_ids[1], NEURON_INDEX[2], Vote::No)
            .await
            .unwrap();
        let voted_proposal_info = governance_client
            .get_proposal_info(all_proposals_from_governance[1].id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            extract_votes(&voted_proposal_info, &neuron_ids),
            vec![VOTE_YES, VOTE_UNSPECIFIED, VOTE_NO, VOTE_UNSPECIFIED]
        );

        // Register remaining votes for the second proposal
        register_vote(&env, proposal_ids[1], NEURON_INDEX[1], Vote::Yes)
            .await
            .unwrap();
        register_vote(&env, proposal_ids[1], NEURON_INDEX[3], Vote::No)
            .await
            .unwrap();
        let voted_proposal_info = governance_client
            .get_proposal_info(all_proposals_from_governance[1].id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            extract_votes(&voted_proposal_info, &neuron_ids),
            vec![VOTE_YES, VOTE_YES, VOTE_NO, VOTE_NO]
        );

        // Verify the second proposal is no longer pending
        let pending_proposals = env
            .rosetta_client
            .get_pending_proposals(env.network_identifier.clone())
            .await
            .unwrap();
        let pending_proposals_from_governance = governance_client.get_pending_proposals().await;
        assert_eq!(
            pending_proposals_from_governance,
            vec![all_proposals_from_governance[2].clone()]
        );
        assert_eq!(pending_proposals, vec![all_proposals[2].clone()]);

        // Register votes for the third proposal and verify the No vote was correctly registered
        register_vote(&env, proposal_ids[2], NEURON_INDEX[3], Vote::No)
            .await
            .unwrap();
        let voted_proposal_info = governance_client
            .get_proposal_info(all_proposals_from_governance[2].id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            extract_votes(&voted_proposal_info, &neuron_ids),
            vec![VOTE_YES, VOTE_UNSPECIFIED, VOTE_UNSPECIFIED, VOTE_NO]
        );

        // Try to vote again on the same proposal with the same neuron and verify the error
        let invalid_vote_result =
            register_vote(&env, proposal_ids[2], NEURON_INDEX[3], Vote::No).await;
        assert!(invalid_vote_result
            .unwrap_err()
            .to_string()
            .contains("NeuronAlreadyVoted"));

        // Register remaining votes for the third proposal and verify the proposal is no longer pending
        register_vote(&env, proposal_ids[2], NEURON_INDEX[1], Vote::Yes)
            .await
            .unwrap();
        register_vote(&env, proposal_ids[2], NEURON_INDEX[2], Vote::No)
            .await
            .unwrap();
        let pending_proposals = env
            .rosetta_client
            .get_pending_proposals(env.network_identifier.clone())
            .await
            .unwrap();
        let pending_proposals_from_governance = governance_client.get_pending_proposals().await;
        assert_eq!(pending_proposals_from_governance.len(), 0);
        assert_eq!(pending_proposals.len(), 0);
    });
}

/// Set up the Rosetta testing environment with initial balances.
async fn setup_environment() -> RosettaTestingEnvironment {
    RosettaTestingEnvironment::builder()
        .with_initial_balances(
            vec![(
                AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                icp_ledger::Tokens::from_e8s(INITIAL_BALANCE),
            )]
            .into_iter()
            .collect(),
        )
        .with_governance_canister()
        .build()
        .await
}

/// Create neurons with the specified dissolve delay.
async fn create_neurons(
    env: &RosettaTestingEnvironment,
    staked_amount: u64,
    dissolve_delay: u64,
) -> Vec<NeuronId> {
    join_all(
        NEURON_INDEX
            .iter()
            .map(|&index| create_neuron_with_dissolve(env, staked_amount, index, dissolve_delay)),
    )
    .await
}

async fn set_dissolve_delay_from_now(
    env: &RosettaTestingEnvironment,
    neuron_index: u64,
    dissolve_period_secs: u64,
) {
    let dissolve_timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + dissolve_period_secs;
    env.rosetta_client
        .set_neuron_dissolve_delay(
            env.network_identifier.clone(),
            &(*TEST_IDENTITY).clone(),
            RosettaSetNeuronDissolveDelayArgs::builder(dissolve_timestamp_secs)
                .with_neuron_index(neuron_index)
                .build(),
        )
        .await
        .unwrap();
}

async fn create_neuron_with_dissolve(
    env: &RosettaTestingEnvironment,
    staked_amount: u64,
    neuron_index: u64,
    dissolve_period_secs: u64,
) -> NeuronId {
    let _ = tracing_subscriber::fmt::try_init();
    let neuron_response = env
        .rosetta_client
        .create_neuron(
            env.network_identifier.clone(),
            &(*TEST_IDENTITY).clone(),
            RosettaCreateNeuronArgs::builder(staked_amount.into())
                .with_from_subaccount([0; 32])
                .with_neuron_index(neuron_index)
                .build(),
        )
        .await
        .unwrap();
    set_dissolve_delay_from_now(env, neuron_index, dissolve_period_secs).await;
    if let serde_json::Value::Number(n) =
        &neuron_response.metadata.unwrap()["operations"][0]["metadata"]["neuron_id"]
    {
        return NeuronId {
            id: n.as_u64().unwrap(),
        };
    }
    panic!("Neuron creation failed");
}

async fn register_vote(
    env: &RosettaTestingEnvironment,
    proposal_id: u64,
    voter_neuron_index: u64,
    vote: Vote,
) -> anyhow::Result<ConstructionSubmitResponse> {
    env.rosetta_client
        .register_vote(
            env.network_identifier.clone(),
            &(*TEST_IDENTITY).clone(),
            RosettaRegisterVoteArgs::builder(proposal_id, vote as i32)
                .with_neuron_index(voter_neuron_index)
                .build(),
        )
        .await
}

fn extract_votes(proposal_info: &ProposalInfo, neuron_ids: &[NeuronId]) -> Vec<i32> {
    neuron_ids
        .iter()
        .map(|neuron_id| {
            proposal_info
                .ballots
                .get(&neuron_id.id)
                .map(|ballot| ballot.vote)
                .unwrap()
        })
        .collect()
}
