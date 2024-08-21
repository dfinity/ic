use crate::rosetta_tests::{
    lib::{
        create_governance_client, do_multiple_txn, one_day_from_now_nanos, to_public_key,
        NeuronDetails,
    },
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_agent::Identity;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance_api::pb::v1::{
    neuron::DissolveState, proposal::Action, MakeProposalRequest, Motion, Neuron, Proposal,
    ProposalActionRequest,
};
use ic_rosetta_api::{
    convert::neuron_subaccount_bytes_from_public_key,
    ledger_client::proposal_info_response::ProposalInfoResponse,
    models::{CallResponse, EdKeypair},
    request::{request_result::RequestResult, Request},
    request_types::{RegisterVote, Status},
};
use ic_rosetta_test_utils::RequestInfo;
use ic_system_test_driver::{
    driver::test_env::TestEnv,
    util::{block_on, get_identity, IDENTITY_PEM},
};
use slog::info;
use std::{collections::HashMap, sync::Arc, time::UNIX_EPOCH};

const PORT: u32 = 8111;
const VM_NAME: &str = "rosetta-neuron-voting";
pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let one_year_from_now = 60 * 60 * 24 * 365 + now;

    //We need to know the identity of the agent before we create the neurons.
    //The controller of the neuron has to be the agent principal otherwise we cannot make proposals and vote on them.
    let agent_identity = get_identity();
    let agent_principal = agent_identity.sender().unwrap();
    let agent_keypair = EdKeypair::deserialize_pkcs8_pem(IDENTITY_PEM).unwrap();

    // Create neurons and set the controller account to be the agent who makes the proposal with that neuron
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now));
        neuron.aging_since_timestamp_seconds = now;
        neuron.maturity_e8s_equivalent = 420_000_000;
        neuron.controller = Some(agent_principal.into());
        neuron.account =
            neuron_subaccount_bytes_from_public_key(&to_public_key(&agent_keypair), rand::random())
                .unwrap()
                .to_vec();
    };
    let neuron1 = neurons.create_custom(neuron_setup, 100, &agent_keypair);

    //Setup for non proposal making entities
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now));
        neuron.aging_since_timestamp_seconds = now;
        neuron.maturity_e8s_equivalent = 420_000_000;
    };
    let neuron2 = neurons.create(neuron_setup);
    let neuron3 = neurons.create(neuron_setup);
    let neurons = neurons.get_neurons();

    let proposal = MakeProposalRequest {
        title: Some("dummy title".to_string()),
        summary: "test".to_string(),
        action: Some(ProposalActionRequest::Motion(Motion {
            motion_text: "dummy text".to_string(),
        })),
        ..Default::default()
    };
    // Create Rosetta and ledger clients.
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let governance_client = create_governance_client(&env, &client);
    block_on(async {
        let first_proposal = governance_client.make_proposal(&neuron1, &proposal).await;

        //Test the endpoint get_proposal_info of rosetta
        let proposal_info_response: CallResponse = client
            .get_proposal_info(first_proposal.id)
            .await
            .unwrap()
            .unwrap();
        info!(
            _logger,
            "Test if received proposal matches the proposal created"
        );
        let proposal_info =
            ProposalInfoResponse::try_from(Some(proposal_info_response.result)).unwrap();

        let expected_proposal = Proposal {
            title: Some("dummy title".to_string()),
            summary: "test".to_string(),
            action: Some(Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
            })),
            ..Default::default()
        };
        assert_eq!(proposal_info.0.proposal.unwrap(), expected_proposal);
        info!(_logger, "Test Register Vote with Vote: Yes");
        test_register_proposal(&client, &neuron2, &first_proposal, &1).await;
        info!(_logger, "Test Register Vote with Vote: No");
        test_register_proposal(&client, &neuron3, &first_proposal, &2).await;

        //Test the endpoint get_pending_proposals of rosetta
        //Create a couple more proposals so there is something to query
        let second_proposal = governance_client.make_proposal(&neuron1, &proposal).await;
        let third_proposal = governance_client.make_proposal(&neuron1, &proposal).await;
        let pending_proposals = client.get_pending_proposals().await.unwrap();
        info!(
            _logger,
            "Test if get pending proposal matches the proposals created"
        );

        // Number of pending proposals should be 2 since the first proposal was already voted for
        assert_eq!(pending_proposals, vec![expected_proposal.clone(); 2]);

        // Vote on one the second proposal
        test_register_proposal(&client, &neuron2, &second_proposal, &1).await;
        test_register_proposal(&client, &neuron3, &second_proposal, &2).await;

        // Now it should be 1 proposal
        let pending_proposals = client.get_pending_proposals().await.unwrap();
        assert_eq!(pending_proposals, vec![expected_proposal.clone(); 1]);

        // Vote on third and last proposal
        test_register_proposal(&client, &neuron2, &third_proposal, &1).await;
        test_register_proposal(&client, &neuron3, &third_proposal, &2).await;

        // Now there should be no proposal left to vote for
        let pending_proposals = client.get_pending_proposals().await.unwrap();
        assert!(pending_proposals.is_empty());
    });
}

async fn test_register_proposal(
    ros: &RosettaApiClient,
    neuron_info: &NeuronDetails,
    proposal_id: &ProposalId,
    vote: &i32,
) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    //The caller of the register vote command has to be the same as the controller of the neuron
    //let key_pair: Arc<EdKeypair> = Arc::new(EdKeypair::from_pem(IDENTITY_PEM).unwrap());
    let key_pair: Arc<EdKeypair> = Arc::new(neuron_info.key_pair.clone());

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::RegisterVote(RegisterVote {
                account: acc,
                proposal: Some(proposal_id.id),
                vote: *vote,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        true,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        let request_result = results.operations.first().unwrap();
        assert!(matches!(
            request_result,
            RequestResult {
                _type: Request::RegisterVote(RegisterVote { .. }),
                status: Status::Completed,
                ..
            }
        ));
    })
    .expect("failed to register vote");
}
