use crate::driver::test_env::TestEnv;
use crate::rosetta_tests::lib::{
    create_governance_client, do_multiple_txn, one_day_from_now_nanos, NeuronDetails,
};
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::setup;
use crate::rosetta_tests::test_neurons::TestNeurons;
use crate::util::{block_on, get_identity, IDENTITY_PEM};
use ic_agent::Identity;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance::pb::v1::neuron::DissolveState;
use ic_nns_governance::pb::v1::Neuron;
use ic_rosetta_api::models::EdKeypair;
use ic_rosetta_api::request::request_result::RequestResult;
use ic_rosetta_api::request::Request;
use ic_rosetta_api::request_types::{RegisterVote, Status};
use ic_rosetta_test_utils::RequestInfo;
use slog::info;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

const PORT: u32 = 8111;
const VM_NAME: &str = "rosetta-test-neuron-voting";
pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let one_year_from_now = 60 * 60 * 24 * 365
        + std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    //We need to know the identity of the agent before we create the neurons.
    //The controller of the neuron has to be the agent principal otherwise we cannot make proposals and vote on them.
    let agent_identity = get_identity();
    let agent_principal = agent_identity.sender().unwrap();
    // Create neurons.
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now));
        neuron.maturity_e8s_equivalent = 420_000_000;
        neuron.controller = Some(agent_principal.into());
    };
    let neuron1 = neurons.create(neuron_setup);
    let neuron2 = neurons.create(neuron_setup);
    let neuron3 = neurons.create(neuron_setup);
    let neurons = neurons.get_neurons();
    // Create Rosetta and ledger clients.
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let governance_client = create_governance_client(&env, &client);
    block_on(async {
        let proposal_id = governance_client.make_proposal(&neuron1).await;
        info!(_logger, "Test Register Vote with Vote: Yes");
        test_register_proposal(&client, &neuron2, &proposal_id, &1).await;
        info!(_logger, "Test Register Vote with Vote: No");
        test_register_proposal(&client, &neuron3, &proposal_id, &1).await;
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
    let key_pair: Arc<EdKeypair> = Arc::new(EdKeypair::from_pem(IDENTITY_PEM).unwrap());

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
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::RegisterVote(RegisterVote { .. }),
                status: Status::Completed,
                ..
            }
        ));
    })
    .expect("failed to register vote");
}
