use crate::rosetta_tests::{
    lib::{make_user_ed25519, NeuronDetails},
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_ledger_core::Tokens;
use ic_nns_governance_api::pb::v1::KnownNeuronData;
use ic_rosetta_api::{
    ledger_client::list_known_neurons_response::ListKnownNeuronsResponse, models::CallResponse,
};
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use std::collections::HashMap;

const PORT: u32 = 8107;
const VM_NAME: &str = "rosetta-neuron-info";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let (acc, _, _, _) = make_user_ed25519(101);
    ledger_balances.insert(acc, Tokens::new(1000, 0).unwrap());

    let mut neurons = TestNeurons::new(0, &mut ledger_balances);

    let neuron0 = neurons.create(|neuron| {
        neuron.known_neuron_data = Some(KnownNeuronData {
            name: "0".to_owned(),
            description: Some("Neuron 0 description".to_owned()),
        })
    });
    let neuron1: NeuronDetails = neurons.create(|neuron| {
        neuron.known_neuron_data = Some(KnownNeuronData {
            name: "1".to_owned(),
            description: Some("Neuron 1 description".to_owned()),
        })
    });
    let neuron2 = neurons.create(|neuron| {
        neuron.known_neuron_data = Some(KnownNeuronData {
            name: "2".to_owned(),
            description: Some("Neuron 2 description".to_owned()),
        })
    });

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));

    block_on(async {
        let known_neurons: CallResponse = client.get_known_neurons().await.unwrap().unwrap();

        let mut known_neurons_response =
            ListKnownNeuronsResponse::try_from(Some(known_neurons.result)).unwrap();
        known_neurons_response.known_neurons.sort_by(
            |a: &ic_nns_governance_api::pb::v1::KnownNeuron,
             b: &ic_nns_governance_api::pb::v1::KnownNeuron| {
                a.id.unwrap().partial_cmp(&b.id.unwrap()).unwrap()
            },
        );

        // There should be three known neurons
        assert_eq!(known_neurons_response.known_neurons.len(), 3);
        for (known_neuron, neuron_details) in known_neurons_response
            .known_neurons
            .iter()
            .zip(vec![neuron0, neuron1, neuron2].iter())
        {
            let expected_known_neuron_data = KnownNeuronData {
                name: neuron_details.neuron.id.unwrap().id.to_string(),
                description: Some(format!(
                    "Neuron {} description",
                    neuron_details.neuron.id.unwrap().id
                )),
            };
            assert_eq!(
                known_neuron.known_neuron_data.clone().unwrap(),
                expected_known_neuron_data
            );
        }
    });
}
