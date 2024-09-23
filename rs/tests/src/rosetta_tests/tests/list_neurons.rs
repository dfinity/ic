use crate::rosetta_tests::{
    ledger_client::LedgerClient,
    lib::{
        create_ledger_client, do_multiple_txn_external, make_user_ed25519, one_day_from_now_nanos,
        to_public_key, NeuronDetails,
    },
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_agent::Identity;
use ic_ledger_core::Tokens;
use ic_nns_governance_api::pb::v1::Neuron;
use ic_rosetta_api::{
    convert::neuron_subaccount_bytes_from_public_key,
    ledger_client::list_neurons_response::ListNeuronsResponse, request::Request,
    request_types::ListNeurons,
};
use ic_rosetta_test_utils::{EdKeypair, RequestInfo};
use ic_system_test_driver::{
    driver::test_env::TestEnv,
    util::{block_on, get_identity, IDENTITY_PEM},
};
use rosetta_core::objects::ObjectMap;
use std::{collections::HashMap, sync::Arc};

const PORT: u32 = 8107;
const VM_NAME: &str = "neuron-info";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();
    let (acc, _, _, _) = make_user_ed25519(101);
    ledger_balances.insert(acc, Tokens::new(1000, 0).unwrap());

    // A user can only fetch the list of their own neurons. This is why the principals of the caller and the neuron controller have to match.
    let identity = get_identity();
    let principal = identity.sender().unwrap();
    let keypair = EdKeypair::deserialize_pkcs8_pem(IDENTITY_PEM).unwrap();

    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);
    let neuron_setup = |neuron: &mut Neuron| {
        neuron.controller = Some(principal.into());
        neuron.account =
            neuron_subaccount_bytes_from_public_key(&to_public_key(&keypair), rand::random())
                .unwrap()
                .to_vec();
    };
    let neuron1 = neurons.create_custom(neuron_setup, 100, &keypair);
    let neuron2 = neurons.create_custom(neuron_setup, 101, &keypair);
    let neuron3 = neurons.create_custom(neuron_setup, 102, &keypair);

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        test_list_neurons(
            &client,
            &ledger_client,
            vec![neuron1, neuron2, neuron3],
            principal.into(),
            keypair.into(),
        )
        .await;
    });
}

async fn test_list_neurons(
    ros: &RosettaApiClient,
    _ledger: &LedgerClient,
    neuron_details: Vec<NeuronDetails>,
    sender: icp_ledger::account_identifier::AccountIdentifier,
    owner: Arc<EdKeypair>,
) {
    let _expected_type = "LIST_NEURONS".to_string();
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::ListNeurons(ListNeurons { account: sender }),
            sender_keypair: owner.clone(),
        }],
        true,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results
                .operations
                .first()
                .expect("Expected one list neuron operation."),
            ic_rosetta_api::models::Operation {
                type_: _expected_type,
                ..
            }
        ));
        results
    })
    .expect("Failed to retrieve neuron list");

    assert_eq!(1, res.operations.len());
    let metadata: &ObjectMap = res
        .operations
        .first()
        .unwrap()
        .metadata
        .as_ref()
        .expect("No metadata found.");

    let mut list_neurons_response: ListNeuronsResponse =
        ListNeuronsResponse::try_from(Some(metadata.clone())).unwrap();
    list_neurons_response
        .0
        .full_neurons
        .sort_by(|a, b| a.id.unwrap().partial_cmp(&b.id.unwrap()).unwrap());
    assert_eq!(
        neuron_details.len(),
        list_neurons_response.0.full_neurons.len()
    );
    for (neuron_full, neuron_details) in list_neurons_response
        .0
        .full_neurons
        .iter()
        .zip(neuron_details.iter())
    {
        assert_eq!(neuron_details.neuron.id, neuron_full.id);
    }
}
