use crate::rosetta_tests::ledger_client::LedgerClient;
use crate::rosetta_tests::lib::{
    create_ledger_client, do_multiple_txn, do_multiple_txn_external, one_day_from_now_nanos,
    NeuronDetails,
};
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::setup;
use crate::rosetta_tests::test_neurons::TestNeurons;
use ic_rosetta_api::request::request_result::RequestResult;
use ic_rosetta_api::request::Request;
use ic_rosetta_api::request_types::{NeuronInfo, Spawn, Status};
use ic_rosetta_test_utils::RequestInfo;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use rosetta_core::objects::ObjectMap;
use std::collections::HashMap;
use std::sync::Arc;

const PORT: u32 = 8106;
const VM_NAME: &str = "neuron-spawn";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);

    let neuron1 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 500_000_000;
    });
    let neuron2 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 4_000;
    });
    let neuron3 = neurons.create(|neuron| {
        neuron.maturity_e8s_equivalent = 500_000_000;
    });

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));
    let ledger_client = create_ledger_client(&env, &client);

    block_on(async {
        // Enough maturity.
        test_spawn(&client, &ledger_client, &neuron1, None).await;

        // Not enough maturity.
        test_spawn_invalid(&client, &neuron2).await;

        // Partial spawn.
        test_spawn(&client, &ledger_client, &neuron3, Some(75)).await;
    });
}

async fn test_spawn(
    ros: &RosettaApiClient,
    ledger: &LedgerClient,
    neuron_info: &NeuronDetails,
    percentage_to_spawn: Option<u32>,
) {
    let account = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    let neuron_acc = neuron_info.neuron_account;
    let balance_main_before = ledger.get_account_balance(neuron_acc).await;
    assert_ne!(
        balance_main_before.get_e8s(),
        0,
        "Neuron balance shouldn't be 0."
    );

    // the nonce used to generate spawned neuron.
    let spawned_neuron_index: u64 = 4321;
    let (tx_id, results, _) = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Spawn(Spawn {
                account,
                spawned_neuron_index,
                controller: None,
                percentage_to_spawn,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .expect("failed to spawn a neuron");

    assert!(!tx_id.is_transfer());
    assert!(matches!(
        results.operations.first().unwrap(),
        RequestResult {
            _type: Request::Spawn(_),
            status: Status::Completed,
            ..
        }
    ));

    // Check that the neuron is spawning.
    let res = do_multiple_txn_external(
        ros,
        &[RequestInfo {
            request: Request::NeuronInfo(NeuronInfo {
                account,
                controller: None,
                neuron_index: spawned_neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(_, results, _)| results)
    .expect("Failed to retrieve neuron info");

    assert_eq!(1, res.operations.len());
    let metadata: &ObjectMap = res
        .operations
        .first()
        .unwrap()
        .metadata
        .as_ref()
        .expect("No metadata found.");

    assert_eq!(
        "SPAWNING",
        metadata
            .get("state")
            .expect("State expected")
            .as_str()
            .unwrap()
    );
}

async fn test_spawn_invalid(ros: &RosettaApiClient, neuron_info: &NeuronDetails) {
    let account = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    // the nonce used to generate spawned neuron.
    let spawned_neuron_index: u64 = 5678;
    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Spawn(Spawn {
                account,
                spawned_neuron_index,
                controller: Option::None, // use default (same) controller.
                percentage_to_spawn: Option::None,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::Spawn(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    });

    assert!(
        res.is_err(),
        "Error expected while trying to spawn a neuron with no enough maturity"
    );

    let err = res.unwrap_err();
    assert_eq!(err.0.code, 770);
    assert_eq!(err.0.message, "Operation failed".to_string());
}
