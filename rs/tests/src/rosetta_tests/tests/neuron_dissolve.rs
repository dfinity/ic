use crate::rosetta_tests::{
    lib::{do_multiple_txn, one_day_from_now_nanos, NeuronDetails},
    rosetta_client::RosettaApiClient,
    setup::setup,
    test_neurons::TestNeurons,
};
use ic_nns_governance_api::pb::v1::neuron::DissolveState;
use ic_rosetta_api::{
    models::{seconds::Seconds, AccountBalanceResponse, NeuronInfoResponse, NeuronState},
    request::{request_result::RequestResult, Request},
    request_types::{SetDissolveTimestamp, StartDissolve, StopDissolve},
};
use ic_rosetta_test_utils::{assert_canister_error, RequestInfo};
use ic_system_test_driver::{driver::test_env::TestEnv, util::block_on};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

const PORT: u32 = 8105;
const VM_NAME: &str = "rosetta-neuron-dissolve";

pub fn test(env: TestEnv) {
    let _logger = env.logger();

    let mut ledger_balances = HashMap::new();

    // Create neurons.
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let one_year_from_now = 60 * 60 * 24 * 365 + now;

    let mut neurons = TestNeurons::new(2000, &mut ledger_balances);

    let neuron1 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now));
        neuron.aging_since_timestamp_seconds = now;
    });
    let neuron2 = neurons.create(|neuron| {
        neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now));
        neuron.aging_since_timestamp_seconds = now;
    });
    let neuron3 = neurons.create(|_| {});

    // Create Rosetta and ledger clients.
    let neurons = neurons.get_neurons();
    let client = setup(&env, PORT, VM_NAME, Some(ledger_balances), Some(neurons));

    block_on(async {
        test_start_dissolve(&client, &neuron1)
            .await
            .expect("Failed test start dissolve");
        // Verify change of state.
        let metadata: NeuronInfoResponse = get_neuron_balance(&client, &neuron1)
            .await
            .metadata
            .try_into()
            .unwrap();
        assert_eq!(metadata.state, NeuronState::Dissolving);

        test_set_dissolve_timestamp_in_the_past_fail(&client, &neuron1).await;

        test_start_dissolve(&client, &neuron1)
            .await
            .expect("Failed test start dissolve again");

        test_stop_dissolve(&client, &neuron1)
            .await
            .expect("Failed test stop dissolve");

        test_stop_dissolve(&client, &neuron1)
            .await
            .expect("Failed test stop dissolve again");

        test_start_dissolve(&client, &neuron1)
            .await
            .expect("Failed to re-start dissolving neuron");

        // Test set dissolve timestamp to 5000 seconds in the future.
        let timestamp = Seconds::from(std::time::SystemTime::now() + Duration::from_secs(5000));
        test_set_dissolve_timestamp(&client, &neuron2, timestamp).await;

        // Set dissolve again (silently fail).
        test_set_dissolve_timestamp(&client, &neuron2, timestamp).await;

        // Note that this is an incorrect usage, but no error is returned.
        // Start and Stop operations never fail, even when they have no affect.
        test_start_dissolve(&client, &neuron3)
            .await
            .expect("Failed to start dissolving neuron before delay has been set");
    });
}

async fn get_neuron_balance(
    client: &RosettaApiClient,
    neuron: &NeuronDetails,
) -> AccountBalanceResponse {
    let res = client
        .account_balance_neuron(
            neuron.neuron_account,
            None,
            Some((
                neuron.public_key.clone(),
                neuron.neuron_subaccount_identifier,
            )),
            false,
        )
        .await;
    res.unwrap().unwrap()
}

async fn test_start_dissolve(
    ros: &RosettaApiClient,
    neuron_info: &NeuronDetails,
) -> Result<(), ic_rosetta_api::models::Error> {
    let account = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StartDissolve(StartDissolve {
                account,
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
                _type: Request::StartDissolve(_),
                ..
            }
        ));
    })
}

async fn test_stop_dissolve(
    ros: &RosettaApiClient,
    neuron_info: &NeuronDetails,
) -> Result<(), ic_rosetta_api::models::Error> {
    let account = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StopDissolve(StopDissolve {
                account,
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
                _type: Request::StopDissolve(_),
                ..
            }
        ));
    })
}

async fn test_set_dissolve_timestamp_in_the_past_fail(
    ros: &RosettaApiClient,
    neuron_details: &NeuronDetails,
) {
    let err = set_dissolve_timestamp(
        ros,
        neuron_details,
        Seconds::from(std::time::SystemTime::now() - Duration::from_secs(100000)),
    )
    .await;

    assert_canister_error(
        &err.unwrap_err(),
        750,
        "The dissolve delay must be set to a future time.",
    );
}

async fn test_set_dissolve_timestamp(
    ros: &RosettaApiClient,
    neuron_details: &NeuronDetails,
    delay_secs: Seconds,
) {
    set_dissolve_timestamp(ros, neuron_details, delay_secs)
        .await
        .unwrap();
}

async fn set_dissolve_timestamp(
    ros: &RosettaApiClient,
    neuron_info: &NeuronDetails,
    timestamp: Seconds,
) -> Result<(), ic_rosetta_api::models::Error> {
    let account = neuron_info.account_id;
    let key_pair = Arc::new(neuron_info.key_pair.clone());
    let neuron_index = neuron_info.neuron_subaccount_identifier;

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account,
                neuron_index,
                timestamp,
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
                _type: Request::SetDissolveTimestamp(_),
                ..
            }
        ));
    })
}
