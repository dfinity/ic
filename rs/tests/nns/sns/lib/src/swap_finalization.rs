use std::time::Duration;

use ic_nns_governance_api::CreateServiceNervousSystem;
use ic_sns_governance::pb::v1::governance::Mode;
use ic_sns_swap::pb::v1::{GetDerivedStateResponse, GetLifecycleResponse, Lifecycle};
use ic_system_test_driver::{
    canister_agent::HasCanisterAgentCapability,
    canister_api::{CallMode, SnsRequestProvider},
    driver::{
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::GetFirstHealthyNodeSnapshot,
    },
    sns_client::SnsClient,
};
use slog::info;
use tokio::time::sleep;

/// If the swap is committed, waits for the swap to finalize (for up to 2 minutes).
pub async fn finalize_committed_swap(
    env: &TestEnv,
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
) {
    let log = env.logger();
    info!(log, "Finalizing the swap");

    let sns_client = SnsClient::read_attribute(env);
    let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_agent = app_node.build_canister_agent().await;

    info!(log, "Waiting for the swap to be finalized");

    wait_for_swap_to_finalize(env, Duration::from_secs(200)).await;

    sns_client
        .assert_state(env, Lifecycle::Committed, Mode::Normal)
        .await;

    info!(log, "Checking that the swap finalized successfully");

    info!(
        log,
        "Swap finalization check 1: Call swap's `get_state` and assert it contains the correct information"
    );
    let derived_swap_state = {
        let request = sns_request_provider.get_derived_swap_state(CallMode::Query);
        canister_agent
            .call_and_parse(&request)
            .await
            .result()
            .unwrap()
    };

    info!(
        log,
        "Swap finalization check 2: Get all neurons from SNS governance"
    );
    let neurons = get_all_neurons(env).await;

    info!(
        log,
        "Swap finalization check 3: Verify that the correct number of neurons were created"
    );
    let developer_distribution = create_service_nervous_system_proposal
        .initial_token_distribution
        .as_ref()
        .unwrap()
        .developer_distribution
        .as_ref()
        .unwrap();

    let initial_neuron_count = developer_distribution.developer_neurons.len();

    let neuron_basket_construction_parameters = create_service_nervous_system_proposal
        .swap_parameters
        .unwrap()
        .neuron_basket_construction_parameters
        .unwrap();
    let created_neuron_count = (derived_swap_state.direct_participant_count.unwrap()
        + derived_swap_state.cf_neuron_count.unwrap())
        * neuron_basket_construction_parameters.count.unwrap();

    let expected_neuron_count = initial_neuron_count as u64 + created_neuron_count;
    assert_eq!(neurons.len() as u64, expected_neuron_count);

    // Check that the dapp canisters are exclusively owned by the root canister
    let get_sns_canisters_summary_response = {
        let request = sns_request_provider.get_sns_canisters_summary();
        canister_agent
            .call_and_parse(&request)
            .await
            .result()
            .unwrap()
    };
    for canister_summary in get_sns_canisters_summary_response.dapps {
        let controllers = canister_summary.status.unwrap().settings.controllers;
        assert_eq!(
            controllers,
            vec![sns_client.sns_canisters.root.unwrap()],
            "dapp canisters should be exclusively owned by the root canister"
        );
    }
}

/// If the swap is aborted, waits for the swap to finalize (for up to 2 minutes), and verifies that the swap was finalized as expected.
pub async fn finalize_aborted_swap_and_check_success(
    env: TestEnv,
    expected_derived_swap_state: GetDerivedStateResponse,
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
) {
    let log = env.logger();
    info!(log, "Finalizing the swap");

    let sns_client = SnsClient::read_attribute(&env);
    let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_agent = app_node.build_canister_agent().await;

    info!(log, "Waiting for the swap to be finalized");

    wait_for_swap_to_finalize(&env, Duration::from_secs(200)).await;

    sns_client
        .assert_state(&env, Lifecycle::Aborted, Mode::PreInitializationSwap)
        .await;

    info!(log, "Checking that the swap finalized successfully");

    info!(
        log,
        "Swap finalization check 1: Call swap's `get_state` and assert it contains the correct information"
    );
    let derived_swap_state = {
        let request = sns_request_provider.get_derived_swap_state(CallMode::Query);
        canister_agent
            .call_and_parse(&request)
            .await
            .result()
            .unwrap()
    };

    assert_eq!(derived_swap_state, expected_derived_swap_state);

    info!(
        log,
        "Swap finalization check 2: Get all neurons from SNS governance"
    );
    let neurons = get_all_neurons(&env).await;

    info!(
        log,
        "Swap finalization check 3: Verify that the correct number of neurons were created"
    );
    let developer_distribution = create_service_nervous_system_proposal
        .initial_token_distribution
        .as_ref()
        .unwrap()
        .developer_distribution
        .as_ref()
        .unwrap();

    // No neurons should have been created
    let initial_neuron_count = developer_distribution.developer_neurons.len();
    assert_eq!(neurons.len(), initial_neuron_count);

    // The SNS should control no dapps
    let get_sns_canisters_summary_response = {
        let request = sns_request_provider.get_sns_canisters_summary();
        canister_agent
            .call_and_parse(&request)
            .await
            .result()
            .unwrap()
    };
    assert_eq!(
        get_sns_canisters_summary_response.dapps,
        vec![],
        "The SNS should control no dapps"
    );
}

async fn wait_for_swap_to_finalize(env: &TestEnv, max_duration: Duration) {
    let log = env.logger();

    let sns_client = SnsClient::read_attribute(env);
    let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_agent = app_node.build_canister_agent().await;

    let start_time = std::time::SystemTime::now();

    let GetLifecycleResponse {
        lifecycle,
        decentralization_sale_open_timestamp_seconds: _,
        decentralization_swap_termination_timestamp_seconds: _,
    } = {
        let request = sns_request_provider.get_lifecycle(CallMode::Update);
        canister_agent
            .call_and_parse(&request)
            .await
            .result()
            .unwrap()
    };
    let lifecycle = lifecycle.and_then(|v| Lifecycle::try_from(v).ok()).unwrap();
    if !lifecycle.is_terminal() {
        let derived_swap_state = {
            let request = sns_request_provider.get_derived_swap_state(CallMode::Query);
            canister_agent
                .call_and_parse(&request)
                .await
                .result()
                .unwrap()
        };
        panic!(
            "The swap must be in a terminal state to finalize, was {lifecycle:?}. Swap state: {derived_swap_state:?}"
        );
    }

    loop {
        let time_spend_waiting = std::time::SystemTime::now()
            .duration_since(start_time)
            .unwrap();
        if time_spend_waiting > max_duration {
            panic!("The swap did not finalize within {max_duration:?}!");
        }

        let auto_finalization_status = {
            let request = sns_request_provider.get_auto_finalization_status(CallMode::Update);
            canister_agent
                .call_and_parse(&request)
                .await
                .result()
                .unwrap()
        };

        if let Some(auto_finalize_swap_response) =
            auto_finalization_status.auto_finalize_swap_response
        {
            info!(
                log,
                "The swap has been finalized automatically. auto_finalize_swap_response: {:?}",
                auto_finalize_swap_response
            );
            assert_eq!(auto_finalize_swap_response.error_message, None);
            break;
        } else if auto_finalization_status.has_auto_finalize_been_attempted() {
            info!(log, "Automatic finalization in progress");
        } else {
            info!(
                log,
                "Automatic finalization has not been automatically attempted yet"
            );
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn get_all_neurons(env: &TestEnv) -> Vec<ic_sns_governance::pb::v1::Neuron> {
    let sns_client = SnsClient::read_attribute(env);
    let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_agent = app_node.build_canister_agent().await;

    let mut start_page_at = None;
    let mut neurons = Vec::new();
    'repeatedly_call_list_neurons: {
        let max_pages = 1000;
        for _ in 0..max_pages {
            let list_neurons_request =
                sns_request_provider.list_neurons(0, start_page_at.clone(), None, CallMode::Query);
            let neurons_page: Vec<ic_sns_governance::pb::v1::Neuron> = canister_agent
                .call_and_parse(&list_neurons_request)
                .await
                .result()
                .unwrap()
                .neurons;
            match neurons_page.last() {
                Some(last_neuron) => {
                    start_page_at.clone_from(&last_neuron.id);
                }
                None => {
                    assert!(neurons_page.is_empty());
                    break 'repeatedly_call_list_neurons;
                }
            }
            neurons.extend(neurons_page);
        }
        panic!(
            "Too many neurons created in SNS governance, unable to read all of them! (Tried calling list_neurons {max_pages} times.)"
        );
    }
    neurons
}

pub async fn wait_for_swap_to_start(env: &TestEnv) {
    let log: slog::Logger = env.logger();
    let start_time = std::time::SystemTime::now();
    let time_since_unix_epoch = start_time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let sns_client = SnsClient::read_attribute(env);
    let sns_request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_agent = app_node.build_canister_agent().await;

    let get_lifecycle_request = sns_request_provider.get_lifecycle(CallMode::Update);
    let lifecycle = canister_agent
        .call_and_parse(&get_lifecycle_request)
        .await
        .result()
        .unwrap();

    let seconds_to_wait = lifecycle
        .decentralization_sale_open_timestamp_seconds
        .unwrap()
        .saturating_sub(time_since_unix_epoch);

    if seconds_to_wait > 60 {
        panic!(
            "The SNS token swap will not start for over a minute ({seconds_to_wait} seconds). \
            Make sure that governance was compiled with the test feature enabled,
            and that no start time was specified in the CreateServiceNervousSystem proposal.",
        );
    }

    info!(
        log,
        "Waiting {} seconds for the swap to open", seconds_to_wait
    );

    sleep(Duration::from_secs(seconds_to_wait)).await;

    sns_client
        .assert_state(env, Lifecycle::Open, Mode::PreInitializationSwap)
        .await;

    info!(
        log,
        "==== The SNS token swap has opened successfully in {:?} ====",
        start_time.elapsed()
    );
}
