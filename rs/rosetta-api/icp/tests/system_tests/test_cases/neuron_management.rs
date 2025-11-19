use crate::common::utils::update_neuron;
use crate::common::utils::wait_for_rosetta_to_catch_up_with_icp_ledger;
use crate::common::{
    system_test_environment::RosettaTestingEnvironment,
    utils::{account_balance, get_custom_agent, get_test_agent, list_neurons, test_identity},
};
use core::convert::TryFrom;
use ic_agent::{Identity, identity::BasicIdentity};
use ic_icp_rosetta_client::RosettaChangeAutoStakeMaturityArgs;
use ic_icp_rosetta_client::RosettaDisburseMaturityArgs;
use ic_icp_rosetta_client::RosettaHotKeyArgs;
use ic_icp_rosetta_client::RosettaIncreaseNeuronStakeArgs;
use ic_icp_rosetta_client::RosettaNeuronInfoArgs;
use ic_icp_rosetta_client::RosettaSpawnNeuronArgs;
use ic_icp_rosetta_client::{
    RosettaCreateNeuronArgs, RosettaDisburseNeuronArgs, RosettaSetNeuronDissolveDelayArgs,
    RosettaStakeMaturityArgs,
};
use ic_icrc1_test_utils::basic_identity_strategy;
use ic_nns_governance_api::{KnownNeuronData, neuron::DissolveState};
use ic_rosetta_api::ledger_client::list_known_neurons_response::ListKnownNeuronsResponse;
use ic_rosetta_api::ledger_client::list_neurons_response::ListNeuronsResponse;
use ic_rosetta_api::ledger_client::neuron_response::NeuronResponse;
use ic_rosetta_api::models::AccountBalanceRequest;
use ic_rosetta_api::request::transaction_operation_results::TransactionOperationResults;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::ObjectMap;
use rosetta_core::request_types::CallRequest;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Runtime;
use tokio::time::sleep;

lazy_static! {
    pub static ref TEST_IDENTITY: Arc<BasicIdentity> = Arc::new(test_identity());
    pub static ref NUM_TEST_CASES: u32 = 1;
}

#[test]
fn test_create_neuron() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neurons = list_neurons(&agent).await;

        assert!(!neurons.full_neurons.is_empty());
        assert!(neurons.full_neurons.clone().into_iter().all(|n| {
            n.controller == Some(PrincipalId::from(TEST_IDENTITY.sender().unwrap()))
                && n.cached_neuron_stake_e8s == staked_amount
        }));
    });
}

#[test]
fn test_increase_neuron_stake() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let initial_balance = 100_000_000_000;
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_e8s(initial_balance),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = initial_balance / 10;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // Try to stake more than the amount of ICP in the account
        match env
            .rosetta_client
            .increase_neuron_stake(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaIncreaseNeuronStakeArgs::builder(u64::MAX.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
        {
            Err(e)
                if e.to_string().contains(
                    "the debit account doesn't have enough funds to complete the transaction",
                ) => {}
            Err(e) => panic!("Unexpected error: {e}"),
            Ok(ok) => panic!("Expected an errorm but got: {ok:?}"),
        }

        // Now we try with a valid amount
        let additional_stake = initial_balance / 10;
        env.rosetta_client
            .increase_neuron_stake(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaIncreaseNeuronStakeArgs::builder(additional_stake.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(
            neuron.cached_neuron_stake_e8s,
            staked_amount + additional_stake
        );

        wait_for_rosetta_to_catch_up_with_icp_ledger(
            &env.rosetta_client,
            env.network_identifier.clone(),
            &agent,
        )
        .await;

        let balance = env
            .rosetta_client
            .account_balance(
                AccountBalanceRequest::builder(
                    env.network_identifier.clone(),
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()).into(),
                )
                .build(),
            )
            .await
            .unwrap()
            .balances
            .first()
            .unwrap()
            .value
            .parse::<u64>()
            .unwrap();
        assert_eq!(
            balance,
            initial_balance - staked_amount - additional_stake - DEFAULT_TRANSFER_FEE.get_e8s() * 2
        );
    });
}

#[test]
fn test_set_neuron_dissolve_delay_timestamp() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();

        let dissolve_delay_timestamp = match neuron.dissolve_state.unwrap() {
            // When a neuron is created it has a one week dissolve delay
            DissolveState::DissolveDelaySeconds(dissolve_delay_timestamp) => {
                dissolve_delay_timestamp
            }
            k => panic!(
                "Neuron should be in WhenDissolvedTimestampSeconds state, but is instead: {k:?}"
            ),
        };

        let one_week = 24 * 60 * 60 * 7;
        assert_eq!(dissolve_delay_timestamp, one_week);

        let new_dissolve_delay = dissolve_delay_timestamp + 1000;
        let new_dissolve_delay_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + new_dissolve_delay;

        // To be able to set the dissolve delay timestamp we need to set the state machine to live again
        env.rosetta_client
            .set_neuron_dissolve_delay(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaSetNeuronDissolveDelayArgs::builder(new_dissolve_delay_timestamp)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();

        let dissolve_delay_timestamp = match neuron.dissolve_state.unwrap() {
            // The neuron now has a new dissolve delay timestamp and is in NOT DISSOLVING which corresponds to a dissolve delay that is greater than 0
            DissolveState::DissolveDelaySeconds(dissolve_delay_timestamp) => {
                dissolve_delay_timestamp
            }
            k => panic!("Neuron should be in DissolveDelaySeconds state, but is instead: {k:?}"),
        };
        // The Dissolve Delay Timestamp should be updated
        // Since the state machine is live we do not know exactly how much time will be left at the time of calling the governance canister.
        // It should be between dissolve_delay_timestamp and dissolve_delay_timestamp - X seconds depending on how long it takes to call the governance canister
        assert!(dissolve_delay_timestamp <= new_dissolve_delay);
        assert!(dissolve_delay_timestamp > new_dissolve_delay - 10);

        assert!(dissolve_delay_timestamp > 0);
    });
}

#[test]
fn test_start_and_stop_neuron_dissolve() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        let dissolve_delay_timestamp = match neuron.dissolve_state.unwrap() {
            // When a neuron is created its dissolve delay timestamp is set to two weeks from now and is in NOT DISSOLVING state
            DissolveState::DissolveDelaySeconds(dissolve_delay_timestamp) => {
                dissolve_delay_timestamp
            }
            k => panic!("Neuron should be in DissolveDelaySeconds state, but is instead: {k:?}"),
        };
        let start_dissolving_response = TransactionOperationResults::try_from(
            env.rosetta_client
                .start_dissolving_neuron(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    neuron_index,
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();

        // The neuron should now be in DISSOLVING state
        assert_eq!(
            start_dissolving_response.operations.first().unwrap().status,
            Some("COMPLETED".to_owned()),
            "Expected the operation to be completed but got: {start_dissolving_response:?}"
        );
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        match neuron.dissolve_state.unwrap() {
            DissolveState::WhenDissolvedTimestampSeconds(d) => {
                assert!(dissolve_delay_timestamp <= d);
            }
            k => panic!("Neuron should be in DissolveDelaySeconds state, but is instead: {k:?}"),
        };

        // When we try to dissolve an already dissolving neuron the response should succeed with no change to the neuron
        let start_dissolving_response = TransactionOperationResults::try_from(
            env.rosetta_client
                .start_dissolving_neuron(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    neuron_index,
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();
        assert_eq!(
            start_dissolving_response.operations.first().unwrap().status,
            Some("COMPLETED".to_owned())
        );
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert!(
            matches!(
                neuron.dissolve_state.clone().unwrap(),
                DissolveState::WhenDissolvedTimestampSeconds(_)
            ),
            "Neuron should be in WhenDissolvedTimestampSeconds state, but is instead: {:?}",
            neuron.dissolve_state.unwrap()
        );

        // Stop dissolving the neuron
        let stop_dissolving_response = TransactionOperationResults::try_from(
            env.rosetta_client
                .stop_dissolving_neuron(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    neuron_index,
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();
        assert_eq!(
            stop_dissolving_response.operations.first().unwrap().status,
            Some("COMPLETED".to_owned())
        );
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert!(matches!(
            neuron.dissolve_state.unwrap(),
            DissolveState::DissolveDelaySeconds(_)
        ));
    });
}

#[test]
fn test_change_auto_stake_maturity() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        // The neuron should not have auto stake maturity set
        assert!(neuron.auto_stake_maturity.is_none());

        // Change the auto stake maturity to true
        let change_auto_stake_maturity_response = TransactionOperationResults::try_from(
            env.rosetta_client
                .change_auto_stake_maturity(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    RosettaChangeAutoStakeMaturityArgs::builder(true)
                        .with_neuron_index(neuron_index)
                        .build(),
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();

        assert_eq!(
            change_auto_stake_maturity_response
                .operations
                .first()
                .unwrap()
                .status,
            Some("COMPLETED".to_owned())
        );
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert!(neuron.auto_stake_maturity.unwrap());

        // Change the auto stake maturity to false
        let change_auto_stake_maturity_response = TransactionOperationResults::try_from(
            env.rosetta_client
                .change_auto_stake_maturity(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    RosettaChangeAutoStakeMaturityArgs::builder(false)
                        .with_neuron_index(neuron_index)
                        .build(),
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();

        assert_eq!(
            change_auto_stake_maturity_response
                .operations
                .first()
                .unwrap()
                .status,
            Some("COMPLETED".to_owned())
        );
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert!(neuron.auto_stake_maturity.is_none());
    });
}

#[test]
fn test_disburse_neuron() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let initial_balance = 100_000_000_000;
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_e8s(initial_balance),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = initial_balance/10;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();
        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;

        TransactionOperationResults::try_from(
            env.rosetta_client
                .start_dissolving_neuron(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    neuron_index,
                )
                .await
                .unwrap()
                .metadata,
        )
        .unwrap();

        let mut neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        // If we try to disburse the neuron when it is not yet DISSOLVED we expect an error
        match env
            .rosetta_client
            .disburse_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaDisburseNeuronArgs::builder(neuron_index)
                    .with_recipient(TEST_IDENTITY.sender().unwrap().into())
                    .build(),
            )
            .await
        {
            Err(e) if e.to_string().contains(&format!("Could not disburse: PreconditionFailed: Neuron {} has NOT been dissolved. It is in state Dissolving",neuron.id.unwrap().id)) => (),
            Err(e) => panic!("Unexpected error: {e}"),
            Ok(_) => panic!("Expected an error but got success"),
        }
        // Let rosetta catch up with the transfer that happended when creating the neuron
        wait_for_rosetta_to_catch_up_with_icp_ledger(
            &env.rosetta_client,
            env.network_identifier.clone(),
            &agent,
        ).await;
        let balance_before_disburse = env
        .rosetta_client
        .account_balance(
            AccountBalanceRequest::builder(
                env.network_identifier.clone(),
                AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()).into(),
            )
            .build(),
        )
        .await
        .unwrap()
        .balances
        .first()
        .unwrap()
        .clone()
        .value.parse::<u64>().unwrap();

        // We now update the neuron so it is in state DISSOLVED
        let now_system_time: SystemTime = env.pocket_ic.get_time().await.try_into().unwrap();
        let now = now_system_time.duration_since(UNIX_EPOCH).unwrap().as_secs();
        neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(now - 1));
        update_neuron(&agent, neuron).await;

        match list_neurons(&agent).await.full_neurons[0].dissolve_state.clone().unwrap() {
            DissolveState::WhenDissolvedTimestampSeconds (d) => {
                // The neuron should now be in DISSOLVED state
                assert!(d<now);
            }
            k => panic!(
                "Neuron should be in DissolveDelaySeconds state, but is instead: {k:?}"
            ),
        }

        // Now we should be able to disburse the neuron
        env.rosetta_client
            .disburse_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaDisburseNeuronArgs::builder(neuron_index)
                    .with_recipient(TEST_IDENTITY.sender().unwrap().into())
                    .build(),
            )
            .await
            .unwrap();

        // Wait for the ledger to sync up to the block where the disbursement happened
        wait_for_rosetta_to_catch_up_with_icp_ledger(
            &env.rosetta_client,
            env.network_identifier.clone(),
            &agent,
        )
        .await;

        // The recipient should have received the disbursed amount
        let balance_after_disburse = env
            .rosetta_client
            .account_balance(
                AccountBalanceRequest::builder(
                    env.network_identifier.clone(),
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()).into(),
                )
                .build(),
            )
            .await
            .unwrap()
            .balances
            .first()
            .unwrap().clone()
            .value.parse::<u64>().unwrap();
        // The balance should be the same as before the creation of the neuron minus the transfer fee
        assert_eq!(balance_after_disburse, balance_before_disburse + staked_amount - DEFAULT_TRANSFER_FEE.get_e8s());
    });
}

#[test]
fn test_list_known_neurons() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into()).build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let mut neuron = list_neurons(&agent).await.full_neurons[0].to_owned();

        neuron.known_neuron_data = Some(KnownNeuronData {
            name: "KnownNeuron 0".to_owned(),
            description: Some("This is a known neuron".to_owned()),
            links: Some(vec![]),
            committed_topics: Some(vec![]),
        });
        update_neuron(&agent, neuron).await;

        let known_neurons = ListKnownNeuronsResponse::try_from(Some(
            env.rosetta_client
                .call(CallRequest {
                    network_identifier: env.network_identifier.clone(),
                    method_name: "list_known_neurons".to_owned(),
                    parameters: ObjectMap::new(),
                })
                .await
                .unwrap()
                .result,
        ))
        .unwrap();

        assert_eq!(known_neurons.known_neurons.len(), 1);
        assert_eq!(
            known_neurons.known_neurons[0]
                .known_neuron_data
                .clone()
                .unwrap(),
            KnownNeuronData {
                name: "KnownNeuron 0".to_owned(),
                description: Some("This is a known neuron".to_owned()),
                links: Some(vec![]),
                committed_topics: Some(vec![]),
            }
        );
    });
}

#[test]
fn test_get_neuron_info() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();

        let neuron_info = NeuronResponse::try_from(
            TransactionOperationResults::try_from(
                env.rosetta_client
                    .get_neuron_info(
                        env.network_identifier.clone(),
                        RosettaNeuronInfoArgs::builder(neuron_index)
                            .with_principal_id(TEST_IDENTITY.sender().unwrap().into())
                            .build(),
                        &(*TEST_IDENTITY).clone(),
                    )
                    .await
                    .unwrap()
                    .metadata,
            )
            .unwrap()
            .operations
            .first()
            .unwrap()
            .clone()
            .metadata
            .unwrap(),
        )
        .unwrap();

        assert_eq!(neuron_info.neuron_id, neuron.id.unwrap().id);
        assert_eq!(neuron_info.controller.0, TEST_IDENTITY.sender().unwrap());

        let neuron_info = NeuronResponse::try_from(
            TransactionOperationResults::try_from(
                env.rosetta_client
                    .get_neuron_info(
                        env.network_identifier.clone(),
                        RosettaNeuronInfoArgs::builder(neuron_index)
                            .with_public_key((&Arc::new(test_identity())).into())
                            .build(),
                        &(*TEST_IDENTITY).clone(),
                    )
                    .await
                    .unwrap()
                    .metadata,
            )
            .unwrap()
            .operations
            .first()
            .unwrap()
            .clone()
            .metadata
            .unwrap(),
        )
        .unwrap();

        assert_eq!(neuron_info.neuron_id, neuron.id.unwrap().id);
        assert_eq!(neuron_info.controller.0, TEST_IDENTITY.sender().unwrap());

        assert!(
            env.rosetta_client
                .get_neuron_info(
                    env.network_identifier.clone(),
                    // Ask for a neuron that does not exist
                    RosettaNeuronInfoArgs::builder(neuron_index + 1)
                        .with_public_key((&Arc::new(test_identity())).into())
                        .build(),
                    &(*TEST_IDENTITY).clone(),
                )
                .await
                .is_err()
        );
    });
}

#[test]
fn test_hotkey_management() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(basic_identity_strategy().no_shrink()),
            |hot_key_identity| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let env = RosettaTestingEnvironment::builder()
                        .with_initial_balances(
                            vec![(
                                AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                                // A hundred million ICP should be enough
                                icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                            )]
                            .into_iter()
                            .collect(),
                        )
                        .with_governance_canister()
                        .build()
                        .await;

                    // Stake the minimum amount 100 million e8s
                    let staked_amount = 100_000_000u64;
                    let neuron_index = 0;

                    env.rosetta_client
                        .create_neuron(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaCreateNeuronArgs::builder(staked_amount.into())
                                .with_neuron_index(neuron_index)
                                .build(),
                        )
                        .await
                        .unwrap();

                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
                    let neuron = list_neurons(&agent)
                        .await
                        .full_neurons
                        .first()
                        .unwrap()
                        .to_owned();
                    // Make sure that the neuron has no hot keys
                    assert!(neuron.hot_keys.is_empty());

                    // Add a hot key to the neuron
                    env.rosetta_client
                        .add_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index)
                                .with_principal_id(hot_key_identity.sender().unwrap().into())
                                .build(),
                        )
                        .await
                        .unwrap();

                    let neuron = list_neurons(&agent)
                        .await
                        .full_neurons
                        .first()
                        .unwrap()
                        .to_owned();
                    // Make sure that the neuron has a hot key
                    assert_eq!(neuron.hot_keys.len(), 1);
                    assert_eq!(
                        neuron.hot_keys.first().unwrap().0,
                        hot_key_identity.sender().unwrap()
                    );

                    // Remove the hot key from the neuron
                    env.rosetta_client
                        .remove_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index)
                                .with_principal_id(hot_key_identity.sender().unwrap().into())
                                .build(),
                        )
                        .await
                        .unwrap();

                    let neuron = list_neurons(&agent)
                        .await
                        .full_neurons
                        .first()
                        .unwrap()
                        .to_owned();
                    // Make sure that the neuron has no hot keys
                    assert!(neuron.hot_keys.is_empty());
                    let hot_key_identity = Arc::new(hot_key_identity);
                    // Now we try the same but with a public key
                    env.rosetta_client
                        .add_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index)
                                .with_public_key((&hot_key_identity).into())
                                .build(),
                        )
                        .await
                        .unwrap();

                    let neuron = list_neurons(&agent)
                        .await
                        .full_neurons
                        .first()
                        .unwrap()
                        .to_owned();
                    // Make sure that the neuron has a hot key
                    assert_eq!(neuron.hot_keys.len(), 1);
                    assert_eq!(
                        neuron.hot_keys.first().unwrap().0,
                        hot_key_identity.sender().unwrap()
                    );

                    // Remove the hot key from the neuron
                    env.rosetta_client
                        .remove_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index)
                                .with_public_key((&hot_key_identity).into())
                                .build(),
                        )
                        .await
                        .unwrap();

                    let neuron = list_neurons(&agent)
                        .await
                        .full_neurons
                        .first()
                        .unwrap()
                        .to_owned();
                    // Make sure that the neuron has no hot keys
                    assert!(neuron.hot_keys.is_empty());

                    // Now we try to not provide a key
                    match env
                        .rosetta_client
                        .add_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index).build(),
                        )
                        .await
                    {
                        Err(e)
                            if e.to_string()
                                .contains("Either public key or principal id has to be set") => {}
                        Err(e) => panic!("Unexpected error: {e}"),
                        Ok(_) => panic!("Expected an error but got success"),
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_stake_maturity() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let mut neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(neuron.maturity_e8s_equivalent, 0);

        let new_maturity = 100_000_000;
        neuron.maturity_e8s_equivalent = new_maturity;
        update_neuron(&agent, neuron).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(neuron.maturity_e8s_equivalent, new_maturity);

        // First we try an invalid amount to be staked
        let stake_percentage_invalid = 101;
        assert!(
            env.rosetta_client
                .stake_maturity(
                    env.network_identifier.clone(),
                    &(*TEST_IDENTITY).clone(),
                    RosettaStakeMaturityArgs::builder(neuron_index)
                        .with_percentage_to_stake(stake_percentage_invalid)
                        .build()
                )
                .await
                .is_err()
        );

        // Now we try a valid amount
        let stake_percentage = 50;
        env.rosetta_client
            .stake_maturity(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaStakeMaturityArgs::builder(neuron_index)
                    .with_percentage_to_stake(stake_percentage)
                    .build(),
            )
            .await
            .unwrap();

        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(
            neuron.maturity_e8s_equivalent,
            new_maturity * stake_percentage as u64 / 100
        );

        // Now we try without specifying the stake
        env.rosetta_client
            .stake_maturity(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaStakeMaturityArgs::builder(neuron_index).build(),
            )
            .await
            .unwrap();

        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(neuron.maturity_e8s_equivalent, 0);
        assert_eq!(neuron.staked_maturity_e8s_equivalent.unwrap(), new_maturity);
    });
}

#[test]
fn test_spawn_neuron() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(basic_identity_strategy().no_shrink()),
            |controller_identity| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let env = RosettaTestingEnvironment::builder()
                        .with_initial_balances(
                            vec![(
                                AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                                // A hundred million ICP should be enough
                                icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                            )]
                            .into_iter()
                            .collect(),
                        )
                        .with_governance_canister()
                        .build()
                        .await;

                    // Stake the minimum amount 100 million e8s
                    let staked_amount = 100_000_000u64;
                    let neuron_index = 0;

                    env.rosetta_client
                        .create_neuron(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaCreateNeuronArgs::builder(staked_amount.into())
                                .with_neuron_index(neuron_index)
                                .build(),
                        )
                        .await
                        .unwrap();

                    // See if the neuron was created successfully
                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
                    let mut neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
                    assert_eq!(neuron.maturity_e8s_equivalent, 0);

                    let new_maturity = 100_000_000_000;
                    neuron.maturity_e8s_equivalent = new_maturity;
                    update_neuron(&agent, neuron).await;

                    let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
                    assert_eq!(neuron.maturity_e8s_equivalent, new_maturity);

                    let spawned_neuron_index = 1;
                    let invalid_percentage_to_spawn = 101;
                    assert!(env.rosetta_client
                        .spawn_neuron(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaSpawnNeuronArgs::builder(neuron_index, spawned_neuron_index)
                                .with_controller_principal_id(
                                    controller_identity.sender().unwrap().into(),
                                )
                                .with_percentage_to_spawn(invalid_percentage_to_spawn)
                                .build(),
                        )
                        .await
                        .is_err());

                    let percentage_to_spawn = 50;
                    env.rosetta_client
                        .spawn_neuron(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaSpawnNeuronArgs::builder(neuron_index, spawned_neuron_index)
                                .with_controller_principal_id(
                                    controller_identity.sender().unwrap().into(),
                                )
                                .with_percentage_to_spawn(percentage_to_spawn)
                                .build(),
                        )
                        .await
                        .unwrap();

                    let controller_identity = Arc::new(controller_identity);
                    let controller_agent = get_custom_agent(
                        controller_identity.clone(),
                        env.pocket_ic.url().unwrap().port().unwrap(),
                    )
                    .await;

                    let neurons = list_neurons(&controller_agent).await.full_neurons;
                    assert_eq!(neurons.len(), 1);
                    assert_eq!(
                        neurons.first().unwrap().controller.unwrap().0,
                        controller_identity.sender().unwrap()
                    );
                    assert_eq!(
                        neurons.first().unwrap().maturity_e8s_equivalent,
                        new_maturity * percentage_to_spawn as u64 / 100, "Neuron stake should be 50% of the original neuron stake, but is instead: {:?}", neurons.first().unwrap()
                    );

                    let neuron_info = NeuronResponse::try_from(
                        TransactionOperationResults::try_from(
                            env.rosetta_client
                                .get_neuron_info(
                                    env.network_identifier.clone(),
                                    RosettaNeuronInfoArgs::builder(spawned_neuron_index)
                                        .with_principal_id(controller_identity.sender().unwrap().into())
                                        .build(),
                                    &controller_identity.clone(),
                                )
                                .await
                                .unwrap()
                                .metadata,
                        )
                        .unwrap()
                        .operations
                        .first()
                        .unwrap()
                        .clone()
                        .metadata
                        .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        neurons.first().unwrap().id.unwrap().id,
                        neuron_info.neuron_id
                    );

                    env.rosetta_client.spawn_neuron(
                        env.network_identifier.clone(),
                        &(*TEST_IDENTITY).clone(),
                        RosettaSpawnNeuronArgs::builder(neuron_index, spawned_neuron_index)
                            .with_controller_public_key((&(*TEST_IDENTITY)).into())
                            .with_percentage_to_spawn(percentage_to_spawn)
                            .build(),
                    ).await.unwrap();

                    let neurons = list_neurons(&agent).await.full_neurons;
                    assert_eq!(neurons.len(), 2);
                    assert_eq!(
                        neurons.last().unwrap().controller.unwrap().0,
                        TEST_IDENTITY.sender().unwrap()
                    );
                    assert_eq!(
                        neurons.last().unwrap().maturity_e8s_equivalent,
                        new_maturity * percentage_to_spawn as u64 / 100 /2
                    );
                    let neuron_info = NeuronResponse::try_from(
                        TransactionOperationResults::try_from(
                            env.rosetta_client
                                .get_neuron_info(
                                    env.network_identifier.clone(),
                                    RosettaNeuronInfoArgs::builder(spawned_neuron_index)
                                        .with_public_key((&Arc::new(test_identity())).into())
                                        .build(),
                                    &(*TEST_IDENTITY).clone(),
                                )
                                .await
                                .unwrap()
                                .metadata,
                        )
                        .unwrap()
                        .operations
                        .first()
                        .unwrap()
                        .clone()
                        .metadata
                        .unwrap(),
                    )
                    .unwrap();
                    assert!(
                        neurons.iter().any(|n| n.id.unwrap().id == neuron_info.neuron_id),
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_list_neurons() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_governance_canister()
            .build()
            .await;

        // The user should not yet have any neurons
        let list_neurons_response = ListNeuronsResponse::try_from(
            TransactionOperationResults::try_from(
                env.rosetta_client
                    .list_neurons(env.network_identifier.clone(), &(*TEST_IDENTITY).clone())
                    .await
                    .unwrap()
                    .metadata,
            )
            .unwrap()
            .operations
            .first()
            .unwrap()
            .clone()
            .metadata,
        )
        .unwrap()
        .0;
        assert_eq!(list_neurons_response.full_neurons.len(), 0);

        // Stake the minimum amount 100 million e8s
        let staked_amount = 100_000_000u64;
        let neuron_index = 0;
        let from_subaccount = [0; 32];

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_from_subaccount(from_subaccount)
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let neurons_governance = list_neurons(&agent).await.full_neurons;

        let neurons_rosetta = ListNeuronsResponse::try_from(
            TransactionOperationResults::try_from(
                env.rosetta_client
                    .list_neurons(env.network_identifier.clone(), &(*TEST_IDENTITY).clone())
                    .await
                    .unwrap()
                    .metadata,
            )
            .unwrap()
            .operations
            .first()
            .unwrap()
            .clone()
            .metadata,
        )
        .unwrap()
        .0
        .full_neurons;
        assert_eq!(neurons_governance.len(), 1);
        assert_eq!(neurons_rosetta.len(), 1);
        assert_eq!(
            neurons_governance.first().unwrap().id,
            neurons_rosetta.first().unwrap().id
        );
    });
}

#[test]
fn test_refresh_voting_power() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(basic_identity_strategy().no_shrink()),
            |hot_key_identity| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let env = RosettaTestingEnvironment::builder()
                        .with_initial_balances(
                            vec![(
                                AccountIdentifier::from(TEST_IDENTITY.sender().unwrap()),
                                // A hundred million ICP should be enough
                                icp_ledger::Tokens::from_tokens(100_000_000).unwrap(),
                            )]
                            .into_iter()
                            .collect(),
                        )
                        .with_governance_canister()
                        .build()
                        .await;

                    // Stake the minimum amount 100 million e8s
                    let staked_amount = 100_000_000u64;
                    let neuron_index = 0;
                    let from_subaccount = [0; 32];

                    env.rosetta_client
                        .create_neuron(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaCreateNeuronArgs::builder(staked_amount.into())
                                .with_from_subaccount(from_subaccount)
                                .with_neuron_index(neuron_index)
                                .build(),
                        )
                        .await
                        .unwrap();

                    // Add a hot key to the neuron
                    env.rosetta_client
                        .add_hot_key(
                            env.network_identifier.clone(),
                            &(*TEST_IDENTITY).clone(),
                            RosettaHotKeyArgs::builder(neuron_index)
                                .with_principal_id(hot_key_identity.sender().unwrap().into())
                                .build(),
                        )
                        .await
                        .unwrap();

                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;

                    // Test with hot key identity.
                    let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
                    let refresh_timestamp =
                        neuron.voting_power_refreshed_timestamp_seconds.unwrap();

                    // Wait for a second before updating the voting power. This is done so the timestamp is sure to have a different value when refreshed
                    sleep(std::time::Duration::from_secs(1)).await;

                    let hotkey_caller_identity = Arc::new(hot_key_identity);
                    TransactionOperationResults::try_from(
                        env.rosetta_client
                            .refresh_voting_power(
                                env.network_identifier.clone(),
                                &hotkey_caller_identity.clone(),
                                neuron_index,
                                (*TEST_IDENTITY).clone().generate_principal_id().ok(),
                            )
                            .await
                            .unwrap()
                            .metadata,
                    )
                    .unwrap();

                    let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
                    // The voting power should have been refreshed
                    assert!(
                        neuron.voting_power_refreshed_timestamp_seconds.unwrap()
                            > refresh_timestamp
                    );

                    // Test with neuron owner's identity, without specifying a controller.
                    let refresh_timestamp =
                        neuron.voting_power_refreshed_timestamp_seconds.unwrap();

                    // Wait for a second before updating the voting power. This is done so the timestamp is sure to have a different value when refreshed
                    sleep(std::time::Duration::from_secs(1)).await;
                    TransactionOperationResults::try_from(
                        env.rosetta_client
                            .refresh_voting_power(
                                env.network_identifier.clone(),
                                &(*TEST_IDENTITY).clone(),
                                neuron_index,
                                /*controller=*/ None,
                            )
                            .await
                            .unwrap()
                            .metadata,
                    )
                    .unwrap();

                    let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
                    // The voting power should have been refreshed
                    assert!(
                        neuron.voting_power_refreshed_timestamp_seconds.unwrap()
                            > refresh_timestamp
                    );
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_disburse_maturity() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let test_identity_acc_id = AccountIdentifier::from(TEST_IDENTITY.sender().unwrap());
        let env = RosettaTestingEnvironment::builder()
            .with_initial_balances(
                vec![(
                    test_identity_acc_id,
                    // A hundred million ICP should be enough
                    icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .with_minting_account(Account {
                owner: ic_nns_constants::GOVERNANCE_CANISTER_ID.into(),
                subaccount: None,
            })
            .with_governance_canister()
            .with_cached_maturity_modulation()
            .build()
            .await;

        let staked_amount = 1_000_000_000u64;
        let neuron_index = 0;

        env.rosetta_client
            .create_neuron(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaCreateNeuronArgs::builder(staked_amount.into())
                    .with_neuron_index(neuron_index)
                    .build(),
            )
            .await
            .unwrap();

        // See if the neuron was created successfully
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let mut neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(neuron.maturity_e8s_equivalent, 0);

        // Assing maturity to the neuron
        let new_maturity = 300_000_000;
        neuron.maturity_e8s_equivalent = new_maturity;
        update_neuron(&agent, neuron).await;
        let neuron = list_neurons(&agent).await.full_neurons[0].to_owned();
        assert_eq!(neuron.maturity_e8s_equivalent, new_maturity);

        let receiver = AccountIdentifier::new(PrincipalId::new_user_test_id(100), None);

        let test_id_balance_before = account_balance(&env.pocket_ic, &test_identity_acc_id)
            .await
            .get_e8s();

        let _ = env
            .rosetta_client
            .disburse_maturity(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaDisburseMaturityArgs::builder(neuron_index, 50)
                    .with_recipient(receiver)
                    .build(),
            )
            .await
            .expect("failed to disburse maturity");

        // Disburse the rest to the test id - without specifying the recipient.
        let _ = env
            .rosetta_client
            .disburse_maturity(
                env.network_identifier.clone(),
                &(*TEST_IDENTITY).clone(),
                RosettaDisburseMaturityArgs::builder(neuron_index, 100).build(),
            )
            .await
            .expect("failed to disburse maturity");

        // Wait a week for the disbursement to finalize.
        env.pocket_ic
            .advance_time(std::time::Duration::from_secs(60 * 60 * 24 * 7))
            .await;
        for _ in 0..10 {
            // We have to tick a few more times so that inter canister calls get completed.
            env.pocket_ic
                .advance_time(std::time::Duration::from_secs(1))
                .await;
            env.pocket_ic.tick().await;
        }

        let receiver_balance_after = account_balance(&env.pocket_ic, &receiver).await;
        assert_eq!(receiver_balance_after.get_e8s(), new_maturity / 2);

        let test_id_balance_after = account_balance(&env.pocket_ic, &test_identity_acc_id)
            .await
            .get_e8s();
        assert_eq!(
            test_id_balance_after,
            test_id_balance_before + new_maturity / 2
        );
    });
}
