use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::{get_test_agent, list_neurons, test_identity};
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaCreateNeuronArgs;
use ic_icp_rosetta_client::RosettaSetNeuronDissolveDelayArgs;
use ic_nns_governance::pb::v1::neuron::DissolveState;
use ic_types::PrincipalId;
use icp_ledger::AccountIdentifier;
use lazy_static::lazy_static;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_IDENTITY: Arc<BasicIdentity> = Arc::new(test_identity());
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
            // When a neuron is created its dissolve delay timestamp is set to now which corresponds to the state DISSOLVED
            DissolveState::WhenDissolvedTimestampSeconds(dissolve_delay_timestamp) => {
                dissolve_delay_timestamp
            }
            k => panic!(
                "Neuron should be in WhenDissolvedTimestampSeconds state, but is instead: {:?}",
                k
            ),
        };

        // We can't know the exact timestamp of the dissolve delay, but we can assert that it is in the past or now
        assert!(
            dissolve_delay_timestamp
                <= env
                    .pocket_ic
                    .get_time()
                    .await
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
        let additional_dissolve_delay = 1000;
        let new_dissolve_delay_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + additional_dissolve_delay;

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
            k => panic!(
                "Neuron should be in DissolveDelaySeconds state, but is instead: {:?}",
                k
            ),
        };
        // The Dissolve Delay Timestamp should be updated
        // Since the state machine is live we do not know exactly how much time will be left at the time of calling the governance canister.
        // It should be between dissolve_delay_timestamp and dissolve_delay_timestamp - X seconds depending on how long it takes to call the governance canister
        assert!(dissolve_delay_timestamp <= additional_dissolve_delay);
        assert!(dissolve_delay_timestamp > 0);
    });
}
