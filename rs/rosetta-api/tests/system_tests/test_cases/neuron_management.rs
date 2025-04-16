use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::{get_test_agent, list_neurons, test_identity};
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaCreateNeuronArgs;
use ic_types::PrincipalId;
use icp_ledger::AccountIdentifier;
use lazy_static::lazy_static;
use std::sync::Arc;
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
                (*TEST_IDENTITY).clone(),
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
