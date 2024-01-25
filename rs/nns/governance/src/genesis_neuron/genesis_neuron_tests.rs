// TODO(NNS1-2819): Remove file after deployment
use crate::{
    governance::Governance,
    pb::v1::{
        governance::{genesis_neuron_accounts::GenesisNeuronAccount, GenesisNeuronAccounts},
        Neuron,
    },
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Subaccount};

fn make_dummy_neuron(
    neuron_id: NeuronId,
    subaccount: Subaccount,
    amount: u64,
    controller: PrincipalId,
) -> Neuron {
    Neuron {
        id: Some(neuron_id),
        account: subaccount.0.to_vec(),
        controller: Some(controller),
        hot_keys: vec![],
        cached_neuron_stake_e8s: amount,
        ..Default::default()
    }
}

#[test]
fn test_that_if_amounts_are_sufficient_only_specified_neurons_are_tagged() {
    let controller_a = PrincipalId::new_user_test_id(100);
    let controller_b = PrincipalId::new_user_test_id(101);
    let controller_c = PrincipalId::new_user_test_id(102);

    let neuron_a1_subaccount = Subaccount([1; 32]);
    let neuron_a1 = make_dummy_neuron(NeuronId { id: 1 }, neuron_a1_subaccount, 100, controller_a);
    let neuron_a2_subaccount = Subaccount([2; 32]);
    let neuron_a2 = make_dummy_neuron(NeuronId { id: 2 }, neuron_a2_subaccount, 100, controller_a);

    let neuron_b1_subaccount = Subaccount([3; 32]);
    let neuron_b1 = make_dummy_neuron(NeuronId { id: 3 }, neuron_b1_subaccount, 100, controller_b);
    let neuron_b2_subaccount = Subaccount([4; 32]);
    let neuron_b2 = make_dummy_neuron(NeuronId { id: 4 }, neuron_b2_subaccount, 100, controller_b);

    let neuron_c1_subaccount = Subaccount([5; 32]);
    let neuron_c1 = make_dummy_neuron(NeuronId { id: 5 }, neuron_c1_subaccount, 99, controller_c);
    let neuron_c2_subaccount = Subaccount([6; 32]);
    let neuron_c2 = make_dummy_neuron(NeuronId { id: 6 }, neuron_c2_subaccount, 100, controller_c);
    let neuron_c3_subaccount = Subaccount([7; 32]);
    let neuron_c3 = make_dummy_neuron(NeuronId { id: 7 }, neuron_c3_subaccount, 100, controller_c);

    let neurons = vec![
        neuron_a1, neuron_a2, neuron_b1, neuron_b2, neuron_c1, neuron_c2, neuron_c3,
    ]
    .into_iter()
    .map(|n| (n.id.as_ref().unwrap().id, n))
    .collect::<std::collections::BTreeMap<_, _>>();

    let genesis_neuron_accounts = Some(GenesisNeuronAccounts {
        genesis_neuron_accounts: vec![
            GenesisNeuronAccount {
                account_ids: vec![AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    Some(neuron_a1_subaccount),
                )
                .to_hex()],
                tag_start_timestamp_seconds: None,
                tag_end_timestamp_seconds: None,
                error_count: 0,
                neuron_type: 1, //Seed
                amount_icp_e8s: 100,
                id: 1,
            },
            GenesisNeuronAccount {
                account_ids: vec![AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    Some(neuron_b1_subaccount),
                )
                .to_hex()],
                tag_start_timestamp_seconds: None,
                tag_end_timestamp_seconds: None,
                error_count: 0,
                neuron_type: 2, //ECT
                amount_icp_e8s: 100,
                id: 2,
            },
            GenesisNeuronAccount {
                account_ids: vec![AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    Some(neuron_c1_subaccount),
                )
                .to_hex()],
                tag_start_timestamp_seconds: None,
                tag_end_timestamp_seconds: None,
                error_count: 0,
                neuron_type: 1, //Seed
                amount_icp_e8s: 100,
                id: 3,
            },
        ],
    });

    // We use new, then new_restored so that indexes populate as expected
    let mut governance = Governance::new(
        crate::pb::v1::Governance {
            neurons,
            ..Default::default()
        },
        Box::new(MockEnvironment::new(vec![], 0)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );
    // We do not yet have the data structure, so we can't tag
    assert!(!governance.some_genesis_neurons_are_untagged());

    // Add genesis neurons
    let proto = governance.take_heap_proto();
    let mut governance = Governance::new_restored(
        proto,
        Box::new(MockEnvironment::new(vec![], 0)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
        genesis_neuron_accounts,
    );

    // It tags 1 per round, so we should be able to tag 3 times
    assert!(governance.some_genesis_neurons_are_untagged());
    governance.tag_genesis_neurons();
    assert!(governance.some_genesis_neurons_are_untagged());
    governance.tag_genesis_neurons();
    assert!(governance.some_genesis_neurons_are_untagged());
    governance.tag_genesis_neurons();
    // Can no longer tag
    assert!(!governance.some_genesis_neurons_are_untagged());

    // b/c 1 had enough to account for expected ICP, only 1, and not 2, is claimed
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| { n.neuron_type })
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 2 }, |n| { n.neuron_type })
            .unwrap(),
        None
    );
    // b/c 3 had enough to account for expected ICP, only 3, and not 4, is claimed
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 3 }, |n| { n.neuron_type })
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 4 }, |n| { n.neuron_type })
            .unwrap(),
        None
    );
    // B/c 5 didn't account for all expected ICP, all other neurons are claimed
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 5 }, |n| { n.neuron_type })
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 6 }, |n| { n.neuron_type })
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        governance
            .neuron_store
            .with_neuron(&NeuronId { id: 7 }, |n| { n.neuron_type })
            .unwrap(),
        Some(1)
    );
}
