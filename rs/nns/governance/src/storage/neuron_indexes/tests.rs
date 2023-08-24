use super::*;

use crate::pb::v1::{neuron::Followees, KnownNeuronData};

use ic_nervous_system_governance::index::{
    neuron_following::NeuronFollowingIndex, neuron_principal::NeuronPrincipalIndex,
};
use ic_nns_common::pb::v1::NeuronId;
use maplit::{hashmap, hashset};

#[test]
fn add_one_neuron() {
    let mut indexes = new_heap_based();

    let neuron = Neuron {
        id: Some(NeuronId { id: 1 }),
        account: [1u8; 32].to_vec(),
        controller: Some(PrincipalId::new_user_test_id(1)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ],
        followees: hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
        },
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),
        ..Default::default()
    };

    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap()),
        None
    );

    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1)),
        hashset! {}
    );

    assert_eq!(
        indexes
            .following()
            .get_followers_by_followee_and_category(&2, Signed32::from(1)),
        Vec::<u64>::default()
    );

    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);

    assert_eq!(indexes.add_neuron(&neuron), Ok(()));

    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap()),
        Some(NeuronId { id: 1 })
    );

    for principal_num in 1..=3 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(principal_num)),
            hashset! { 1 }
        );
    }

    for followee_id in 2..=4 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&followee_id, Signed32::from(1)),
            vec![1]
        );
    }

    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![NeuronId { id: 1 }]
    );
}
