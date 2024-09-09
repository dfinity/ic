use crate::{
    neurons_fund::*,
    pb::v1::{
        neurons_fund_snapshot::NeuronsFundNeuronPortion as NeuronsFundNeuronPortionPb,
        IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionPb,
        NeuronsFundParticipation as NeuronsFundParticipationPb,
        NeuronsFundSnapshot as NeuronsFundSnapshotPb,
        SwapParticipationLimits as SwapParticipationLimitsPb,
    },
};
use ic_base_types::PrincipalId;
use ic_neurons_fund::{PolynomialMatchingFunction, SerializableFunction};
use ic_nns_common::pb::v1::NeuronId;

#[test]
fn test_neurons_fund_participation_anonymization() {
    let id1 = NeuronId { id: 123 };
    let id2 = NeuronId { id: 456 };
    let amount_icp_e8s = 100_000_000_000;
    let maturity_equivalent_icp_e8s = 100_000_000_000;
    let controller = PrincipalId::default();
    let is_capped = false;
    let n1: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
        nns_neuron_id: Some(id1),
        amount_icp_e8s: Some(amount_icp_e8s),
        maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
        controller: Some(controller),
        hotkeys: vec![],
        is_capped: Some(is_capped),
    };
    let n2 = NeuronsFundNeuronPortionPb {
        nns_neuron_id: Some(id2),
        ..n1.clone()
    };
    let neurons = vec![n1, n2];
    let snapshot = NeuronsFundSnapshotPb {
        neurons_fund_neuron_portions: neurons,
    };
    let participation = NeuronsFundParticipationPb {
        ideal_matched_participation_function: Some(IdealMatchedParticipationFunctionPb {
            serialized_representation: Some(
                PolynomialMatchingFunction::new(
                    1_000_000_000_000_000,
                    NeuronsFundParticipationLimits {
                        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
                        contribution_threshold_icp: dec!(33_000.0),
                        one_third_participation_milestone_icp: dec!(100_000.0),
                        full_participation_milestone_icp: dec!(167_000.0),
                    },
                )
                .unwrap()
                .serialize(),
            ),
        }),
        neurons_fund_reserves: Some(snapshot.clone()),
        swap_participation_limits: Some(SwapParticipationLimitsPb {
            min_direct_participation_icp_e8s: Some(0),
            max_direct_participation_icp_e8s: Some(u64::MAX),
            min_participant_icp_e8s: Some(1_000_000_000),
            max_participant_icp_e8s: Some(10_000_000_000),
        }),
        direct_participation_icp_e8s: Some(1_000_000_000_000),
        total_maturity_equivalent_icp_e8s: Some(1_000_000_000_000_000),
        max_neurons_fund_swap_participation_icp_e8s: Some(1_000_000_000_000),
        intended_neurons_fund_participation_icp_e8s: Some(1_000_000_000_000),
        allocated_neurons_fund_participation_icp_e8s: Some(2 * amount_icp_e8s),
    };
    let participation_validation_result = participation.validate();
    assert!(
        participation_validation_result.is_ok(),
        "expected Ok result, got {:#?}",
        participation_validation_result
    );
    let anonymized_participation = participation.anonymized();
    assert_eq!(
        anonymized_participation.validate().map(|_| ()),
        Err(
            NeuronsFundParticipationValidationError::NeuronsFundSnapshotValidationError(
                NeuronsFundSnapshotValidationError::NeuronsFundNeuronPortionError(
                    0,
                    NeuronsFundNeuronPortionError::UnspecifiedField("nns_neuron_id".to_string())
                )
            )
        )
    );
    assert_eq!(
        anonymized_participation,
        NeuronsFundParticipationPb {
            neurons_fund_reserves: Some(snapshot.anonymized()),
            ..participation
        }
    );
}

#[test]
fn test_neurons_fund_snapshot_anonymization() {
    let id1 = NeuronId { id: 123 };
    let id2 = NeuronId { id: 456 };
    let amount_icp_e8s = 100_000_000_000;
    let maturity_equivalent_icp_e8s = 100_000_000_000;
    let controller = PrincipalId::default();
    let is_capped = false;
    let n1: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
        nns_neuron_id: Some(id1),
        amount_icp_e8s: Some(amount_icp_e8s),
        maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
        controller: Some(controller),
        hotkeys: vec![],
        is_capped: Some(is_capped),
    };
    let n2 = NeuronsFundNeuronPortionPb {
        nns_neuron_id: Some(id2),
        ..n1.clone()
    };
    let neurons = vec![n1, n2];
    let snapshot = NeuronsFundSnapshotPb {
        neurons_fund_neuron_portions: neurons.clone(),
    };
    assert_eq!(
        snapshot.validate(),
        Ok(NeuronsFundSnapshot {
            neurons: neurons
                .iter()
                .map(|n| { (n.nns_neuron_id.unwrap(), n.validate().unwrap()) })
                .collect()
        })
    );
    let anonymized_snapshot = snapshot.anonymized();
    assert_eq!(
        anonymized_snapshot.validate(),
        Err(
            NeuronsFundSnapshotValidationError::NeuronsFundNeuronPortionError(
                0,
                NeuronsFundNeuronPortionError::UnspecifiedField("nns_neuron_id".to_string())
            )
        )
    );
    assert_eq!(
        anonymized_snapshot,
        NeuronsFundSnapshotPb {
            neurons_fund_neuron_portions: neurons.into_iter().map(|n| { n.anonymized() }).collect()
        }
    );
}

#[test]
fn test_neurons_fund_neuron_portion_anonymization() {
    let id = NeuronId { id: 123 };
    let amount_icp_e8s = 100_000_000_000;
    let maturity_equivalent_icp_e8s = 100_000_000_000;
    let controller = PrincipalId::default();
    let hotkeys = Vec::new();
    let is_capped = false;

    let neuron: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
        nns_neuron_id: Some(id),
        amount_icp_e8s: Some(amount_icp_e8s),
        maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
        controller: Some(controller),
        hotkeys: vec![],
        is_capped: Some(is_capped),
    };
    assert_eq!(
        neuron.validate(),
        Ok(NeuronsFundNeuronPortion {
            id,
            amount_icp_e8s,
            maturity_equivalent_icp_e8s,
            controller,
            hotkeys,
            is_capped,
        })
    );
    let anonymized_neuron = neuron.anonymized();
    assert_eq!(
        anonymized_neuron.validate(),
        Err(NeuronsFundNeuronPortionError::UnspecifiedField(
            "nns_neuron_id".to_string()
        ))
    );
    assert_eq!(
        anonymized_neuron,
        NeuronsFundNeuronPortionPb {
            nns_neuron_id: None,
            ..neuron
        }
    );
}
