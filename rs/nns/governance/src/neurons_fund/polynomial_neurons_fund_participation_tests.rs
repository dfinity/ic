use super::*;
use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::{E8, WIDE_RANGE_OF_U64_VALUES};

fn nid(id: u64) -> NeuronId {
    NeuronId { id }
}

fn get_swap_participation_limits_for_tests() -> impl Iterator<Item = SwapParticipationLimits> {
    vec![
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 0,
            max_direct_participation_icp_e8s: 0,
            min_participant_icp_e8s: 0,
            max_participant_icp_e8s: 0,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 0,
            max_direct_participation_icp_e8s: 200_000 * E8,
            min_participant_icp_e8s: 0,
            max_participant_icp_e8s: E8,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 200_000 * E8,
            max_direct_participation_icp_e8s: 200_000 * E8,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: E8,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 200_000 * E8,
            max_direct_participation_icp_e8s: 500_000 * E8,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 50_000 * E8,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 500_000 * E8,
            max_direct_participation_icp_e8s: 500_000 * E8,
            min_participant_icp_e8s: 50_000 * E8,
            max_participant_icp_e8s: 50_000 * E8,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 500_000 * E8,
            max_direct_participation_icp_e8s: u64::MAX,
            min_participant_icp_e8s: 50_000 * E8,
            max_participant_icp_e8s: u64::MAX,
        },
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 0,
            max_direct_participation_icp_e8s: u64::MAX,
            min_participant_icp_e8s: 0,
            max_participant_icp_e8s: u64::MAX,
        },
    ]
    .into_iter()
}

fn get_neuron_sets_for_tests() -> impl Iterator<Item = Vec<NeuronsFundNeuron>> {
    let controller = PrincipalId::default();
    let hotkeys = Vec::new();
    vec![
        // No neurons.
        vec![],
        // Single neuron with zero maturity.
        vec![NeuronsFundNeuron {
            id: nid(1000),
            maturity_equivalent_icp_e8s: 0,
            controller,
            hotkeys: hotkeys.clone(),
        }],
        // Single neuron with maximal possible maturity.
        vec![NeuronsFundNeuron {
            id: nid(1000),
            maturity_equivalent_icp_e8s: u64::MAX,
            controller,
            hotkeys: hotkeys.clone(),
        }],
        // Two equi-mature neurons with super huge maturity.
        vec![
            NeuronsFundNeuron {
                id: nid(1000),
                maturity_equivalent_icp_e8s: u64::MAX / 2,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(1),
                maturity_equivalent_icp_e8s: u64::MAX / 2,
                controller,
                hotkeys: hotkeys.clone(),
            },
        ],
        // Two neurons, both with super huge maturity, but one has 1 e8 more than the other.
        vec![
            NeuronsFundNeuron {
                id: nid(1000),
                maturity_equivalent_icp_e8s: u64::MAX / 2,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(1),
                maturity_equivalent_icp_e8s: u64::MAX - (u64::MAX / 2),
                controller,
                hotkeys: hotkeys.clone(),
            },
        ],
        // The sum of the maturities in this set of neurons is `u64::MAX`.
        // If this scenario completes successfully, then we have demonstrated
        // that an overflow is unlikely to be an issue with our implementation.
        (0..64)
            .map(|i: u8| NeuronsFundNeuron {
                id: nid(i as u64),
                maturity_equivalent_icp_e8s: 2_u64.pow(i as u32),
                controller,
                hotkeys: hotkeys.clone(),
            })
            .collect::<Vec<_>>(),
        // Neurons with a wide range of maturities, and one neuron with a super huge amount of
        // maturity (but not enough to overflow).
        vec![
            NeuronsFundNeuron {
                id: nid(1000),
                maturity_equivalent_icp_e8s: 0,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(1),
                maturity_equivalent_icp_e8s: 1, // no `* E8` on purpose
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(2),
                maturity_equivalent_icp_e8s: 10 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(3),
                maturity_equivalent_icp_e8s: 25 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(4),
                maturity_equivalent_icp_e8s: 50 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(5),
                maturity_equivalent_icp_e8s: 100 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(6),
                maturity_equivalent_icp_e8s: 250 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(7),
                maturity_equivalent_icp_e8s: 500 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(8),
                maturity_equivalent_icp_e8s: 1000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(9),
                maturity_equivalent_icp_e8s: 2500 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(10),
                maturity_equivalent_icp_e8s: 5000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(11),
                maturity_equivalent_icp_e8s: 5000 * E8, // Same as for nid(10) on purpose
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(12),
                maturity_equivalent_icp_e8s: 10_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(13),
                maturity_equivalent_icp_e8s: 25_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(14),
                maturity_equivalent_icp_e8s: 50_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(15),
                maturity_equivalent_icp_e8s: 100_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(16),
                maturity_equivalent_icp_e8s: 250_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(17),
                maturity_equivalent_icp_e8s: 500_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(18),
                maturity_equivalent_icp_e8s: 1_000_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(19),
                maturity_equivalent_icp_e8s: 2_500_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(20),
                maturity_equivalent_icp_e8s: 5_000_000 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            },
            NeuronsFundNeuron {
                id: nid(21),
                maturity_equivalent_icp_e8s: u64::MAX / 2, // Ensure the Fund's total still fits u64.
                controller,
                hotkeys: hotkeys.clone(),
            },
        ],
        // 1K neurons with 1 ICP of maturity each, and another 1k with 100 ICP of maturity each.
        // (All with the same controller, as that shouldn't matter for the Neurons' Fund.)
        (0..1_000)
            .map(|i: u64| NeuronsFundNeuron {
                id: nid(i),
                maturity_equivalent_icp_e8s: E8,
                controller,
                hotkeys: hotkeys.clone(),
            })
            .chain((1_000..2_000).map(|i: u64| NeuronsFundNeuron {
                id: nid(i),
                maturity_equivalent_icp_e8s: 100 * E8,
                controller,
                hotkeys: hotkeys.clone(),
            }))
            .collect::<Vec<_>>(),
    ]
    .into_iter()
}

#[track_caller]
fn assert_remainder_plus_refund_equals_initial_maturity(
    initial_neuron_portions: &NeuronsFundSnapshot,
    final_neuron_portions: &NeuronsFundSnapshot,
    refunded_neuron_portions: &NeuronsFundSnapshot,
) {
    for (nns_neuron_id, initial_neruon_portion) in initial_neuron_portions.neurons() {
        let initial_amount_icp_e8s = initial_neruon_portion.amount_icp_e8s;
        let final_amount_icp_e8s = final_neuron_portions
            .neurons()
            .get(nns_neuron_id)
            .map(|neuron_portion| neuron_portion.amount_icp_e8s)
            .unwrap_or(0);
        let refunded_amount_icp_e8s = refunded_neuron_portions
            .neurons()
            .get(nns_neuron_id)
            .map(|neuron_portion| neuron_portion.amount_icp_e8s)
            .unwrap_or(0);
        assert_eq!(
            initial_amount_icp_e8s,
            final_amount_icp_e8s + refunded_amount_icp_e8s
        );
    }
}

fn run_test(neurons_fund_participation_limits: NeuronsFundParticipationLimits) {
    for neurons in get_neuron_sets_for_tests() {
        for swap_participation_limits in get_swap_participation_limits_for_tests() {
            let initial_participation_fn =
                || -> Result<PolynomialNeuronsFundParticipation, String> {
                    let swap_participation_limits = swap_participation_limits.clone();
                    let neurons = neurons.clone();
                    let initial_participation = PolynomialNeuronsFundParticipation::new(
                        neurons_fund_participation_limits,
                        swap_participation_limits,
                        neurons,
                    )
                    .unwrap();
                    NeuronsFundParticipationPb::from(initial_participation)
                        .validate()
                        .map_err(|err| err.to_string())
                };
            let initial_participation: NeuronsFundParticipation<_> =
                initial_participation_fn().unwrap();
            let initial_participation_clone = initial_participation_fn().unwrap();
            let initial_neuron_portions = initial_participation_fn().unwrap().into_snapshot();
            for direct_participation_icp_e8s in &*WIDE_RANGE_OF_U64_VALUES {
                let direct_participation_icp_e8s = *direct_participation_icp_e8s;

                let final_participation = initial_participation_clone
                    .from_initial_participation(direct_participation_icp_e8s)
                    .unwrap();
                // Test individual fields that can be specified via `initial_participation`.
                assert_eq!(
                    final_participation.swap_participation_limits,
                    initial_participation.swap_participation_limits,
                );
                assert_eq!(
                    final_participation.ideal_matched_participation_function,
                    initial_participation.ideal_matched_participation_function,
                );
                assert_eq!(
                    final_participation.direct_participation_icp_e8s,
                    direct_participation_icp_e8s,
                );
                assert_eq!(
                    final_participation.max_neurons_fund_swap_participation_icp_e8s,
                    initial_participation.max_neurons_fund_swap_participation_icp_e8s,
                );
                // Test that the underlying Neurons' Fund snapshot is correctly computed.
                {
                    let final_neuron_portions = final_participation.neurons_fund_reserves.clone();
                    let refunded_neuron_portions = initial_neuron_portions
                        .clone()
                        .diff(&final_neuron_portions)
                        .unwrap();
                    if final_neuron_portions.is_empty() {
                        assert_eq!(
                            refunded_neuron_portions.num_neurons(),
                            initial_neuron_portions.num_neurons(),
                            "\ninitial_neuron_portions = {initial_neuron_portions:#?}\nrefunded_neuron_portions = {refunded_neuron_portions:#?}"
                        );
                    } else {
                        assert!(
                            final_neuron_portions.num_neurons()
                                <= initial_neuron_portions.num_neurons()
                        );
                    }
                    if refunded_neuron_portions.is_empty() {
                        assert_eq!(
                            final_neuron_portions.num_neurons(),
                            initial_neuron_portions.num_neurons()
                        );
                    } else {
                        assert!(
                            refunded_neuron_portions.num_neurons()
                                <= initial_neuron_portions.num_neurons()
                        );
                    }
                    // (1) The union of neurons in final and refunded = the neurons in initial,
                    // but (2) final_neuron_portions and refunded_neuron_portions can overlap.
                    assert!(
                        initial_neuron_portions.num_neurons()
                            <= final_neuron_portions.num_neurons()
                                + refunded_neuron_portions.num_neurons(),
                    );
                    assert_remainder_plus_refund_equals_initial_maturity(
                        &initial_neuron_portions,
                        &final_neuron_portions,
                        &refunded_neuron_portions,
                    );
                }
                // The the overall `final_participation` is a valid NeuronsFundParticipation structure.
                assert_matches!(
                    NeuronsFundParticipationPb::from(final_participation).validate(),
                    Ok(_)
                );
            }
        }
    }
}

fn get_neurons_fund_participation_limits_for_tests(
    xdr_icp_rate: Decimal,
) -> NeuronsFundParticipationLimits {
    let network_economics = NeuronsFundEconomicsPb::with_default_values();

    Governance::try_derive_neurons_fund_participation_limits_impl(&network_economics, xdr_icp_rate)
        .unwrap()
}

#[test]
fn test_with_xdr_icp_rate_1() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(1.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_2() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(2.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_5() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(5.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_10() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(10.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_20() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(20.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_50() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(50.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_xdr_icp_rate_100() {
    let neurons_fund_participation_limits =
        get_neurons_fund_participation_limits_for_tests(dec!(100.0));
    run_test(neurons_fund_participation_limits);
}

#[test]
fn test_with_old_values() {
    // These values were used before XDR-based limits were introduced for the Neurons' Fund.
    let neurons_fund_participation_limits = NeuronsFundParticipationLimits {
        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
        contribution_threshold_icp: dec!(33_000.0),
        one_third_participation_milestone_icp: dec!(100_000.0),
        full_participation_milestone_icp: dec!(167_000.0),
    };
    run_test(neurons_fund_participation_limits);
}
