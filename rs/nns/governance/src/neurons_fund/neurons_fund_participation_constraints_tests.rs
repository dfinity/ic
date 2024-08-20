use super::*;
use assert_matches::assert_matches;
use ic_nervous_system_common::E8;
use ic_neurons_fund::{
    rescale_to_icp, MatchingFunction, SerializableFunction, ValidatedLinearScalingCoefficient,
};
use maplit::{btreemap, btreeset};

fn new_neurons_fund_neuron(id: u64, maturity_equivalent_icp_e8s: u64) -> NeuronsFundNeuron {
    let id = NeuronId { id };
    let controller = PrincipalId::new_user_test_id(55);
    let hotkey1 = PrincipalId::new_user_test_id(56);
    let hotkey2 = PrincipalId::new_user_test_id(57);
    let hotkeys = vec![hotkey1, hotkey2];
    NeuronsFundNeuron {
        id,
        maturity_equivalent_icp_e8s,
        controller,
        hotkeys,
    }
}

// The first digit in the IDs of the following neurons has a positive relationship to
// the amount of maturity. The second digit just lets us have more than one neuron with
// the same maturity, with IDs starting the same digit. Thus, as direct participation
// increases, neurons with smaller IDs have enough maturity such that they can participate
// in Neuron's Fund.
fn new_neurons_fund_neurons() -> Vec<NeuronsFundNeuron> {
    vec![
        new_neurons_fund_neuron(10, E8),
        new_neurons_fund_neuron(20, 2 * E8),
        new_neurons_fund_neuron(30, 3 * E8),
        new_neurons_fund_neuron(40, 4 * E8),
        new_neurons_fund_neuron(50, 20 * E8),
        new_neurons_fund_neuron(61, 35 * E8),
        new_neurons_fund_neuron(62, 35 * E8),
        new_neurons_fund_neuron(70, 100 * E8),
        new_neurons_fund_neuron(80, 800 * E8),
    ]
}

fn test_swap_participation_limits() -> SwapParticipationLimits {
    SwapParticipationLimits {
        min_direct_participation_icp_e8s: 50 * E8,
        max_direct_participation_icp_e8s: 100 * E8,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 4 * E8,
    }
}

#[derive(Debug)]
struct LogisticFunction {
    pub supremum_icp: f64,
    pub steepness_inv_icp: f64,
    pub midpoint_icp: f64,
}

impl MatchingFunction for LogisticFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String> {
        let x_icp = f64::try_from(rescale_to_icp(x_icp_e8s)?)
            .map_err(|err| format!("cannot convert {} to f64: {}", x_icp_e8s, err))?;
        let res_icp = self.supremum_icp
            / (1.0 + (-1.0 * self.steepness_inv_icp * (x_icp - self.midpoint_icp)).exp());
        Decimal::try_from(res_icp).map_err(|err| err.to_string())
    }
}

impl SerializableFunction for LogisticFunction {
    fn serialize(&self) -> String {
        format!("{:?}", self)
    }
}

impl LogisticFunction {
    fn new_test_curve() -> Self {
        Self {
            supremum_icp: 100.0,
            steepness_inv_icp: 0.05,
            midpoint_icp: 100.0,
        }
    }
}

fn test_participation() -> NeuronsFundParticipation<LogisticFunction> {
    NeuronsFundParticipation::new_for_test(
        test_swap_participation_limits(),
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap()
}

#[test]
fn test_diff_with_empty_snapshot() {
    // Test that `{} - {} == {}`.
    assert_eq!(
        NeuronsFundSnapshot::empty().diff(&NeuronsFundSnapshot::empty()),
        Ok(NeuronsFundSnapshot::empty())
    );
    let controller = PrincipalId::default();
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let snapshot = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(2) => NeuronsFundNeuronPortion {
                id: nid(2),
                amount_icp_e8s: 200,
                maturity_equivalent_icp_e8s: 2000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(3) => NeuronsFundNeuronPortion {
                id: nid(3),
                amount_icp_e8s: 300,
                maturity_equivalent_icp_e8s: 9000,
                is_capped: true,
                controller,
                hotkeys: hotkeys.clone(),
            }
        },
    };
    // Test that `snapshot - snapshot == {}`.
    assert_eq!(
        snapshot.clone().diff(&snapshot),
        Ok(NeuronsFundSnapshot::empty())
    );
    // Test that `snapshot - {} == snapshot1`, where `snapshot1` is identical to `snapshot`,
    // except that the `is_capped` field of all of its elements is set to `false`.
    assert_eq!(
        snapshot.clone().diff(&NeuronsFundSnapshot::empty()),
        Ok(NeuronsFundSnapshot {
            neurons: btreemap! {
                nid(1) => NeuronsFundNeuronPortion {
                    id: nid(1),
                    amount_icp_e8s: 100,
                    maturity_equivalent_icp_e8s: 1000,
                    is_capped: false,
                    controller,
                    hotkeys: hotkeys.clone(),
                },
                nid(2) => NeuronsFundNeuronPortion {
                    id: nid(2),
                    amount_icp_e8s: 200,
                    maturity_equivalent_icp_e8s: 2000,
                    is_capped: false,
                    controller,
                    hotkeys: hotkeys.clone(),
                },
                nid(3) => NeuronsFundNeuronPortion {
                    id: nid(3),
                    amount_icp_e8s: 300,
                    maturity_equivalent_icp_e8s: 9000,
                    is_capped: false,
                    controller,
                    hotkeys: hotkeys.clone(),
                }
            },
        })
    );
}

#[test]
fn test_diff_ok_once_then_err() {
    let controller = PrincipalId::default();
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let left = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(2) => NeuronsFundNeuronPortion {
                id: nid(2),
                amount_icp_e8s: 200,
                maturity_equivalent_icp_e8s: 2000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(3) => NeuronsFundNeuronPortion {
                id: nid(3),
                amount_icp_e8s: 300,
                maturity_equivalent_icp_e8s: 9000,
                is_capped: true,
                controller,
                hotkeys: hotkeys.clone(),
            }
        },
    };
    let right = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 80,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(3) => NeuronsFundNeuronPortion {
                id: nid(3),
                amount_icp_e8s: 300,
                maturity_equivalent_icp_e8s: 9000,
                is_capped: true,
                controller,
                hotkeys: hotkeys.clone(),
            }
        },
    };
    let expected_diff = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 20,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(2) => NeuronsFundNeuronPortion {
                id: nid(2),
                amount_icp_e8s: 200,
                maturity_equivalent_icp_e8s: 2000,
                is_capped: false,
                controller,
                hotkeys,
            }
        },
    };
    let diff = assert_matches!(left.diff(&right), Ok(diff) if diff == expected_diff => diff);
    // The `diff` is strict (not idempotent), so the second subtraction should fail.
    assert_eq!(
        diff.diff(&right),
        Err("Cannot compute diff of two Neurons' Fund snapshots:\n  \
            - Cannot compute diff of two portions of neuron NeuronId { id: 1 }: \
            left.amount_icp_e8s=20, right.amount_icp_e8s=80."
            .to_string())
    );
}

#[test]
fn test_diff_extra_neuron_err() {
    let controller = PrincipalId::default();
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let left = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
        },
    };
    let right = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 80,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
            nid(3) => NeuronsFundNeuronPortion {
                id: nid(3),
                amount_icp_e8s: 300,
                maturity_equivalent_icp_e8s: 9000,
                is_capped: true,
                controller,
                hotkeys,
            }
        },
    };
    assert_eq!(
        left.diff(&right),
        Err(format!(
            "Cannot compute diff of two Neurons' Fund snapshots: \
            right-hand side contains 1 extra neuron portions: {:?}",
            nid(3)
        ))
    );
}

#[test]
fn test_diff_negative_amount_in_diff_err() {
    let controller = PrincipalId::default();
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let left = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
        },
    };
    let right = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 180,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys,
            },
        },
    };
    assert_eq!(
        left.diff(&right),
        Err(format!(
            "Cannot compute diff of two Neurons' Fund snapshots:\n  \
            - Cannot compute diff of two portions of neuron {:?}: \
            left.amount_icp_e8s=100, right.amount_icp_e8s=180.",
            nid(1)
        ))
    );
}

#[test]
fn test_diff_controller_err() {
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let left = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller: PrincipalId::new_user_test_id(111),
                hotkeys: hotkeys.clone(),
            },
        },
    };
    let right = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 80,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller: PrincipalId::new_user_test_id(222),
                hotkeys,
            },
        },
    };
    assert_eq!(
        left.diff(&right),
        Err(format!(
            "Cannot compute diff of two Neurons' Fund snapshots:\n  \
              - Cannot compute diff of two portions of neuron {:?}: \
                left.controller={}, \
                right.controller={}.",
            nid(1),
            PrincipalId::new_user_test_id(111),
            PrincipalId::new_user_test_id(222),
        ))
    );
}

#[test]
fn test_diff_maturity_err() {
    let controller = PrincipalId::default();
    let nid = |id: u64| NeuronId { id };
    let hotkeys = Vec::new();
    let left = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 100,
                maturity_equivalent_icp_e8s: 1000,
                is_capped: false,
                controller,
                hotkeys: hotkeys.clone(),
            },
        },
    };
    let right = NeuronsFundSnapshot {
        neurons: btreemap! {
            nid(1) => NeuronsFundNeuronPortion {
                id: nid(1),
                amount_icp_e8s: 80,
                maturity_equivalent_icp_e8s: 1111,
                is_capped: false,
                controller,
                hotkeys,
            },
        },
    };
    assert_eq!(
        left.diff(&right),
        Err(
            "Cannot compute diff of two Neurons' Fund snapshots:\n  - Cannot compute diff \
            of two portions of neuron NeuronId { id: 1 }: \
            left.maturity_equivalent_icp_e8s=1000 != right.maturity_equivalent_icp_e8s=1111."
                .to_string()
        )
    );
}

#[test]
fn test_diff_is_capped() {
    let nid = |id: u64| NeuronId { id };
    let controller = PrincipalId::default();
    let hotkeys = Vec::new();
    let test_with = |is_capped_left: bool, is_capped_right: bool| {
        let left = NeuronsFundSnapshot {
            neurons: btreemap! {
                nid(1) => NeuronsFundNeuronPortion {
                    id: nid(1),
                    amount_icp_e8s: 100,
                    maturity_equivalent_icp_e8s: 1000,
                    is_capped: is_capped_left,
                    controller,
                    hotkeys: hotkeys.clone(),
                },
            },
        };
        let right = NeuronsFundSnapshot {
            neurons: btreemap! {
                nid(1) => NeuronsFundNeuronPortion {
                    id: nid(1),
                    amount_icp_e8s: 80,
                    maturity_equivalent_icp_e8s: 1000,
                    is_capped: is_capped_right,
                    controller,
                    hotkeys: hotkeys.clone(),
                },
            },
        };
        left.diff(&right)
    };
    // If a neuron was initially uncapped and is still uncapped, let's record the fact that it's
    // uncapped also in the refund (i.e, `diff`).
    assert_matches!(test_with(false, false), Ok(diff) if !diff.neurons[&nid(1)].is_capped);
    // If a neuron was initially uncapped, if shouldn't become capped at the end of a swap.
    assert_matches!(test_with(false, true), Err(_));
    // If a neuron was initially capped but is not capped at the end of a swap, let's record
    // the fact that it's not capped also in the refund (i.e, `diff`).
    assert_matches!(test_with(true, false), Ok(diff) if !diff.neurons[&nid(1)].is_capped);
    // If a neuron was initially capped and is still capped at the end of a swap, let's record
    // the fact that it's still capped also in the refund (i.e, `diff`).
    assert_matches!(test_with(true, true), Ok(diff) if diff.neurons[&nid(1)].is_capped);
}

#[test]
fn compute_intervals_test() {
    let participation = test_participation();
    let neurons: BTreeMap<u64, (NeuronId, u64)> = participation
        .neurons_fund_reserves
        .neurons()
        .iter()
        .map(|(id, n)| (id.id, (*id, n.maturity_equivalent_icp_e8s)))
        .collect();

    let eligibility_intervals = participation
        .compute_neuron_partition_intervals(
            rescale_to_icp(
                participation
                    .swap_participation_limits
                    .min_participant_icp_e8s,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        eligibility_intervals,
        vec![
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 1261104295,
                neurons: btreeset! {},
            },
            // 1261104295 is the value of `direct_participation_icp_e8s` at which the biggest
            // Neurons' Fund neuron (ID 80) becomes eligible, i.e., its proportional
            // participation amount `(800 / 1000) * f(x)` reaches `min_participant_icp_e8s`,
            // where `f(x)` is the ideal matching function.
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 1261104295,
                to_direct_participation_icp_e8s: 5605550845,
                neurons: btreeset! {
                    neurons[&80],
                },
            },
            // 5605550845 is the value of `direct_participation_icp_e8s` at which the second-
            // biggest Neurons' Fund neuron (ID 70) becomes eligible, i.e., its proportional
            // participation amount `(100 / 1000) * f(x)` reaches `min_participant_icp_e8s`,
            // where `f(x)` is the ideal matching function.
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 5605550845,
                to_direct_participation_icp_e8s: 8167418536,
                neurons: btreeset! {
                    neurons[&80],
                    neurons[&70],
                },
            },
            // 8167418536 is the value of `direct_participation_icp_e8s` at which the third-
            // and fourth-biggest Neurons' Fund neurons (IDs 61, 62) become eligible, i.e.,
            // their proportional participation amounts `(each with 35 / 1000) * f(x)` reach
            // `min_participant_icp_e8s`, where `f(x)` is the ideal matching function.
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 8167418536,
                to_direct_participation_icp_e8s: 100 * E8,
                neurons: btreeset! {
                    neurons[&80],
                    neurons[&70],
                    neurons[&61],
                    neurons[&62],
                },
            },
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 100 * E8,
                to_direct_participation_icp_e8s: u64::MAX,
                neurons: btreeset! {
                    neurons[&80],
                    neurons[&70],
                    neurons[&61],
                    neurons[&62],
                    neurons[&50],
                },
            },
        ],
    );

    let capping_intervals = participation
        .compute_neuron_partition_intervals(
            rescale_to_icp(
                participation
                    .swap_participation_limits
                    .max_participant_icp_e8s,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        capping_intervals,
        vec![
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 4111122042,
                neurons: btreeset! {},
            },
            // 4111122042 is the value of `direct_participation_icp_e8s` at which the biggest
            // Neurons' Fund neuron (ID 80) becomes capped, i.e., its proportional participation
            // amount `(800 / 1000) * f(x)` reaches `max_participant_icp_e8s`, where `f(x)` is
            // the ideal matching function.
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 4111122042,
                to_direct_participation_icp_e8s: 9189069784,
                neurons: btreeset! {
                    neurons[&80],
                },
            },
            // 9189069784 is the value of `direct_participation_icp_e8s` at which the second-
            // biggest Neurons' Fund neuron (ID 70) becomes capped, i.e., its proportional
            // participation amount `(100 / 1000) * f(x)` reaches `max_participant_icp_e8s`,
            // where `f(x)` is the ideal matching function.
            NeuronParticipationInterval {
                from_direct_participation_icp_e8s: 9189069784,
                to_direct_participation_icp_e8s: u64::MAX,
                neurons: btreeset! {
                    neurons[&80],
                    neurons[&70],
                },
            },
        ],
    );
}

#[test]
fn compute_linear_scaling_coefficients_test() {
    let mut participation = test_participation();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(
        linear_scaling_coefficients,
        vec![
            // `direct_participation_icp_e8s` too low for anyone from the NF to participate.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 1261104295,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // The biggest NF neuron (ID 80) starts participating.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 1261104295,
                to_direct_participation_icp_e8s: 4111122042,
                slope_numerator: 800 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // The biggest NF neuron (ID 80) becomes capped at the maximum participant amount
            // for this Swap (`intercept_icp_e8s` = 4 ICP). Note that it no longer contributes
            // towards `slope_numerator`.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 4111122042,
                to_direct_participation_icp_e8s: 5605550845,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // The second-biggest NF neuron (ID 70) starts participating, adding its maturity
            // to the `slope_numerator` (+100 ICP).
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 5605550845,
                to_direct_participation_icp_e8s: 8167418536,
                slope_numerator: 100 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // The next two equi-mature neurons (IDs 61, 62) start participating, adding their
            // maturity to the `slope_numerator` (+70 ICP).
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 8167418536,
                to_direct_participation_icp_e8s: 9189069784,
                slope_numerator: 170 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // The priorly added neuron (ID 70) becomes capped, to its maturity is no longer
            // counted towards the `slope_numerator`, rather adding the maximum participant
            // amount to `intercept_icp_e8s` (+4 ICP, 8 ICP in total, since neuron ID 80 is
            // still capped).
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 9189069784,
                to_direct_participation_icp_e8s: 100 * E8,
                slope_numerator: 70 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 8 * E8,
            },
            // The last neuron (ID 50) start participating, adding its maturity to
            // the `slope_numerator` (+20 ICP).
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 100 * E8,
                to_direct_participation_icp_e8s: u64::MAX,
                slope_numerator: 90 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 8 * E8,
            },
        ],
    );
    // Test that varying the `max_direct_participation_icp_e8s` field does not affect
    // the coefficient intervals, as the ideal matching function does not depend on it.
    participation
        .swap_participation_limits
        .max_direct_participation_icp_e8s = 50 * E8;
    let new_linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(new_linear_scaling_coefficients, linear_scaling_coefficients);

    participation
        .swap_participation_limits
        .max_direct_participation_icp_e8s = 75 * E8;
    let new_linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(new_linear_scaling_coefficients, linear_scaling_coefficients);

    participation
        .swap_participation_limits
        .max_direct_participation_icp_e8s = u64::MAX;
    let new_linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(new_linear_scaling_coefficients, linear_scaling_coefficients);
}

#[test]
fn compute_linear_scaling_coefficients_max_min_direct_participation_eqaul() {
    // `min_direct_participation_icp_e8s == max_direct_participation_icp_e8s`
    let participation = NeuronsFundParticipation::new_for_test(
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 100 * E8,
            max_direct_participation_icp_e8s: 100 * E8,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 4 * E8,
        },
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(
        linear_scaling_coefficients,
        vec![
            // No NF participation until the largest neuron becomes eligible.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 1261104295,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // N80 is eligible and uncapped; all others are not eligible yet.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 1261104295,
                to_direct_participation_icp_e8s: 4111122042,
                slope_numerator: 800 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // N80 becomes capped, so it does not contribute to `slope_numerator` anymore
            // (only to `intercept_icp_e8s`).
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 4111122042,
                to_direct_participation_icp_e8s: 5605550845,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // N70 becomes eligible (and uncapped) while N80 is still capped.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 5605550845,
                to_direct_participation_icp_e8s: 8167418536,
                slope_numerator: 100 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // N61 and N62 become eligible (and uncapped) while N70 is still eligible (and
            // uncapped) and N80 is still capped.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 8167418536,
                to_direct_participation_icp_e8s: 9189069784,
                slope_numerator: 170 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 4 * E8,
            },
            // N70 becomes capped, while N61 and N62 are still eligible (and uncapped)
            // and N80 is still capped.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 9189069784,
                to_direct_participation_icp_e8s: 100 * E8,
                slope_numerator: 70 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                // N80 and N70 are capped
                intercept_icp_e8s: 8 * E8,
            },
            // N50 becomes eligible (and uncapped) while N80 and N70 are still capped.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 100 * E8,
                to_direct_participation_icp_e8s: u64::MAX,
                slope_numerator: 90 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 8 * E8,
            },
            // No more intervals, as `max_direct_participation_icp_e8s` is already reached.
            // In particular, N40, N30, N20, N10 are not eligible under any circumstances.
        ]
    );
}

#[test]
fn compute_linear_scaling_coefficients_max_min_participant_icp_equal() {
    // `min_participant_icp_e8s == max_participant_icp_e8s`.
    let participation = NeuronsFundParticipation::new_for_test(
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 50 * E8,
            max_direct_participation_icp_e8s: 100 * E8,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 2 * E8,
        },
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(
        linear_scaling_coefficients,
        vec![
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 2672876708,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0
            },
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 2672876708,
                to_direct_participation_icp_e8s: 7227411278,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                // N80 and N70 just became eligible and are already capped.
                intercept_icp_e8s: 2 * E8,
            },
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 7227411278,
                to_direct_participation_icp_e8s: u64::MAX,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                // N80 and N70 are still capped; N61 and N62 became and capped.
                intercept_icp_e8s: 4 * E8,
            },
        ]
    );
}

#[test]
fn compute_linear_scaling_coefficients_max_participant_icp_is_inf() {
    let participation = NeuronsFundParticipation::new_for_test(
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 50 * E8,
            max_direct_participation_icp_e8s: 100 * E8,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: u64::MAX,
        },
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    // Expected there not to be any capped neurons so `intercept_icp_e8s == 0` on all intervals.
    assert_eq!(
        linear_scaling_coefficients,
        vec![
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 2672876708,
                slope_numerator: 0,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 2672876708,
                to_direct_participation_icp_e8s: 7227411278,
                // N80 is eligible and uncapped.
                slope_numerator: 800 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 7227411278,
                to_direct_participation_icp_e8s: u64::MAX,
                // N80 and N70 are eligible and uncapped.
                slope_numerator: 900 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // At the maximum direct participation (100 ICP), the NF still participates at only 50
            // ICP, so the proportional amount for the next biggest neurons (N61 and N62) are each
            // (35 / 1000) * 50 = 1.75 ICP, i.e., below `min_direct_participation_icp_e8s == 2.0`
            // ICP, so they are never eligible in this scenario.
        ]
    );
}

#[test]
fn compute_linear_scaling_coefficients_min_participant_icp_is_zero() {
    // `max_participant_icp_e8s == u64::MAX`.
    let participation = NeuronsFundParticipation::new_for_test(
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 50 * E8,
            max_direct_participation_icp_e8s: 100 * E8,
            min_participant_icp_e8s: 0,
            max_participant_icp_e8s: 5 * E8,
        },
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    // Expected there not to be any capped neurons so `intercept_icp_e8s == 0` on all intervals.
    assert_eq!(
        linear_scaling_coefficients,
        vec![
            // All neurons become eligible from `direct_participation_icp_e8s == 0`,
            // as `min_participant_icp_e8s == 0`.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 0,
                to_direct_participation_icp_e8s: 4583899598,
                slope_numerator: 1000 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 0,
            },
            // N80 becomes capped. All other neurons are still contributing towards
            // `slope_numerator`.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 4583899598,
                to_direct_participation_icp_e8s: 100 * E8,
                slope_numerator: 200 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 5 * E8,
            },
            // N70 becomes capped and N80 is still capped. Only N50, N61, and N62 remain
            // eligible and uncapped.
            ValidatedLinearScalingCoefficient {
                from_direct_participation_icp_e8s: 100 * E8,
                to_direct_participation_icp_e8s: u64::MAX,
                slope_numerator: 100 * E8,
                slope_denominator: participation.total_maturity_equivalent_icp_e8s,
                intercept_icp_e8s: 10 * E8,
            },
        ]
    );
}

#[test]
fn compute_linear_scaling_coefficients_no_participant_amount_limits() {
    // `max_participant_icp_e8s == u64::MAX`.
    let participation = NeuronsFundParticipation::new_for_test(
        SwapParticipationLimits {
            min_direct_participation_icp_e8s: 50 * E8,
            max_direct_participation_icp_e8s: 100 * E8,
            min_participant_icp_e8s: 0,
            max_participant_icp_e8s: u64::MAX,
        },
        new_neurons_fund_neurons(),
        Box::from(LogisticFunction::new_test_curve()),
    )
    .unwrap();
    let linear_scaling_coefficients: Vec<_> = participation
        .compute_linear_scaling_coefficients()
        .unwrap()
        .into_iter()
        .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval).unwrap())
        .collect();
    assert_eq!(
        linear_scaling_coefficients,
        vec![ValidatedLinearScalingCoefficient {
            from_direct_participation_icp_e8s: 0,
            to_direct_participation_icp_e8s: u64::MAX,
            slope_numerator: participation.total_maturity_equivalent_icp_e8s,
            slope_denominator: participation.total_maturity_equivalent_icp_e8s,
            intercept_icp_e8s: 0,
        },]
    );
}
