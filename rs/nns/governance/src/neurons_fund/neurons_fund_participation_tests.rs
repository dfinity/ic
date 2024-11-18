use super::*;
use ic_neurons_fund::test_functions::SimpleLinearFunction;

fn nid(id: u64) -> NeuronId {
    NeuronId { id }
}

/// Test that the Neurons' Fund participation is correct in a scenario in which direct participation
/// in an SNS swap is between `500` and `u64::MAX`. This setting allows for even very small neurons
/// to become eligible in the best case, while some smaller neurons not being eligible in the worst
/// case, so refund computation is non-trivial.
///
/// Narrative Outline:
/// 1. Create a Neurons' Fund with three neurons: one small, one medium, one big.
/// 2. Create an initial participation based on this Neurons' Fund.
/// 3. Derive the final participation from the initial participation.
/// 4. Assert that the relationship between the field values is correct for the initial
///    and final participations. In particular, a decrease is expected for the fields
///    `intended_neurons_fund_participation_icp_e8s` and `allocated_neurons_fund_participation_icp_e8s`.
///    (Initial participation is for the best-case scenario, so final participation is less than or
///    equal to the initial.) Note that these two fields have the same value in the initial
///    participation, but a slightly different value in the final participation. This is because we
///    set the smallest neuron's maturity to a value is sufficient for it to participate in the best
///    case scenario (corresponding to the initial participation) while not sufficient for it to
///    participate in the final participation.
/// 5. Assert that the `total_amount_icp_e8s` is computed correctly.
/// 6. Assert that the neuron portions comprising maturity refunds computed through
///    ```
///    initial_participation
///        .into_snapshot()
///        .diff(final_participation.snapshot()),
///    ```
///    are expected.
///
/// The code under test is `NeuronsFundParticipation` with all of its operations and sub-structures,
/// e.g., `NeuronsFundSnapshot`, *except* for `ideal_matched_participation_function`. Thus, we mock
/// the production-ready `ideal_matched_participation_function` with `SimpleLinearFunction`, which
/// ensures that we get a simple 1:1 matching.
#[test]
fn test() {
    let controller = PrincipalId::default();
    let hotkeys = Vec::new();
    let small_neuron = NeuronsFundNeuron {
        id: nid(111),
        maturity_equivalent_icp_e8s: 590,
        controller,
        hotkeys: hotkeys.clone(),
    };
    let medium_neuron = NeuronsFundNeuron {
        id: nid(222),
        maturity_equivalent_icp_e8s: 5_000,
        controller,
        hotkeys: hotkeys.clone(),
    };
    let big_neuron = NeuronsFundNeuron {
        id: nid(333),
        maturity_equivalent_icp_e8s: 500_000,
        controller,
        hotkeys: hotkeys.clone(),
    };
    let swap_participation_limits = SwapParticipationLimits {
        min_participant_icp_e8s: 50,
        max_participant_icp_e8s: 40_000,
        // Due to this value, only `big_neuron` is eligible for `final_participation`, i.e.,
        // 1. Since `medium_neuron.maturity_equivalent_icp_e8s == 5_000`, we get
        //    `500 * 5_000 / (590 + 5_000 + 500_000)  ==  4.944...  <  min_participant_icp_e8s`.
        // 2. Since `big_neuron.maturity_equivalent_icp_e8s == 500_000`, we analogously get
        //    `big_neuron.maturity_equivalent_icp_e8s == 494.471...  >=  min_participant_icp_e8s`.
        min_direct_participation_icp_e8s: 500,
        // Due to this value, all three neurons are capped for `initial_participation`, i.e.,
        // Since `small_neuron.maturity_equivalent_icp_e8s == 590`, we get
        // `u64::MAX * 590 / (590 + 5_000 + 500_000)  >  max_participant_icp_e8s`.
        max_direct_participation_icp_e8s: u64::MAX,
    };
    let initial_participation = NeuronsFundParticipation::new_for_test(
        swap_participation_limits,
        vec![
            small_neuron.clone(),
            medium_neuron.clone(),
            big_neuron.clone(),
        ],
        Box::new(SimpleLinearFunction {}),
    )
    .unwrap();
    let final_participation = initial_participation
        .from_initial_participation_for_test(500, Box::new(SimpleLinearFunction {}))
        .unwrap();
    println!("initial_participation = {:#?}", initial_participation);
    println!("final_participation = {:#?}", final_participation);

    assert_eq!(initial_participation.direct_participation_icp_e8s, u64::MAX);
    assert_eq!(final_participation.direct_participation_icp_e8s, 500);

    // 10% of the Neurons' Fund total maturity
    assert_eq!(
        initial_participation.max_neurons_fund_swap_participation_icp_e8s,
        50_559
    );
    // Still 10% of the Neurons' Fund total maturity, as this value does not depend on
    // `direct_participation_icp_e8s`.
    assert_eq!(
        final_participation.max_neurons_fund_swap_participation_icp_e8s,
        50_559
    );
    // This is just the minimum of `max_neurons_fund_swap_participation_icp_e8s` and whatever the
    // matching function gives us, which in this case is `u64::MAX` (due to 1:1) matching.
    assert_eq!(
        initial_participation.intended_neurons_fund_participation_icp_e8s,
        50_559
    );
    // Now that the matching function gives us 500, this is how much we should be matching
    // despite the Neurons' Fund having reserved 50_559 of maturity for this SNS instance.
    assert_eq!(
        final_participation.intended_neurons_fund_participation_icp_e8s,
        500
    );
    // Only `big_neuron` is capped, giving 40_000. `small_neuron` and `medium_neuron` together
    // have proportional maturity `50559 * (5_000 + 590) / 505590  ==  559`.
    assert_eq!(
        initial_participation.allocated_neurons_fund_participation_icp_e8s,
        40_559
    );
    // Only `big_neuron` is eligible, giving 494.471...
    assert_eq!(
        final_participation.allocated_neurons_fund_participation_icp_e8s,
        494
    );
    // Same as `initial_participation.allocated_neurons_fund_participation_icp_e8s`.
    assert_eq!(
        initial_participation
            .neurons_fund_reserves
            .total_amount_icp_e8s()
            .unwrap(),
        40_559
    );
    // Same as `final_participation.allocated_neurons_fund_participation_icp_e8s`.
    assert_eq!(
        final_participation
            .neurons_fund_reserves
            .total_amount_icp_e8s()
            .unwrap(),
        494
    );
    // Make sure the refunds are as expected.
    assert_eq!(
        initial_participation
            .into_snapshot()
            .diff(final_participation.snapshot()),
        Ok(NeuronsFundSnapshot::new([
            NeuronsFundNeuronPortion {
                id: small_neuron.id,
                amount_icp_e8s: 59,
                maturity_equivalent_icp_e8s: small_neuron.maturity_equivalent_icp_e8s,
                controller,
                hotkeys: hotkeys.clone(),
                is_capped: false,
            },
            NeuronsFundNeuronPortion {
                id: medium_neuron.id,
                amount_icp_e8s: 500,
                maturity_equivalent_icp_e8s: medium_neuron.maturity_equivalent_icp_e8s,
                controller,
                hotkeys: hotkeys.clone(),
                is_capped: false,
            },
            NeuronsFundNeuronPortion {
                id: big_neuron.id,
                amount_icp_e8s: 39_506,
                maturity_equivalent_icp_e8s: big_neuron.maturity_equivalent_icp_e8s,
                controller,
                hotkeys,
                is_capped: false,
            },
        ]))
    );
}
