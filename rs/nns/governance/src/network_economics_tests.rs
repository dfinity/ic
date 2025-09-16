use super::*;
use ic_nervous_system_proto::pb::v1::Decimal as ProtoDecimal;
use pretty_assertions::assert_eq;

#[test]
fn test_inherit_from_recursively() {
    let base = NetworkEconomics::with_default_values();

    let changes = NetworkEconomics {
        reject_cost_e8s: 99, // Change.

        neurons_fund_economics: Some(NeuronsFundEconomics {
            neurons_fund_matched_funding_curve_coefficients: Some(
                NeuronsFundMatchedFundingCurveCoefficients {
                    // Deep change.
                    contribution_threshold_xdr: Some(ProtoDecimal {
                        human_readable: Some("42".to_string()),
                    }),

                    one_third_participation_milestone_xdr: None,
                    ..Default::default()
                },
            ),

            // This is equivalent to None, because 0 is ALWAYS vulnerable to
            // being overridden, even when inside Some. Therefore no change here.
            minimum_icp_xdr_rate: Some(Percentage {
                basis_points: Some(0),
            }),

            ..Default::default()
        }),

        // No change for these either.
        neuron_management_fee_per_proposal_e8s: 0,
        voting_power_economics: None,
        ..Default::default()
    };

    let observed_network_economics = changes.inherit_from(&base);

    let mut expected_network_economics = NetworkEconomics::with_default_values();

    // Change reject_cost in expected result.
    {
        let reject_cost_e8s = &mut expected_network_economics.reject_cost_e8s;
        assert_ne!(*reject_cost_e8s, 99);
        *reject_cost_e8s = 99;
    }

    // Change misc NF parameters in expected result.
    {
        let neurons_fund_economics = expected_network_economics
            .neurons_fund_economics
            .as_mut()
            .unwrap();

        let minimum_icp_xdr_rate = neurons_fund_economics
            .minimum_icp_xdr_rate
            .as_mut()
            .unwrap();
        assert_ne!(
            *minimum_icp_xdr_rate,
            Percentage {
                basis_points: Some(0)
            }
        );

        let contribution_threshold_xdr = neurons_fund_economics
            .neurons_fund_matched_funding_curve_coefficients
            .as_mut()
            .unwrap()
            .contribution_threshold_xdr
            .as_mut()
            .unwrap()
            .human_readable
            .as_mut()
            .unwrap();
        assert_ne!(*contribution_threshold_xdr, "42".to_string());
        *contribution_threshold_xdr = "42".to_string();
    }

    assert_eq!(observed_network_economics, expected_network_economics);
}

#[test]
fn test_network_economics_with_default_values_is_valid() {
    assert_eq!(NetworkEconomics::with_default_values().validate(), Ok(()));
}

#[test]
fn test_neuron_minimum_dissolve_delay_to_vote_seconds_bounds() {
    // Define constants for better readability and maintainability
    const LOWER_BOUND_SECONDS: u64 = 3 * ONE_MONTH_SECONDS;
    const UPPER_BOUND_SECONDS: u64 = 6 * ONE_MONTH_SECONDS;
    const DEFAULT_SECONDS: u64 = LOWER_BOUND_SECONDS; // Assuming default is the minimum

    // Test cases: (delay in seconds, expected result)
    let test_cases = [
        (
            None,
            Err(vec![
                "neuron_minimum_dissolve_delay_to_vote_seconds must be set.".to_string(),
            ]),
        ),
        (
            Some(LOWER_BOUND_SECONDS - 1),
            Err(vec![format!(
                "neuron_minimum_dissolve_delay_to_vote_seconds (Some({})) must be between three and six months.",
                LOWER_BOUND_SECONDS - 1
            )]),
        ),
        (
            Some(UPPER_BOUND_SECONDS + 1),
            Err(vec![format!(
                "neuron_minimum_dissolve_delay_to_vote_seconds (Some({})) must be between three and six months.",
                UPPER_BOUND_SECONDS + 1
            )]),
        ),
        (Some(DEFAULT_SECONDS), Ok(())),
        (Some(LOWER_BOUND_SECONDS), Ok(())),
        (Some(UPPER_BOUND_SECONDS), Ok(())),
    ];

    for (delay_seconds, expected_result) in test_cases {
        let mut economics = NetworkEconomics::with_default_values();
        economics
            .voting_power_economics
            .as_mut()
            .expect("bug: voting_power_economics missing")
            .neuron_minimum_dissolve_delay_to_vote_seconds = delay_seconds;

        assert_eq!(
            economics.validate(),
            expected_result,
            "Failed for delay: {:?}",
            delay_seconds
        );
    }
}
