use super::*;
use ic_nervous_system_proto::pb::v1::Decimal as ProtoDecimal;
use crate::governance::MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
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
fn test_neuron_minimum_dissolve_delay_to_vote_seconds_out_of_bounds_is_invalid() {
    let mut default_network_economics = NetworkEconomics::with_default_values();
    default_network_economics
        .voting_power_economics
        .unwrap()
        .neuron_minimum_dissolve_delay_to_vote_seconds =
        Some(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1);
    assert_eq!(default_network_economics.validate(), Ok(()));
}
