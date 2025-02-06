use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_inherit_from_recursively() {
    let base = NetworkEconomics::with_default_values();

    let changes = NetworkEconomics {
        reject_cost_e8s: 99,

        // This should not show up in the result.
        neuron_management_fee_per_proposal_e8s: 0,

        voting_power_economics: Some(VotingPowerEconomics {
            start_reducing_voting_power_after_seconds: Some(42),

            // This should not show up in the result.
            clear_following_after_seconds: None
        }),

        // This should not show up in the result.
        neurons_fund_economics: None,

        ..Default::default()
    };

    let observed_network_economics = changes.inherit_from(&base);

    let mut expected_network_economics = NetworkEconomics::with_default_values();
    expected_network_economics.reject_cost_e8s = 99;
    expected_network_economics
        .voting_power_economics
        .as_mut()
        .unwrap()
        .start_reducing_voting_power_after_seconds = Some(42);

    assert_eq!(observed_network_economics, expected_network_economics);
}
