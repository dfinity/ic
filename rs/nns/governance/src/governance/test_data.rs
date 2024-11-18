// This is in its own mod so that it can be used by other crates.
//
// Ideally, this would only be available when cfg(feature = "test") is enabled,
// but it doesn't seem like making this always available creates much risk. A
// the same time, trying to hide this behind "test" would create more hurdles.
use super::*;
use ic_nervous_system_common::E8;
use ic_nervous_system_proto::pb::v1 as pb;
use ic_neurons_fund::{
    NeuronsFundParticipationLimits, PolynomialMatchingFunction, SerializableFunction,
};
use ic_sns_swap::pb::v1::{IdealMatchedParticipationFunction, LinearScalingCoefficient};
use lazy_static::lazy_static;
use rust_decimal_macros::dec;

// Alias types from crate::pb::v1::...
//
// This is done within another mod to differentiate against types that have
// similar names as types found in ic_sns_init.
mod src {
    pub use crate::pb::v1::create_service_nervous_system::{
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            developer_distribution::NeuronDistribution, DeveloperDistribution, SwapDistribution,
            TreasuryDistribution,
        },
        swap_parameters::NeuronBasketConstructionParameters,
        GovernanceParameters, InitialTokenDistribution, SwapParameters,
    };
} // end mod src

// Both are 1 pixel. The first contains #00FF0F. The second is black.
pub const IMAGE_1: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";
pub const IMAGE_2: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAAAAAAEAAEvUrSNAAAAAElFTkSuQmCC";

lazy_static! {
    pub static ref CREATE_SERVICE_NERVOUS_SYSTEM: CreateServiceNervousSystem = CreateServiceNervousSystem {
        name: Some("Hello, world!".to_string()),
        description: Some("Best app that you ever did saw.".to_string()),
        url: Some("https://best.app".to_string()),
        logo: Some(pb::Image {
            base64_encoding: Some(IMAGE_1.to_string()),
        }),
        fallback_controller_principal_ids: vec![PrincipalId::new_user_test_id(349839)],
        initial_token_distribution: Some(src::InitialTokenDistribution {
            developer_distribution: Some(src::DeveloperDistribution {
                developer_neurons: vec![src::NeuronDistribution {
                    controller: Some(PrincipalId::new_user_test_id(830947)),
                    dissolve_delay: Some(pb::Duration {
                        seconds: Some(ONE_MONTH_SECONDS * 6),
                    }),
                    memo: Some(763535),
                    stake: Some(pb::Tokens { e8s: Some(756575) }),
                    vesting_period: Some(pb::Duration {
                        seconds: Some(0),
                    }),
                }],
            }),
            treasury_distribution: Some(src::TreasuryDistribution {
                total: Some(pb::Tokens { e8s: Some(307064) }),
            }),
            swap_distribution: Some(src::SwapDistribution {
                total: Some(pb::Tokens {
                    e8s: Some(1_840_880_000),
                }),
            }),
        }),
        ledger_parameters: Some(LedgerParameters {
            transaction_fee: Some(pb::Tokens { e8s: Some(11143) }),
            token_name: Some("Most valuable SNS of all time.".to_string()),
            token_symbol: Some("Kanye".to_string()),
            token_logo: Some(pb::Image {
                base64_encoding: Some(IMAGE_2.to_string()),
            }),
        }),
        governance_parameters: Some(src::GovernanceParameters {
            // Proposal Parameters
            // -------------------
            proposal_rejection_fee: Some(pb::Tokens { e8s: Some(372250) }),
            proposal_initial_voting_period: Some(pb::Duration {
                seconds: Some(709_499),
            }),
            proposal_wait_for_quiet_deadline_increase: Some(pb::Duration {
                seconds: Some(75_891),
            }),

            // Neuron Parameters
            // -----------------
            neuron_minimum_stake: Some(pb::Tokens { e8s: Some(250_000) }),

            neuron_minimum_dissolve_delay_to_vote: Some(pb::Duration {
                seconds: Some(482538),
            }),
            neuron_maximum_dissolve_delay: Some(pb::Duration {
                seconds: Some(ONE_MONTH_SECONDS * 12),
            }),
            neuron_maximum_dissolve_delay_bonus: Some(pb::Percentage {
                basis_points: Some(18_00),
            }),

            neuron_maximum_age_for_age_bonus: Some(pb::Duration {
                seconds: Some(740908),
            }),
            neuron_maximum_age_bonus: Some(pb::Percentage {
                basis_points: Some(54_00),
            }),

            voting_reward_parameters: Some(src::VotingRewardParameters {
                initial_reward_rate: Some(pb::Percentage {
                    basis_points: Some(25_92),
                }),
                final_reward_rate: Some(pb::Percentage {
                    basis_points: Some(7_40),
                }),
                reward_rate_transition_duration: Some(pb::Duration {
                    seconds: Some(378025),
                }),
            }),
        }),
        dapp_canisters: vec![pb::Canister {
            id: Some(CanisterId::from_u64(1000).get())
        }],

        swap_parameters: Some(src::SwapParameters {
            confirmation_text: Some("Confirm you are a human".to_string()),
            restricted_countries: Some(pb::Countries {
                iso_codes: vec!["CH".to_string()]
            }),

            minimum_participants: Some(50),
            minimum_direct_participation_icp: Some(pb::Tokens {
                e8s: Some(12_300_000_000-6_100_000_000), // Subtract neurons_fund_investment_icp
            }),
            maximum_direct_participation_icp: Some(pb::Tokens {
                e8s: Some(25_000_000_000-6_100_000_000), // Subtract neurons_fund_investment_icp
            }),
            minimum_participant_icp: Some(pb::Tokens {
                e8s:  Some(100_000_000)
            }),
            maximum_participant_icp: Some(pb::Tokens {
                e8s:  Some(10_000_000_000)
            }),
            neuron_basket_construction_parameters: Some(src::NeuronBasketConstructionParameters {
                count: Some(2),
                dissolve_delay_interval: Some(pb::Duration {
                    seconds: Some(10_001),
                })
            }),
            start_time: Some(GlobalTimeOfDay {
               seconds_after_utc_midnight: Some(0),
            }),
            duration: Some(pb::Duration {
                seconds: Some(604_800),
            }),

            neurons_fund_investment_icp: Some(pb::Tokens {
                e8s: Some(6_100_000_000),
            }),
            neurons_fund_participation: Some(false),

            // Deprecated fields must not be set.
            minimum_icp: None,
            maximum_icp: None,
        })
    };

    pub static ref CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING: CreateServiceNervousSystem = {
        let swap_parameters = CREATE_SERVICE_NERVOUS_SYSTEM
            .swap_parameters
            .clone()
            .unwrap();
        CreateServiceNervousSystem {
            swap_parameters: Some(src::SwapParameters {
                minimum_direct_participation_icp: Some(pb::Tokens {
                    e8s: Some(36_000 * E8),
                }),
                maximum_direct_participation_icp: Some(pb::Tokens {
                    e8s: Some(90_000 * E8),
                }),
                minimum_participant_icp: Some(pb::Tokens {
                    e8s: Some(50 * E8),
                }),
                maximum_participant_icp: Some(pb::Tokens {
                    e8s: Some(1_000 * E8),
                }),
                neurons_fund_participation: Some(true),

                // Unset legacy fields
                minimum_icp: None,
                maximum_icp: None,
                neurons_fund_investment_icp: None,
                ..swap_parameters
            }),
            ..CREATE_SERVICE_NERVOUS_SYSTEM.clone()
        }
    };

    pub static ref NEURONS_FUND_PARTICIPATION_CONSTRAINTS: NeuronsFundParticipationConstraints = NeuronsFundParticipationConstraints {
        min_direct_participation_threshold_icp_e8s: Some(
            36_000 * E8,
        ),
        max_neurons_fund_participation_icp_e8s: Some(
            45_000 * E8,
        ),
        coefficient_intervals: vec![LinearScalingCoefficient {
            from_direct_participation_icp_e8s: Some(0),
            to_direct_participation_icp_e8s: Some(u64::MAX),
            slope_numerator: Some(1),
            slope_denominator: Some(1),
            intercept_icp_e8s: Some(0),
        }],
        ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
            serialized_representation: Some(
                PolynomialMatchingFunction::new(
                    u64::MAX,
                    NeuronsFundParticipationLimits {
                        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
                        contribution_threshold_icp: dec!(33_000.0),
                        one_third_participation_milestone_icp: dec!(100_000.0),
                        full_participation_milestone_icp: dec!(167_000.0),
                    },
                    false
                ).unwrap().serialize(),
            ),
        }),
    };
}
