use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_parse() {
    let configuration_file_path = {
        let mut result = std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        result.push("example_sns_init_v2.yaml");
        result
    };
    let contents = std::fs::read_to_string(configuration_file_path).unwrap();

    let observed_sns_configuration_file =
        serde_yaml::from_str::<SnsConfigurationFile>(&contents).unwrap();

    let expected_sns_configuration_file = SnsConfigurationFile {
        name: "Daniel".to_string(),
        description: "The best software engineer you ever did saw.\n".to_string(),
        logo: PathBuf::from("batman.png"),
        url: "https://www.example.com".to_string(),

        principals: vec![PrincipalAlias {
            id: "hello-world-big-opaque-blob-here-to-ruin-your-eyes".to_string(),
            name: Some("Bruce Wayne".to_string()),
            email: Some("batman@superherosinc.com".to_string()),
        }],

        fallback_controller_principals: vec!["Bruce Wayne".to_string()],

        token: Token {
            name: "Batman".to_string(),
            symbol: "BTM".to_string(),
            transaction_fee: "10_000 e8s".to_string(),
        },

        proposals: Proposals {
            rejection_fee: "1 token".to_string(),
            initial_voting_period: "4d".to_string(),
            maximum_wait_for_quiet_deadline_extension: "1 day".to_string(),
        },

        neurons: Neurons {
            minimum_creation_stake: "10 tokens".to_string(),
        },

        voting: Voting {
            minimum_dissolve_delay: "26 weeks".to_string(),

            maximum_voting_power_bonuses: MaximumVotingPowerBonuses {
                dissolve_delay: Bonus {
                    duration: "8 years".to_string(),
                    boost: "100%".to_string(),
                },

                age: Bonus {
                    duration: "4 years".to_string(),
                    boost: "25%".to_string(),
                },
            },

            reward_rate: RewardRate {
                initial: "10%".to_string(),
                r#final: "2.25%".to_string(),
                transition_duration: "12 years".to_string(),
            },
        },

        distribution: Distribution {
            neurons: vec![
                Neuron {
                    principal: "Bruce Wayne".to_string(),
                    stake: "15 tokens".to_string(),
                    memo: 42,
                    dissolve_delay: "0.5 years".to_string(),
                },
                Neuron {
                    principal: "Bruce Wayne".to_string(),
                    stake: "15 tokens".to_string(),
                    memo: 0, // Not explicitly supplied -> 0 is taken as default.
                    dissolve_delay: "0.5 years".to_string(),
                },
            ],

            balances: Balances {
                governance: "50 tokens".to_string(),
                swap: "30 tokens".to_string(),
            },

            total: "95 tokens".to_string(),
        },
    };

    assert_eq!(
        observed_sns_configuration_file,
        expected_sns_configuration_file,
    );
}
