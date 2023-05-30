use super::*;
use ic_nervous_system_humanize::{parse_duration, parse_percentage, parse_tokens};
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
            transaction_fee: parse_tokens("10_000 e8s").unwrap(),
        },

        proposals: Proposals {
            rejection_fee: parse_tokens("1 token").unwrap(),
            initial_voting_period: parse_duration("4d").unwrap(),
            maximum_wait_for_quiet_deadline_extension: parse_duration("1 day").unwrap(),
        },

        neurons: Neurons {
            minimum_creation_stake: parse_tokens("10 tokens").unwrap(),
        },

        voting: Voting {
            minimum_dissolve_delay: parse_duration("26 weeks").unwrap(),

            maximum_voting_power_bonuses: MaximumVotingPowerBonuses {
                dissolve_delay: Bonus {
                    duration: parse_duration("8 years").unwrap(),
                    bonus: parse_percentage("100%").unwrap(),
                },

                age: Bonus {
                    duration: parse_duration("4 years").unwrap(),
                    bonus: parse_percentage("25%").unwrap(),
                },
            },

            reward_rate: RewardRate {
                initial: parse_percentage("10%").unwrap(),
                r#final: parse_percentage("2.25%").unwrap(),
                transition_duration: parse_duration("12 years").unwrap(),
            },
        },

        distribution: Distribution {
            neurons: vec![
                Neuron {
                    principal: "Bruce Wayne".to_string(),
                    stake: parse_tokens("15 tokens").unwrap(),
                    memo: 42,
                    dissolve_delay: parse_duration("1 years").unwrap(),
                },
                Neuron {
                    principal: "Bruce Wayne".to_string(),
                    stake: parse_tokens("15 tokens").unwrap(),
                    memo: 0, // Not explicitly supplied -> 0 is taken as default.
                    dissolve_delay: parse_duration("1 years").unwrap(),
                },
            ],

            initial_balances: InitialBalances {
                governance: parse_tokens("50 tokens").unwrap(),
                swap: parse_tokens("30 tokens").unwrap(),
            },

            total: parse_tokens("95 tokens").unwrap(),
        },
    };

    assert_eq!(
        observed_sns_configuration_file,
        expected_sns_configuration_file,
    );
}
