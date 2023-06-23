use super::*;
use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
use ic_nervous_system_humanize::{parse_duration, parse_percentage, parse_tokens};
use pretty_assertions::assert_eq;

const NOMINAL_SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY + SECONDS_PER_DAY / 4;

struct SaveAndRestoreCurrentDirectoryOnExit {
    original: PathBuf,
}

impl SaveAndRestoreCurrentDirectoryOnExit {
    fn new() -> Self {
        let original = std::env::current_dir().unwrap();
        println!("Saving original working dir: {}", original.display());
        Self { original }
    }
}

impl Drop for SaveAndRestoreCurrentDirectoryOnExit {
    fn drop(&mut self) {
        std::env::set_current_dir(self.original.clone());
        println!(
            "Restored original dir: {}",
            std::env::current_dir().unwrap().display()
        );
    }
}

#[test]
fn test_parse() {
    let input_path = {
        let mut result = std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        result.push("example_sns_init_v2.yaml");
        result
    };

    let contents = std::fs::read_to_string(input_path).unwrap();
    let observed_sns_configuration_file =
        serde_yaml::from_str::<SnsConfigurationFile>(&contents).unwrap();

    let expected_sns_configuration_file = SnsConfigurationFile {
        name: "Daniel".to_string(),
        description: "The best software engineer you ever did saw.\n".to_string(),
        logo: PathBuf::from("test.png"),
        url: "https://forum.dfinity.org/thread-where-this-sns-is-discussed".to_string(),

        principals: vec![
            PrincipalAlias {
                id: "5zxxw-63ouu-faaaa-aaaap-4ai".to_string(),
                name: Some("Bruce Wayne".to_string()),
                email: Some("batman@superherosinc.com".to_string()),
            },
            PrincipalAlias {
                id: PrincipalId::new_user_test_id(746890).to_string(),
                name: Some("Alfred Pennyworth".to_string()),
                email: None,
            },
            PrincipalAlias {
                id: "c2n4r-wni5m-dqaaa-aaaap-4ai".to_string(),
                name: Some("employees (canister)".to_string()),
                email: None,
            },
            PrincipalAlias {
                id: "ucm27-3lxwy-faaaa-aaaap-4ai".to_string(),
                name: Some("departments (canister)".to_string()),
                email: None,
            },
        ],

        fallback_controller_principals: vec!["5zxxw-63ouu-faaaa-aaaap-4ai".to_string()],
        dapp_canisters: vec![
            "c2n4r-wni5m-dqaaa-aaaap-4ai".to_string(),
            "ucm27-3lxwy-faaaa-aaaap-4ai".to_string(),
        ],

        token: Token {
            name: "Batman".to_string(),
            symbol: "BTM".to_string(),
            transaction_fee: nervous_system_pb::Tokens { e8s: Some(10_000) },
        },

        proposals: Proposals {
            rejection_fee: nervous_system_pb::Tokens { e8s: Some(E8) },
            initial_voting_period: nervous_system_pb::Duration {
                seconds: Some(4 * SECONDS_PER_DAY),
            },
            maximum_wait_for_quiet_deadline_extension: nervous_system_pb::Duration {
                seconds: Some(SECONDS_PER_DAY),
            },
        },

        neurons: Neurons {
            minimum_creation_stake: nervous_system_pb::Tokens { e8s: Some(10 * E8) },
        },

        voting: Voting {
            minimum_dissolve_delay: nervous_system_pb::Duration {
                seconds: Some(26 * 7 * SECONDS_PER_DAY),
            },

            maximum_voting_power_bonuses: MaximumVotingPowerBonuses {
                dissolve_delay: Bonus {
                    duration: nervous_system_pb::Duration {
                        seconds: Some(8 * NOMINAL_SECONDS_PER_YEAR),
                    },
                    bonus: nervous_system_pb::Percentage {
                        basis_points: Some(1_00_00), // 100%
                    },
                },

                age: Bonus {
                    duration: nervous_system_pb::Duration {
                        seconds: Some(4 * NOMINAL_SECONDS_PER_YEAR),
                    },
                    bonus: nervous_system_pb::Percentage {
                        basis_points: Some(25_00), // 25%
                    },
                },
            },

            reward_rate: RewardRate {
                initial: nervous_system_pb::Percentage {
                    basis_points: Some(10_00), // 10%
                },
                r#final: nervous_system_pb::Percentage {
                    basis_points: Some(2_25), // 2.25%
                },
                transition_duration: nervous_system_pb::Duration {
                    seconds: Some(12 * NOMINAL_SECONDS_PER_YEAR),
                },
            },
        },

        distribution: Distribution {
            neurons: vec![
                Neuron {
                    principal: "5zxxw-63ouu-faaaa-aaaap-4ai".to_string(),
                    stake: nervous_system_pb::Tokens { e8s: Some(15 * E8) },
                    memo: 42,
                    dissolve_delay: nervous_system_pb::Duration {
                        seconds: Some(NOMINAL_SECONDS_PER_YEAR),
                    },
                    vesting_period: nervous_system_pb::Duration {
                        seconds: Some(NOMINAL_SECONDS_PER_YEAR + 1),
                    },
                },
                Neuron {
                    principal: "uqf5l-jukmu-fqaaa-aaaap-4ai".to_string(),
                    stake: nervous_system_pb::Tokens {
                        e8s: Some(14 * E8 + 9 * E8 / 10), // 14.9 tokens
                    },
                    memo: 0, // Not explicitly supplied -> 0 is taken as default.
                    dissolve_delay: nervous_system_pb::Duration {
                        seconds: Some(52 * 7 * SECONDS_PER_DAY),
                    },
                    vesting_period: nervous_system_pb::Duration {
                        seconds: Some(53 * 7 * SECONDS_PER_DAY),
                    },
                },
            ],

            initial_balances: InitialBalances {
                governance: nervous_system_pb::Tokens { e8s: Some(60 * E8) },
                swap: nervous_system_pb::Tokens { e8s: Some(40 * E8) },
            },

            total: nervous_system_pb::Tokens {
                e8s: Some(129 * E8 + 9 * E8 / 10), // 129.9 tokens
            },
        },

        swap: Swap {
            minimum_participants: 57,

            minimum_icp: parse_tokens("232_714 tokens").unwrap(),
            maximum_icp: parse_tokens("557_054 tokens").unwrap(),

            minimum_participant_icp: parse_tokens("5 tokens").unwrap(),
            maximum_participant_icp: parse_tokens("100 tokens").unwrap(),

            confirmation_text: Some("Hello, world?".to_string()),

            restricted_countries: vec!["US".to_string(), "CH".to_string()],

            vesting_schedule: VestingSchedule {
                events: 83,
                interval: parse_duration("17 days").unwrap(),
            },

            start_time: Some(nervous_system_pb::GlobalTimeOfDay::from_hh_mm(12, 0).unwrap()),
            duration: nervous_system_pb::Duration {
                seconds: Some(7 * 24 * 60 * 60),
            },
        },
    };

    assert_eq!(
        observed_sns_configuration_file,
        expected_sns_configuration_file,
    );
}

#[test]
fn test_convert_to_create_service_nervous_system() {
    // Step 1: Prepare the world.
    let save_and_restore_current_directory_on_exit = SaveAndRestoreCurrentDirectoryOnExit::new();
    let test_root_dir = std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
    std::env::set_current_dir(test_root_dir);

    let contents = std::fs::read_to_string("example_sns_init_v2.yaml").unwrap();
    let sns_configuration_file = serde_yaml::from_str::<SnsConfigurationFile>(&contents).unwrap();

    // Step 2: Call code under test.
    let observed_create_service_nervous_system = sns_configuration_file
        .try_convert_to_create_service_nervous_system()
        .unwrap();

    // Step 3: Inspect results.

    assert_eq!(
        CreateServiceNervousSystem {
            // These will be inspected later.
            logo: None,
            initial_token_distribution: None,
            swap_parameters: None,
            governance_parameters: None,
            ledger_parameters: None,

            ..observed_create_service_nervous_system
        },
        CreateServiceNervousSystem {
            name: Some("Daniel".to_string()),
            description: Some("The best software engineer you ever did saw.\n".to_string()),
            url: Some("https://forum.dfinity.org/thread-where-this-sns-is-discussed".to_string()),

            fallback_controller_principal_ids: vec![PrincipalId::from_str(
                "5zxxw-63ouu-faaaa-aaaap-4ai"
            )
            .unwrap(),],

            dapp_canisters: vec![
                nervous_system_pb::Canister {
                    id: Some(PrincipalId::from_str("c2n4r-wni5m-dqaaa-aaaap-4ai").unwrap()),
                },
                nervous_system_pb::Canister {
                    id: Some(PrincipalId::from_str("ucm27-3lxwy-faaaa-aaaap-4ai").unwrap()),
                },
            ],

            logo: None,
            initial_token_distribution: None,
            swap_parameters: None,
            ledger_parameters: None,
            governance_parameters: None,
        }
    );

    let observed_logo = observed_create_service_nervous_system
        .logo
        .unwrap()
        .base64_encoding
        .unwrap();
    assert!(
        observed_logo.starts_with("data:image/png;base64,"),
        "{:?}",
        observed_logo,
    );

    let observed_logo_content = base64::decode(
        observed_logo
            .strip_prefix("data:image/png;base64,")
            .unwrap(),
    )
    .unwrap();
    let expected_logo_content = std::fs::read("test.png").unwrap();
    assert!(
        // == is used instead of the usual assert_eq!, because when the observed
        // value is not as expected, assert_eq! would produce a ton of spam, due
        // to this being a large blob.
        observed_logo_content == expected_logo_content,
        "len(observed) == {} vs. len(expected) == {}",
        observed_logo_content.len(),
        expected_logo_content.len(),
    );

    assert_eq!(
        observed_create_service_nervous_system
            .initial_token_distribution
            .unwrap(),
        nns_governance_pb::InitialTokenDistribution {
            developer_distribution: Some(nns_governance_pb::DeveloperDistribution {
                developer_neurons: vec![
                    nns_governance_pb::NeuronDistribution {
                        controller: Some(
                            PrincipalId::from_str("5zxxw-63ouu-faaaa-aaaap-4ai").unwrap()
                        ),
                        dissolve_delay: Some(parse_duration("1 years").unwrap()),
                        memo: Some(42),
                        stake: Some(parse_tokens("15 tokens").unwrap()),
                        vesting_period: Some(parse_duration("1 year 1 second").unwrap()),
                    },
                    nns_governance_pb::NeuronDistribution {
                        controller: Some(
                            PrincipalId::from_str("uqf5l-jukmu-fqaaa-aaaap-4ai").unwrap()
                        ),
                        dissolve_delay: Some(parse_duration("52 weeks").unwrap()),
                        memo: Some(0),
                        stake: Some(parse_tokens("14.9 tokens").unwrap()),
                        vesting_period: Some(parse_duration("53 weeks").unwrap()),
                    },
                ],
            }),
            treasury_distribution: Some(nns_governance_pb::TreasuryDistribution {
                total: Some(parse_tokens("60 tokens").unwrap()),
            }),
            swap_distribution: Some(nns_governance_pb::SwapDistribution {
                total: Some(parse_tokens("40 tokens").unwrap()),
            }),
        },
    );

    assert_eq!(
        observed_create_service_nervous_system
            .ledger_parameters
            .unwrap(),
        nns_governance_pb::LedgerParameters {
            transaction_fee: Some(parse_tokens("10_000 e8s").unwrap()),
            token_name: Some("Batman".to_string()),
            token_symbol: Some("BTM".to_string()),
            token_logo: None,
        },
    );

    assert_eq!(
        observed_create_service_nervous_system
            .governance_parameters
            .unwrap(),
        nns_governance_pb::GovernanceParameters {
            // Proposal Parameters
            // -------------------
            proposal_rejection_fee: Some(parse_tokens("1 token").unwrap()),
            proposal_initial_voting_period: Some(parse_duration("4d").unwrap()),
            proposal_wait_for_quiet_deadline_increase: Some(parse_duration("1 day").unwrap()),

            // Neuron Parameters
            // -----------------
            neuron_minimum_stake: Some(parse_tokens("10 tokens").unwrap()),

            neuron_minimum_dissolve_delay_to_vote: Some(parse_duration("26 weeks").unwrap()),
            neuron_maximum_dissolve_delay: Some(parse_duration("8 years").unwrap()),
            neuron_maximum_dissolve_delay_bonus: Some(parse_percentage("100%").unwrap()),

            neuron_maximum_age_for_age_bonus: Some(parse_duration("4 years").unwrap()),
            neuron_maximum_age_bonus: Some(parse_percentage("25%").unwrap()),

            // Voting Reward(s) Parameters
            // ---------------------------
            voting_reward_parameters: Some(nns_governance_pb::VotingRewardParameters {
                initial_reward_rate: Some(parse_percentage("10%").unwrap()),
                final_reward_rate: Some(parse_percentage("2.25%").unwrap()),
                reward_rate_transition_duration: Some(parse_duration("12 years").unwrap()),
            }),
        },
    );

    assert_eq!(
        observed_create_service_nervous_system
            .swap_parameters
            .unwrap(),
        nns_governance_pb::SwapParameters {
            minimum_participants: Some(57),

            minimum_icp: Some(parse_tokens("232_714 tokens").unwrap()),
            maximum_icp: Some(parse_tokens("557_054 tokens").unwrap()),

            minimum_participant_icp: Some(parse_tokens("5 tokens").unwrap()),
            maximum_participant_icp: Some(parse_tokens("100 tokens").unwrap()),

            confirmation_text: Some("Hello, world?".to_string()),

            restricted_countries: Some(nervous_system_pb::Countries {
                iso_codes: vec!["US".to_string(), "CH".to_string(),],
            }),

            neuron_basket_construction_parameters: Some(
                nns_governance_pb::NeuronBasketConstructionParameters {
                    count: Some(83),
                    dissolve_delay_interval: Some(parse_duration("17 days").unwrap()),
                }
            ),

            start_time: nervous_system_pb::GlobalTimeOfDay::from_hh_mm(12, 0).ok(),
            duration: Some(nervous_system_pb::Duration {
                seconds: Some(7 * 24 * 60 * 60),
            }),
        }
    );
}
