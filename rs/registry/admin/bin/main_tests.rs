use super::*;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use ic_types::PrincipalId;
use pretty_assertions::assert_eq;

#[test]
fn convert_from_flags_to_create_service_nervous_system() {
    let logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";
    let token_logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAAAAAAEAAEvUrSNAAAAAElFTkSuQmCC";
    assert_ne!(logo, token_logo);

    let flags = ProposeToCreateServiceNervousSystemCmd::parse_from([
        "propose-to-create-service-nervous-system",
        "--name",
        "Daniel Wong",
        "--description",
        "The best software engineer at DFINITY.",
        "--url",
        "https://www.example.com",
        "--logo",
        logo,
        "--fallback-controller-principal-id",
        &PrincipalId::new_user_test_id(354_886).to_string(),
        "--fallback-controller-principal-id",
        &PrincipalId::new_user_test_id(354_887).to_string(),
        "--dapp-canister",
        &CanisterId::from_u64(800_219).to_string(),
        "--dapp-canister",
        &CanisterId::from_u64(800_220).to_string(),
        // Developer 1
        "--developer-neuron-controller",
        &PrincipalId::new_user_test_id(308_651).to_string(),
        "--developer-neuron-dissolve-delay",
        "52w",
        "--developer-neuron-memo",
        "0",
        "--developer-neuron-stake",
        "100_tokens",
        "--developer-neuron-vesting-period",
        "104w",
        // Developer 2
        "--developer-neuron-controller",
        &PrincipalId::new_user_test_id(598_815).to_string(),
        "--developer-neuron-dissolve-delay",
        "26w",
        "--developer-neuron-memo",
        "1",
        "--developer-neuron-stake",
        "101_tokens",
        "--developer-neuron-vesting-period",
        "52w",
        "--treasury-amount",
        "1_000_tokens",
        "--swap-amount",
        "1_234_tokens",
        "--swap-minimum-participants",
        "42",
        "--swap-minimum-direct-participation-icp",
        "123_tokens",
        "--swap-maximum-direct-participation-icp",
        "65000_tokens",
        "--swap-minimum-participant-icp",
        "650_tokens",
        "--swap-maximum-participant-icp",
        "6500_tokens",
        "--confirmation-text",
        "I confirm that I am a human",
        "--restrict-swap-in-country",
        "CH",
        "--restrict-swap-in-country",
        "US",
        "--swap-neuron-count",
        "3",
        "--swap-neuron-dissolve-delay",
        "6w",
        "--swap-start-time",
        "10:01 UTC",
        "--swap-duration",
        "7 days",
        "--neurons-fund-participation",
        "--transaction-fee",
        "10_000_e8s",
        "--token-name",
        "Legitimate Integration Techniques",
        "--token-symbol",
        "LIT",
        "--token-logo-url",
        token_logo,
        "--proposal-rejection-fee",
        "0.1_tokens",
        "--proposal-initial-voting-period",
        "1d",
        "--proposal-wait-for-quiet-deadline-increase",
        "1h",
        "--neuron-minimum-stake",
        "1_tokens",
        "--neuron-minimum-dissolve-delay-to-vote",
        "4w",
        "--neuron-maximum-dissolve-delay",
        "1461d", // 4 year (including leap day)
        "--neuron-maximum-dissolve-delay-bonus",
        "50%",
        "--neuron-maximum-age-for-age-bonus",
        "2922d", // 8 years (including leap days)
        "--neuron-maximum-age-bonus",
        "10%",
        "--initial-voting-reward-rate",
        "10.5%",
        "--final-voting-reward-rate",
        "5.25%",
        "--voting-reward-rate-transition-duration",
        "4383d", // 12 years (including leap days).
    ]);

    let result = CreateServiceNervousSystem::try_from(flags).unwrap();

    assert_eq!(
        CreateServiceNervousSystem {
            initial_token_distribution: None, // We'll inspect this separately, because it's kinda big.
            ..result
        },
        CreateServiceNervousSystem {
            name: Some("Daniel Wong".to_string()),
            description: Some("The best software engineer at DFINITY.".to_string()),
            url: Some("https://www.example.com".to_string()),
            logo: Some(nervous_system_pb::Image {
                base64_encoding: Some(logo.to_string())
            }),

            fallback_controller_principal_ids: vec![
                PrincipalId::new_user_test_id(354_886),
                PrincipalId::new_user_test_id(354_887)
            ],
            dapp_canisters: vec![
                nervous_system_pb::Canister {
                    id: Some(PrincipalId::from(CanisterId::from_u64(800_219))),
                },
                nervous_system_pb::Canister {
                    id: Some(PrincipalId::from(CanisterId::from_u64(800_220)))
                }
            ],
            swap_parameters: Some(SwapParameters {
                minimum_participants: Some(42),
                minimum_direct_participation_icp: Some(nervous_system_pb::Tokens::from_tokens(123)),
                maximum_direct_participation_icp: Some(nervous_system_pb::Tokens::from_tokens(
                    65000
                )),
                minimum_participant_icp: Some(nervous_system_pb::Tokens::from_tokens(650)),
                maximum_participant_icp: Some(nervous_system_pb::Tokens::from_tokens(6500)),
                neuron_basket_construction_parameters: Some(
                    swap_parameters::NeuronBasketConstructionParameters {
                        count: Some(3),
                        dissolve_delay_interval: Some(nervous_system_pb::Duration {
                            seconds: Some(6 * 7 * ONE_DAY_SECONDS),
                        }),
                    }
                ),
                confirmation_text: Some("I confirm that I am a human".to_string()),
                restricted_countries: Some(nervous_system_pb::Countries {
                    iso_codes: vec!["CH".to_string(), "US".to_string()],
                }),
                start_time: nervous_system_pb::GlobalTimeOfDay::from_hh_mm(10, 1).ok(),
                duration: Some(nervous_system_pb::Duration {
                    seconds: Some(7 * ONE_DAY_SECONDS),
                }),
                neurons_fund_participation: Some(true),
                // Deprecated fields
                minimum_icp: None,
                maximum_icp: None,
                neurons_fund_investment_icp: None,
            }),
            ledger_parameters: Some(LedgerParameters {
                transaction_fee: Some(nervous_system_pb::Tokens { e8s: Some(10_000) }),
                token_name: Some("Legitimate Integration Techniques".to_string()),
                token_symbol: Some("LIT".to_string()),
                token_logo: Some(nervous_system_pb::Image {
                    base64_encoding: Some(token_logo.to_string()),
                }),
            }),
            governance_parameters: Some(GovernanceParameters {
                proposal_rejection_fee: Some(nervous_system_pb::Tokens { e8s: Some(E8 / 10) }),
                proposal_initial_voting_period: Some(nervous_system_pb::Duration {
                    seconds: Some(ONE_DAY_SECONDS),
                }),
                proposal_wait_for_quiet_deadline_increase: Some(nervous_system_pb::Duration {
                    seconds: Some(60 * 60),
                }),

                neuron_minimum_stake: Some(nervous_system_pb::Tokens { e8s: Some(E8) }),
                neuron_minimum_dissolve_delay_to_vote: Some(nervous_system_pb::Duration {
                    seconds: Some(4 * 7 * ONE_DAY_SECONDS),
                }),
                neuron_maximum_dissolve_delay: Some(nervous_system_pb::Duration {
                    seconds: Some(1461 * ONE_DAY_SECONDS),
                }),
                neuron_maximum_dissolve_delay_bonus: Some(nervous_system_pb::Percentage {
                    basis_points: Some(50_00),
                }),
                neuron_maximum_age_for_age_bonus: Some(nervous_system_pb::Duration {
                    seconds: Some(2922 * ONE_DAY_SECONDS),
                }),
                neuron_maximum_age_bonus: Some(nervous_system_pb::Percentage {
                    basis_points: Some(10_00),
                }),

                voting_reward_parameters: Some(VotingRewardParameters {
                    initial_reward_rate: Some(nervous_system_pb::Percentage {
                        basis_points: Some(10_50),
                    }),
                    final_reward_rate: Some(nervous_system_pb::Percentage {
                        basis_points: Some(5_25),
                    }),
                    reward_rate_transition_duration: Some(nervous_system_pb::Duration {
                        seconds: Some(4383 * ONE_DAY_SECONDS),
                    }),
                }),
            }),

            initial_token_distribution: None,
        }
    );

    assert_eq!(
        result.initial_token_distribution.unwrap(),
        InitialTokenDistribution {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![
                    NeuronDistribution {
                        controller: Some(PrincipalId::new_user_test_id(308_651)),
                        dissolve_delay: Some(nervous_system_pb::Duration {
                            seconds: Some(52 * 7 * ONE_DAY_SECONDS),
                        }),
                        memo: Some(0),
                        stake: Some(nervous_system_pb::Tokens {
                            e8s: Some(100 * E8),
                        }),
                        vesting_period: Some(nervous_system_pb::Duration {
                            seconds: Some(104 * 7 * ONE_DAY_SECONDS),
                        }),
                    },
                    NeuronDistribution {
                        controller: Some(PrincipalId::new_user_test_id(598_815)),
                        dissolve_delay: Some(nervous_system_pb::Duration {
                            seconds: Some(26 * 7 * ONE_DAY_SECONDS),
                        }),
                        memo: Some(1),
                        stake: Some(nervous_system_pb::Tokens {
                            e8s: Some(101 * E8),
                        }),
                        vesting_period: Some(nervous_system_pb::Duration {
                            seconds: Some(52 * 7 * ONE_DAY_SECONDS),
                        }),
                    }
                ],
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total: Some(nervous_system_pb::Tokens {
                    e8s: Some(1_000 * E8),
                })
            }),
            swap_distribution: Some(SwapDistribution {
                total: Some(nervous_system_pb::Tokens {
                    e8s: Some(1_234 * E8),
                })
            }),
        }
    );
}

#[test]
fn convert_from_flags_to_create_service_nervous_system_without_start_time() {
    let logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";
    let token_logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAAAAAAEAAEvUrSNAAAAAElFTkSuQmCC";
    assert_ne!(logo, token_logo);

    let flags = ProposeToCreateServiceNervousSystemCmd::parse_from([
        "propose-to-create-service-nervous-system",
        "--name",
        "Daniel Wong",
        "--description",
        "The best software engineer at DFINITY.",
        "--url",
        "https://www.example.com",
        "--logo",
        logo,
        "--fallback-controller-principal-id",
        &PrincipalId::new_user_test_id(354_886).to_string(),
        "--fallback-controller-principal-id",
        &PrincipalId::new_user_test_id(354_887).to_string(),
        "--dapp-canister",
        &CanisterId::from_u64(800_219).to_string(),
        "--dapp-canister",
        &CanisterId::from_u64(800_220).to_string(),
        // Developer 1
        "--developer-neuron-controller",
        &PrincipalId::new_user_test_id(308_651).to_string(),
        "--developer-neuron-dissolve-delay",
        "52w",
        "--developer-neuron-memo",
        "0",
        "--developer-neuron-stake",
        "100_tokens",
        "--developer-neuron-vesting-period",
        "104w",
        // Developer 2
        "--developer-neuron-controller",
        &PrincipalId::new_user_test_id(598_815).to_string(),
        "--developer-neuron-dissolve-delay",
        "26w",
        "--developer-neuron-memo",
        "1",
        "--developer-neuron-stake",
        "101_tokens",
        "--developer-neuron-vesting-period",
        "52w",
        "--treasury-amount",
        "1_000_tokens",
        "--swap-amount",
        "1_234_tokens",
        "--swap-minimum-participants",
        "42",
        "--swap-minimum-direct-participation-icp",
        "123_tokens",
        "--swap-maximum-direct-participation-icp",
        "65000_tokens",
        "--swap-minimum-participant-icp",
        "650_tokens",
        "--swap-maximum-participant-icp",
        "6500_tokens",
        "--confirmation-text",
        "I confirm that I am a human",
        "--restrict-swap-in-country",
        "CH",
        "--restrict-swap-in-country",
        "US",
        "--swap-neuron-count",
        "3",
        "--swap-neuron-dissolve-delay",
        "6w",
        "--swap-duration",
        "7 days",
        "--neurons-fund-participation",
        "--transaction-fee",
        "10_000_e8s",
        "--token-name",
        "Legitimate Integration Techniques",
        "--token-symbol",
        "LIT",
        "--token-logo-url",
        token_logo,
        "--proposal-rejection-fee",
        "0.1_tokens",
        "--proposal-initial-voting-period",
        "1d",
        "--proposal-wait-for-quiet-deadline-increase",
        "1h",
        "--neuron-minimum-stake",
        "1_tokens",
        "--neuron-minimum-dissolve-delay-to-vote",
        "4w",
        "--neuron-maximum-dissolve-delay",
        "1461d", // 4 year (including leap day)
        "--neuron-maximum-dissolve-delay-bonus",
        "50%",
        "--neuron-maximum-age-for-age-bonus",
        "2922d", // 8 years (including leap days)
        "--neuron-maximum-age-bonus",
        "10%",
        "--initial-voting-reward-rate",
        "10.5%",
        "--final-voting-reward-rate",
        "5.25%",
        "--voting-reward-rate-transition-duration",
        "4383d", // 12 years (including leap days).
    ]);

    let result = CreateServiceNervousSystem::try_from(flags).unwrap();

    assert_eq!(result.swap_parameters.unwrap().start_time, None);
}
