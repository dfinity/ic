use super::*;

use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
use pretty_assertions::assert_eq;

#[test]
fn test_parse_percentage() {
    assert_eq!(
        parse_percentage("0%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(0)
        }),
    );
    assert_eq!(
        parse_percentage("1%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.0%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.00%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.2%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(120)
        }),
    );
    assert_eq!(
        parse_percentage("1.23%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(123)
        }),
    );
    assert_eq!(
        parse_percentage("0.1%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(10)
        }),
    );
    assert_eq!(
        parse_percentage("0.12%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(12)
        }),
    );
    assert_eq!(
        parse_percentage("0.07%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(7)
        }),
    );

    // Dot must be surrounded.
    let result = parse_percentage("0.%");
    assert!(result.is_err(), "{:?}", result);

    let result = parse_percentage(".1%");
    assert!(result.is_err(), "{:?}", result);

    // Too many decimal places.
    let result = parse_percentage("0.009%");
    assert!(result.is_err(), "{:?}", result);

    // Percent sign required.
    let result = parse_percentage("1.0");
    assert!(result.is_err(), "{:?}", result);
}

#[test]
fn test_parse_tokens() {
    assert_eq!(
        parse_tokens("1e8s"),
        Ok(nervous_system_pb::Tokens { e8s: Some(1) }),
    );
    assert_eq!(
        parse_tokens("1T"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(100_000_000)
        }),
    );
    assert_eq!(
        parse_tokens("1_.23_4_T"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(123_400_000)
        }),
    );
    assert_eq!(
        parse_tokens("_123_456_789_e8s"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(123456789)
        }),
    );
}

#[test]
fn convert_from_flags_to_create_service_nervous_system() {
    let logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";
    let token_logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAAAAAAEAAEvUrSNAAAAAElFTkSuQmCC";
    assert_ne!(logo, token_logo);

    let flags = ProposeToCreateServiceNervousSystemCmd::parse_from(
        [
            "propose-to-create-service-nervous-system",
            "--name",
            "Daniel Wong",
            "--description",
            "The best software engineer at DFINITY.",
            "--url",
            "https://www.example.com",
            "--logo",
            logo,
            "--fallback-controller-principal-ids",
            &PrincipalId::new_user_test_id(354_886).to_string(),
            "--dapp-canisters",
            &CanisterId::from_u64(800_219).to_string(),
            // Developer 1
            "--developer-neuron-controller",
            &PrincipalId::new_user_test_id(308_651).to_string(),
            "--developer-neuron-dissolve-delay",
            "52w",
            "--developer-neuron-memo",
            "0",
            "--developer-neuron-stake",
            "100_T",
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
            "101_T",
            "--developer-neuron-vesting-period",
            "52w",
            "--treasury-amount",
            "1_000_T",
            "--swap-amount",
            "1_234_T",
            "--swap-minimum-participants",
            "42",
            "--swap-minimum-icp",
            "250_T",
            "--swap-maximum-icp",
            "1000_T",
            "--swap-minimum-participant-icp",
            "2_T",
            "--swap-maximum-participant-icp",
            "100_T",
            "--swap-neuron-count",
            "3",
            "--swap-neuron-dissolve-delay",
            "6w",
            "--transaction-fee",
            "10_000_e8s",
            "--token-name",
            "Legitimate Integration Techniques",
            "--token-symbol",
            "LIT",
            "--token-logo-url",
            token_logo,
            "--proposal-rejection-fee",
            "0.1_T",
            "--proposal-initial-voting-period",
            "1d",
            "--proposal-wait-for-quiet-deadline-increase",
            "1h",
            "--neuron-minimum-stake",
            "1_T",
            "--neuron-minimum-dissolve-delay-to-vote",
            "4w",
            "--neuron-maximum-dissolve-delay",
            "1461d", // 4 year (including leap day)
            "--neuron-maximum-dissolve-delay-bonus",
            "50%",
            "--neuron-maximum-age-for-age-bonus",
            "2922d", // 8 years (including lear days)
            "--neuron-maximum-age-bonus",
            "10%",
            "--initial-voting-reward-rate",
            "10.5%",
            "--final-voting-reward-rate",
            "5.25%",
            "--voting-reward-rate-transition-duration",
            "4383d", // 12 years (including leap days).
        ]
        .into_iter(),
    );

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

            fallback_controller_principal_ids: vec![PrincipalId::new_user_test_id(354_886)],
            dapp_canisters: vec![nervous_system_pb::Canister {
                id: Some(PrincipalId::try_from(CanisterId::from_u64(800_219)).unwrap()),
            },],
            swap_parameters: Some(SwapParameters {
                minimum_participants: Some(42),
                minimum_icp: Some(nervous_system_pb::Tokens {
                    e8s: Some(250 * E8),
                }),
                maximum_icp: Some(nervous_system_pb::Tokens {
                    e8s: Some(1_000 * E8),
                }),
                minimum_participant_icp: Some(nervous_system_pb::Tokens { e8s: Some(2 * E8) }),
                maximum_participant_icp: Some(nervous_system_pb::Tokens {
                    e8s: Some(100 * E8),
                }),
                neuron_basket_construction_parameters: Some(
                    swap_parameters::NeuronBasketConstructionParameters {
                        count: Some(3),
                        dissolve_delay_interval: Some(nervous_system_pb::Duration {
                            seconds: Some(6 * 7 * SECONDS_PER_DAY),
                        }),
                    }
                ),
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
                    seconds: Some(SECONDS_PER_DAY),
                }),
                proposal_wait_for_quiet_deadline_increase: Some(nervous_system_pb::Duration {
                    seconds: Some(60 * 60),
                }),

                neuron_minimum_stake: Some(nervous_system_pb::Tokens { e8s: Some(E8) }),
                neuron_minimum_dissolve_delay_to_vote: Some(nervous_system_pb::Duration {
                    seconds: Some(4 * 7 * SECONDS_PER_DAY),
                }),
                neuron_maximum_dissolve_delay: Some(nervous_system_pb::Duration {
                    seconds: Some(1461 * SECONDS_PER_DAY),
                }),
                neuron_maximum_dissolve_delay_bonus: Some(nervous_system_pb::Percentage {
                    basis_points: Some(50_00),
                }),
                neuron_maximum_age_for_age_bonus: Some(nervous_system_pb::Duration {
                    seconds: Some(2922 * SECONDS_PER_DAY),
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
                        seconds: Some(4383 * SECONDS_PER_DAY),
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
                            seconds: Some(52 * 7 * SECONDS_PER_DAY),
                        }),
                        memo: Some(0),
                        stake: Some(nervous_system_pb::Tokens {
                            e8s: Some(100 * E8),
                        }),
                        vesting_period: Some(nervous_system_pb::Duration {
                            seconds: Some(104 * 7 * SECONDS_PER_DAY),
                        }),
                    },
                    NeuronDistribution {
                        controller: Some(PrincipalId::new_user_test_id(598_815)),
                        dissolve_delay: Some(nervous_system_pb::Duration {
                            seconds: Some(26 * 7 * SECONDS_PER_DAY),
                        }),
                        memo: Some(1),
                        stake: Some(nervous_system_pb::Tokens {
                            e8s: Some(101 * E8),
                        }),
                        vesting_period: Some(nervous_system_pb::Duration {
                            seconds: Some(52 * 7 * SECONDS_PER_DAY),
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
