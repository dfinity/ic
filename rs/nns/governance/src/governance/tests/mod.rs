use super::*;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{
        governance::{followers_map::Followers, FollowersMap},
        neuron::DissolveState,
        Neuron as NeuronProto,
    },
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::{assert_is_err, assert_is_ok, E8};
#[cfg(feature = "test")]
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use ic_nns_common::pb::v1::NeuronId;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
#[cfg(feature = "test")]
use ic_sns_init::pb::v1::SnsInitPayload;
#[cfg(feature = "test")]
use ic_sns_init::pb::v1::{self as sns_init_pb};
use lazy_static::lazy_static;
use maplit::{btreemap, hashmap};
use std::convert::TryFrom;

mod neurons_fund;
mod node_provider_rewards;
mod stake_maturity;

#[test]
fn test_time_warp() {
    let w = TimeWarp { delta_s: 0_i64 };
    assert_eq!(w.apply(100_u64), 100);

    let w = TimeWarp { delta_s: 42_i64 };
    assert_eq!(w.apply(100_u64), 142);

    let w = TimeWarp { delta_s: -42_i64 };
    assert_eq!(w.apply(100_u64), 58);
}

mod settle_neurons_fund_participation_request_tests {
    use settle_neurons_fund_participation_request::{Aborted, Committed, Result};
    use SettleNeuronsFundParticipationRequest;

    use super::*;

    lazy_static! {
        static ref COMMITTED: SettleNeuronsFundParticipationRequest =
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                }))
            };
        static ref ABORTED: SettleNeuronsFundParticipationRequest =
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(42),
                result: Some(Result::Aborted(Aborted {}))
            };
    }

    #[test]
    fn ok() {
        assert_is_ok!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            COMMITTED.clone()
        ));
        assert_is_ok!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            ABORTED.clone()
        ));
    }

    #[test]
    fn no_proposal_id() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_result() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                result: None,
                ..COMMITTED.clone()
            }
        ));
    }

    #[test]
    fn no_sns_governance_canister_id() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: None,
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            }
        ));
    }

    #[test]
    fn no_total_direct_participation_icp_e8s() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: None,
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            }
        ));
    }

    #[test]
    fn no_total_neurons_fund_participation_icp_e8s() {
        assert_is_err!(ValidatedSettleNeuronsFundParticipationRequest::try_from(
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(7),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(PrincipalId::new_user_test_id(672891)),
                    total_direct_participation_icp_e8s: Some(100_000 * E8),
                    total_neurons_fund_participation_icp_e8s: None,
                })),
            }
        ));
    }
} // end mod settle_neurons_fund_participation_request_tests

#[cfg(feature = "test")]
mod settle_neurons_fund_participation_mem_tests {
    use crate::{
        governance::MAX_NEURONS_FUND_PARTICIPANTS,
        neurons_fund::{
            neurons_fund_neuron::MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON, NeuronsFundNeuronPortion,
            NeuronsFundSnapshot,
        },
        pb::v1 as gov_pb,
    };
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::NeuronId;
    use ic_nns_governance_api::pb::v1::SettleNeuronsFundParticipationResponse;

    fn make_dummy_neuron_portion() -> NeuronsFundNeuronPortion {
        NeuronsFundNeuronPortion {
            id: Default::default(),
            hotkeys: Default::default(),
            controller: Default::default(),
            amount_icp_e8s: 1_000_000_000,
            maturity_equivalent_icp_e8s: 1_000_000_000,
            is_capped: false,
        }
    }

    /// This test ensures that the number of bytes representing the response payload of
    /// `NnsGov.settle_neurons_fund_participation` is (worst-case) within IC ingress message limits.
    /// See https://internetcomputer.org/docs/current/developer-docs/smart-contracts/maintain/resource-limits
    #[test]
    fn settle_neurons_fund_participation_ingress_mem_limits_pass() {
        let neurons = (0..MAX_NEURONS_FUND_PARTICIPANTS).map(|id| {
            let hotkeys = (0..(MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON as u64))
                .map(|k| PrincipalId::new_user_test_id(MAX_NEURONS_FUND_PARTICIPANTS + k))
                .collect();

            NeuronsFundNeuronPortion {
                hotkeys,
                id: NeuronId { id },
                ..make_dummy_neuron_portion()
            }
        });
        let response = Ok(NeuronsFundSnapshot::new(neurons));
        let intermediate = gov_pb::SettleNeuronsFundParticipationResponse::from(response);
        let payload = SettleNeuronsFundParticipationResponse::from(intermediate);
        let bytes = candid::encode_args((payload,)).unwrap();
        assert!(bytes.len() < 2_000_000);
    }

    /// This test may be adjusted slightly; it is here to help monitor the potentially unbounded
    /// `NnsGov.settle_neurons_fund_participation` response payload byte size.
    #[test]
    fn settle_neurons_fund_participation_ingress_mem_limits_worst_case_bound() {
        let neurons = (0..MAX_NEURONS_FUND_PARTICIPANTS).map(|id| {
            let hotkeys = (0..(MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON as u64))
                .map(|k| PrincipalId::new_user_test_id(MAX_NEURONS_FUND_PARTICIPANTS + k))
                .collect();

            NeuronsFundNeuronPortion {
                id: NeuronId { id },
                hotkeys,
                ..make_dummy_neuron_portion()
            }
        });
        let response = Ok(NeuronsFundSnapshot::new(neurons));
        let intermediate = gov_pb::SettleNeuronsFundParticipationResponse::from(response);
        let payload = SettleNeuronsFundParticipationResponse::from(intermediate);
        let bytes = candid::encode_args((payload,)).unwrap();
        // The following bound is obtained experimentally.
        let expected_bytes_cap = 620_113;
        assert!(
            bytes.len() < expected_bytes_cap,
            "The bytes.len() = {}, expected_bytes_cap = {}",
            bytes.len(),
            expected_bytes_cap
        );
    }
}

#[cfg(feature = "test")]
mod convert_from_create_service_nervous_system_to_sns_init_payload_tests {
    use super::*;
    use ic_nervous_system_proto::pb::v1 as pb;
    use ic_sns_init::pb::v1::sns_init_payload;
    use ic_sns_swap::pb::v1::NeuronBasketConstructionParameters;
    use test_data::{CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING, IMAGE_1, IMAGE_2};

    // Alias types from crate::pb::v1::...
    //
    // This is done within another mod to differentiate against types that have
    // similar names as types found in ic_sns_init.
    mod src {
        pub use crate::pb::v1::create_service_nervous_system::initial_token_distribution::SwapDistribution;
    }

    #[track_caller]
    fn unwrap_duration_seconds(original: &Option<pb::Duration>) -> Option<u64> {
        Some(original.as_ref().unwrap().seconds.unwrap())
    }

    #[track_caller]
    fn unwrap_tokens_e8s(original: &Option<pb::Tokens>) -> Option<u64> {
        Some(original.as_ref().unwrap().e8s.unwrap())
    }

    #[track_caller]
    fn unwrap_percentage_basis_points(original: &Option<pb::Percentage>) -> Option<u64> {
        Some(original.as_ref().unwrap().basis_points.unwrap())
    }

    #[test]
    fn test_convert_from_valid() {
        // Step 1: Prepare the world. (In this case, trivial.)

        // Step 2: Call the code under test.
        let converted =
            SnsInitPayload::try_from(CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone())
                .unwrap();

        // Step 3: Inspect the result.

        let original_ledger_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .ledger_parameters
            .as_ref()
            .unwrap();
        let original_governance_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .governance_parameters
            .as_ref()
            .unwrap();

        let original_voting_reward_parameters: &_ = original_governance_parameters
            .voting_reward_parameters
            .as_ref()
            .unwrap();

        let original_swap_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .swap_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            SnsInitPayload {
                // We'll look at this separately.
                initial_token_distribution: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                nns_proposal_id: None,
                neuron_basket_construction_parameters: None,
                ..converted
            },
            SnsInitPayload {
                transaction_fee_e8s: unwrap_tokens_e8s(&original_ledger_parameters.transaction_fee),
                token_name: Some(original_ledger_parameters.clone().token_name.unwrap()),
                token_symbol: Some(original_ledger_parameters.clone().token_symbol.unwrap()),
                token_logo: Some(IMAGE_2.to_string()),

                proposal_reject_cost_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.proposal_rejection_fee
                ),

                neuron_minimum_stake_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.neuron_minimum_stake
                ),

                fallback_controller_principal_ids:
                    CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                        .fallback_controller_principal_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect(),

                logo: Some(IMAGE_1.to_string(),),
                url: Some("https://best.app".to_string(),),
                name: Some("Hello, world!".to_string(),),
                description: Some("Best app that you ever did saw.".to_string(),),

                neuron_minimum_dissolve_delay_to_vote_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_minimum_dissolve_delay_to_vote
                ),

                initial_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.initial_reward_rate
                ),
                final_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.final_reward_rate
                ),
                reward_rate_transition_duration_seconds: unwrap_duration_seconds(
                    &original_voting_reward_parameters.reward_rate_transition_duration
                ),

                max_dissolve_delay_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_dissolve_delay
                ),

                max_neuron_age_seconds_for_age_bonus: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_age_for_age_bonus
                ),

                max_dissolve_delay_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_dissolve_delay_bonus
                )
                .map(|basis_points| basis_points / 100),

                max_age_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_age_bonus
                )
                .map(|basis_points| basis_points / 100),

                initial_voting_period_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_initial_voting_period
                ),
                wait_for_quiet_deadline_increase_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_wait_for_quiet_deadline_increase
                ),
                dapp_canisters: Some(sns_init_pb::DappCanisters {
                    canisters: vec![pb::Canister {
                        id: Some(CanisterId::from_u64(1000).get()),
                    }],
                }),
                min_participants: original_swap_parameters.minimum_participants,
                min_icp_e8s: None,
                max_icp_e8s: None,
                min_direct_participation_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_direct_participation_icp
                ),
                max_direct_participation_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_direct_participation_icp
                ),
                min_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_participant_icp
                ),
                max_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_participant_icp
                ),

                confirmation_text: original_swap_parameters.confirmation_text.clone(),
                restricted_countries: original_swap_parameters.restricted_countries.clone(),
                neurons_fund_participation: original_swap_parameters.neurons_fund_participation,

                // We'll examine these later
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                nns_proposal_id: None,
                neurons_fund_participation_constraints: None,
            },
        );

        let original_initial_token_distribution: &_ =
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                .initial_token_distribution
                .as_ref()
                .unwrap();
        let original_developer_distribution: &_ = original_initial_token_distribution
            .developer_distribution
            .as_ref()
            .unwrap();
        assert_eq!(
            original_developer_distribution.developer_neurons.len(),
            1,
            "{:#?}",
            original_developer_distribution.developer_neurons,
        );
        let original_neuron_distribution: &_ = original_developer_distribution
            .developer_neurons
            .first()
            .unwrap();

        let src::SwapDistribution { total: swap_total } = original_initial_token_distribution
            .swap_distribution
            .as_ref()
            .unwrap();
        let swap_total_e8s = unwrap_tokens_e8s(swap_total).unwrap();
        assert_eq!(swap_total_e8s, 1_840_880_000);

        assert_eq!(
            converted.initial_token_distribution.unwrap(),
            sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower(
                sns_init_pb::FractionalDeveloperVotingPower {
                    developer_distribution: Some(sns_init_pb::DeveloperDistribution {
                        developer_neurons: vec![sns_init_pb::NeuronDistribution {
                            controller: Some(original_neuron_distribution.controller.unwrap()),

                            stake_e8s: unwrap_tokens_e8s(&original_neuron_distribution.stake)
                                .unwrap(),

                            memo: original_neuron_distribution.memo.unwrap(),

                            dissolve_delay_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.dissolve_delay
                            )
                            .unwrap(),

                            vesting_period_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.vesting_period
                            ),
                        },],
                    },),
                    treasury_distribution: Some(sns_init_pb::TreasuryDistribution {
                        total_e8s: unwrap_tokens_e8s(
                            &original_initial_token_distribution
                                .treasury_distribution
                                .as_ref()
                                .unwrap()
                                .total
                        )
                        .unwrap(),
                    },),
                    swap_distribution: Some(sns_init_pb::SwapDistribution {
                        // These are intentionally the same.
                        total_e8s: swap_total_e8s,
                        initial_swap_amount_e8s: swap_total_e8s,
                    },),
                    airdrop_distribution: Some(sns_init_pb::AirdropDistribution {
                        airdrop_neurons: vec![],
                    },),
                },
            ),
        );

        let original_neuron_basket_construction_parameters =
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                .swap_parameters
                .as_ref()
                .unwrap()
                .neuron_basket_construction_parameters
                .as_ref()
                .unwrap();

        assert_eq!(
            converted.neuron_basket_construction_parameters.unwrap(),
            NeuronBasketConstructionParameters {
                count: original_neuron_basket_construction_parameters
                    .count
                    .unwrap(),
                dissolve_delay_interval_seconds: unwrap_duration_seconds(
                    &original_neuron_basket_construction_parameters.dissolve_delay_interval
                )
                .unwrap(),
            }
        );

        assert_eq!(converted.nns_proposal_id, None);
        assert_eq!(converted.swap_start_timestamp_seconds, None);
        assert_eq!(converted.swap_due_timestamp_seconds, None);
    }

    #[test]
    fn test_convert_from_invalid() {
        // Step 1: Prepare the world: construct input.
        let mut original = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
        let governance_parameters = original.governance_parameters.as_mut().unwrap();

        // Corrupt the data. The problem with this is that wait for quiet extension
        // amount cannot be more than half the initial voting period.
        governance_parameters.proposal_wait_for_quiet_deadline_increase = governance_parameters
            .proposal_initial_voting_period
            .as_ref()
            .map(|duration| {
                let seconds = Some(duration.seconds.unwrap() / 2 + 1);
                pb::Duration { seconds }
            });

        // Step 2: Call the code under test.
        let converted = SnsInitPayload::try_from(original);

        // Step 3: Inspect the result: Err must contain "wait for quiet".
        match converted {
            Ok(ok) => panic!("Invalid data was not rejected. Result: {:#?}", ok),
            Err(err) => assert!(err.contains("wait_for_quiet"), "{}", err),
        }
    }
}

#[cfg(feature = "test")]
mod convert_create_service_nervous_system_proposal_to_sns_init_payload_tests_with_test_feature {
    use super::*;
    use ic_nervous_system_proto::pb::v1 as pb;
    use ic_sns_init::pb::v1::sns_init_payload;
    use ic_sns_swap::pb::v1::NeuronBasketConstructionParameters;
    use test_data::{CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING, IMAGE_1, IMAGE_2};

    // Alias types from crate::pb::v1::...
    //
    // This is done within another mod to differentiate against types that have
    // similar names as types found in ic_sns_init.
    mod src {
        pub use crate::pb::v1::create_service_nervous_system::initial_token_distribution::SwapDistribution;
    }

    #[track_caller]
    fn unwrap_duration_seconds(original: &Option<pb::Duration>) -> Option<u64> {
        Some(original.as_ref().unwrap().seconds.unwrap())
    }

    #[track_caller]
    fn unwrap_tokens_e8s(original: &Option<pb::Tokens>) -> Option<u64> {
        Some(original.as_ref().unwrap().e8s.unwrap())
    }

    #[track_caller]
    fn unwrap_percentage_basis_points(original: &Option<pb::Percentage>) -> Option<u64> {
        Some(original.as_ref().unwrap().basis_points.unwrap())
    }

    #[test]
    fn test_convert_from_valid() {
        // Step 1: Prepare the world. (In this case, trivial.)

        use crate::governance::test_data::NEURONS_FUND_PARTICIPATION_CONSTRAINTS;
        let current_timestamp_seconds = 13_245;
        let proposal_id = 1000;

        // Step 2: Call the code under test.
        let converted = {
            let create_service_nervous_system =
                CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
            // The computation for swap_start_timestamp_seconds and swap_due_timestamp_seconds below
            // is inlined from `Governance::make_sns_init_payload`.
            let (swap_start_timestamp_seconds, swap_due_timestamp_seconds) = {
                let random_swap_start_time = GlobalTimeOfDay {
                    seconds_after_utc_midnight: Some(0),
                };

                let start_time = create_service_nervous_system
                    .swap_parameters
                    .as_ref()
                    .and_then(|swap_parameters| swap_parameters.start_time);

                let duration = create_service_nervous_system
                    .swap_parameters
                    .as_ref()
                    .and_then(|swap_parameters| swap_parameters.duration);

                CreateServiceNervousSystem::swap_start_and_due_timestamps(
                    start_time.unwrap_or(random_swap_start_time),
                    duration.unwrap_or_default(),
                    current_timestamp_seconds,
                )
                .expect("Cannot compute swap_start_timestamp_seconds, swap_due_timestamp_seconds.")
            };

            let sns_init_payload = SnsInitPayload::try_from(create_service_nervous_system).unwrap();

            SnsInitPayload {
                neurons_fund_participation_constraints: Some(
                    NEURONS_FUND_PARTICIPATION_CONSTRAINTS.clone(),
                ),
                nns_proposal_id: Some(proposal_id),
                swap_start_timestamp_seconds: Some(swap_start_timestamp_seconds),
                swap_due_timestamp_seconds: Some(swap_due_timestamp_seconds),
                ..sns_init_payload
            }
        };

        converted.validate_post_execution().unwrap();

        // Step 3: Inspect the result.

        let original_ledger_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .ledger_parameters
            .as_ref()
            .unwrap();
        let original_governance_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .governance_parameters
            .as_ref()
            .unwrap();

        let original_voting_reward_parameters: &_ = original_governance_parameters
            .voting_reward_parameters
            .as_ref()
            .unwrap();

        let original_swap_parameters: &_ = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
            .swap_parameters
            .as_ref()
            .unwrap();

        assert_eq!(
            SnsInitPayload {
                // We'll look at this separately.
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
                ..converted
            },
            SnsInitPayload {
                transaction_fee_e8s: unwrap_tokens_e8s(&original_ledger_parameters.transaction_fee),
                token_name: Some(original_ledger_parameters.clone().token_name.unwrap()),
                token_symbol: Some(original_ledger_parameters.clone().token_symbol.unwrap()),
                token_logo: Some(IMAGE_2.to_string()),

                proposal_reject_cost_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.proposal_rejection_fee
                ),

                neuron_minimum_stake_e8s: unwrap_tokens_e8s(
                    &original_governance_parameters.neuron_minimum_stake
                ),

                fallback_controller_principal_ids:
                    CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                        .fallback_controller_principal_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect(),

                logo: Some(IMAGE_1.to_string(),),
                url: Some("https://best.app".to_string(),),
                name: Some("Hello, world!".to_string(),),
                description: Some("Best app that you ever did saw.".to_string(),),

                neuron_minimum_dissolve_delay_to_vote_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_minimum_dissolve_delay_to_vote
                ),

                initial_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.initial_reward_rate
                ),
                final_reward_rate_basis_points: unwrap_percentage_basis_points(
                    &original_voting_reward_parameters.final_reward_rate
                ),
                reward_rate_transition_duration_seconds: unwrap_duration_seconds(
                    &original_voting_reward_parameters.reward_rate_transition_duration
                ),

                max_dissolve_delay_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_dissolve_delay
                ),

                max_neuron_age_seconds_for_age_bonus: unwrap_duration_seconds(
                    &original_governance_parameters.neuron_maximum_age_for_age_bonus
                ),

                max_dissolve_delay_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_dissolve_delay_bonus
                )
                .map(|basis_points| basis_points / 100),

                max_age_bonus_percentage: unwrap_percentage_basis_points(
                    &original_governance_parameters.neuron_maximum_age_bonus
                )
                .map(|basis_points| basis_points / 100),

                initial_voting_period_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_initial_voting_period
                ),
                wait_for_quiet_deadline_increase_seconds: unwrap_duration_seconds(
                    &original_governance_parameters.proposal_wait_for_quiet_deadline_increase
                ),
                dapp_canisters: Some(sns_init_pb::DappCanisters {
                    canisters: vec![pb::Canister {
                        id: Some(CanisterId::from_u64(1000).get()),
                    }],
                }),
                min_participants: original_swap_parameters.minimum_participants,
                min_icp_e8s: None,
                max_icp_e8s: None,
                min_direct_participation_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_direct_participation_icp
                ),
                max_direct_participation_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_direct_participation_icp
                ),
                min_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.minimum_participant_icp
                ),
                max_participant_icp_e8s: unwrap_tokens_e8s(
                    &original_swap_parameters.maximum_participant_icp
                ),

                confirmation_text: original_swap_parameters.confirmation_text.clone(),
                restricted_countries: original_swap_parameters.restricted_countries.clone(),
                nns_proposal_id: Some(proposal_id),
                neurons_fund_participation: Some(true),

                neurons_fund_participation_constraints: Some(
                    NEURONS_FUND_PARTICIPATION_CONSTRAINTS.clone()
                ),

                // We'll examine these later
                initial_token_distribution: None,
                neuron_basket_construction_parameters: None,
                swap_start_timestamp_seconds: None,
                swap_due_timestamp_seconds: None,
            },
        );

        let original_initial_token_distribution: &_ =
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                .initial_token_distribution
                .as_ref()
                .unwrap();
        let original_developer_distribution: &_ = original_initial_token_distribution
            .developer_distribution
            .as_ref()
            .unwrap();
        assert_eq!(
            original_developer_distribution.developer_neurons.len(),
            1,
            "{:#?}",
            original_developer_distribution.developer_neurons,
        );
        let original_neuron_distribution: &_ = original_developer_distribution
            .developer_neurons
            .first()
            .unwrap();

        let src::SwapDistribution { total: swap_total } = original_initial_token_distribution
            .swap_distribution
            .as_ref()
            .unwrap();
        let swap_total_e8s = unwrap_tokens_e8s(swap_total).unwrap();
        assert_eq!(swap_total_e8s, 1_840_880_000);

        assert_eq!(
            converted.initial_token_distribution.unwrap(),
            sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower(
                sns_init_pb::FractionalDeveloperVotingPower {
                    developer_distribution: Some(sns_init_pb::DeveloperDistribution {
                        developer_neurons: vec![sns_init_pb::NeuronDistribution {
                            controller: Some(original_neuron_distribution.controller.unwrap()),

                            stake_e8s: unwrap_tokens_e8s(&original_neuron_distribution.stake)
                                .unwrap(),

                            memo: original_neuron_distribution.memo.unwrap(),

                            dissolve_delay_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.dissolve_delay
                            )
                            .unwrap(),

                            vesting_period_seconds: unwrap_duration_seconds(
                                &original_neuron_distribution.vesting_period
                            ),
                        },],
                    },),
                    treasury_distribution: Some(sns_init_pb::TreasuryDistribution {
                        total_e8s: unwrap_tokens_e8s(
                            &original_initial_token_distribution
                                .treasury_distribution
                                .as_ref()
                                .unwrap()
                                .total
                        )
                        .unwrap(),
                    },),
                    swap_distribution: Some(sns_init_pb::SwapDistribution {
                        // These are intentionally the same.
                        total_e8s: swap_total_e8s,
                        initial_swap_amount_e8s: swap_total_e8s,
                    },),
                    airdrop_distribution: Some(sns_init_pb::AirdropDistribution {
                        airdrop_neurons: vec![],
                    },),
                },
            ),
        );

        let original_neuron_basket_construction_parameters =
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
                .swap_parameters
                .as_ref()
                .unwrap()
                .neuron_basket_construction_parameters
                .as_ref()
                .unwrap();

        assert_eq!(
            converted.neuron_basket_construction_parameters.unwrap(),
            NeuronBasketConstructionParameters {
                count: original_neuron_basket_construction_parameters
                    .count
                    .unwrap(),
                dissolve_delay_interval_seconds: unwrap_duration_seconds(
                    &original_neuron_basket_construction_parameters.dissolve_delay_interval
                )
                .unwrap(),
            }
        );

        let (expected_swap_start_timestamp_seconds, expected_swap_due_timestamp_seconds) =
            CreateServiceNervousSystem::swap_start_and_due_timestamps(
                original_swap_parameters.start_time.unwrap(),
                original_swap_parameters.duration.unwrap(),
                current_timestamp_seconds,
            )
            .unwrap();

        assert_eq!(
            converted.swap_start_timestamp_seconds,
            Some(expected_swap_start_timestamp_seconds)
        );
        assert_eq!(
            converted.swap_due_timestamp_seconds,
            Some(expected_swap_due_timestamp_seconds)
        );
    }
}

mod metrics_tests {

    use maplit::btreemap;

    use crate::{
        encode_metrics,
        governance::Governance,
        pb::v1::{
            proposal, Governance as GovernanceProto, Motion, Proposal, ProposalData, Tally, Topic,
        },
        test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
    };

    #[test]
    fn test_metrics_total_voting_power() {
        let proposal_1 = ProposalData {
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "Text for this motion".to_string(),
                })),
                ..Proposal::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 555,
            }),
            ..ProposalData::default()
        };

        let proposal_2 = ProposalData {
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::default())),

                ..Proposal::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 1,
            }),
            ..ProposalData::default()
        };

        let governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 =>  proposal_1,
                    2 => proposal_2
                },
                ..GovernanceProto::default()
            },
            Box::new(MockEnvironment::new(Default::default(), 0)),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        let mut writer = ic_metrics_encoder::MetricsEncoder::new(vec![], 1000);

        encode_metrics(&governance, &mut writer).unwrap();

        let body = writer.into_inner();
        let s = String::from_utf8_lossy(&body);

        // We assert that it is '555' instead of '1', so that we know the correct
        // proposal action is filtered out.
        assert!(s.contains("governance_voting_power_total 555 1000"));
    }

    #[test]
    fn test_metrics_proposal_deadline_timestamp_seconds() {
        let manage_neuron_action = proposal::Action::ManageNeuron(Box::default());
        let motion_action = proposal::Action::Motion(Motion {
            motion_text: "Text for this motion".to_string(),
        });

        let open_proposal = ProposalData {
            proposal: Some(Proposal {
                title: Some("open_proposal".to_string()),
                action: Some(manage_neuron_action.clone()),
                ..Proposal::default()
            }),
            ..ProposalData::default()
        };

        let rejected_proposal = ProposalData {
            proposal: Some(Proposal {
                title: Some("rejected_proposal".to_string()),
                action: Some(manage_neuron_action.clone()),
                ..Proposal::default()
            }),
            decided_timestamp_seconds: 1,
            ..ProposalData::default()
        };

        let motion_proposal = ProposalData {
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(motion_action.clone()),
                ..Proposal::default()
            }),
            ..ProposalData::default()
        };

        let governance = Governance::new(
            GovernanceProto {
                proposals: btreemap! {
                    1 =>  open_proposal.clone(),
                    2 =>  rejected_proposal,
                    3 =>  motion_proposal.clone(),
                },
                ..GovernanceProto::default()
            },
            Box::<MockEnvironment>::default(),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        let mut writer = ic_metrics_encoder::MetricsEncoder::new(vec![], 10);

        encode_metrics(&governance, &mut writer).unwrap();

        let body = writer.into_inner();
        let s = String::from_utf8_lossy(&body);

        let voting_period = governance.voting_period_seconds()(open_proposal.topic());
        let deadline_ts = open_proposal.get_deadline_timestamp_seconds(voting_period);

        assert!(s.contains(&format!(
            "governance_proposal_deadline_timestamp_seconds{{proposal_id=\"1\",proposal_topic=\"{}\",proposal_type=\"{}\"}} {} 10",
            Topic::NeuronManagement.as_str_name(),
            &manage_neuron_action.as_str_name(),
            deadline_ts,
        )));

        let voting_period = governance.voting_period_seconds()(motion_proposal.topic());
        let deadline_ts = motion_proposal.get_deadline_timestamp_seconds(voting_period);

        assert!(s.contains(&format!(
            "governance_proposal_deadline_timestamp_seconds{{proposal_id=\"3\",proposal_topic=\"{}\",proposal_type=\"{}\"}} {} 10",
            Topic::Governance.as_str_name(),
            &motion_action.as_str_name(),
            deadline_ts,
        )));

        // We assert that decided proposals are filtered out from metrics
        assert!(!s.contains("proposal_id=\"2\""));
    }
}

mod neuron_archiving_tests {
    use crate::neuron::{DissolveStateAndAge, NeuronBuilder};
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::NeuronId;
    use icp_ledger::Subaccount;
    use proptest::proptest;

    #[test]
    fn test_neuron_is_inactive_based_on_neurons_fund_membership() {
        const NOW: u64 = 123_456_789;

        // Dissolved in the distant past.
        let model_neuron = NeuronBuilder::new(
            NeuronId { id: 1 },
            Subaccount::try_from(&[0u8; 32] as &[u8]).unwrap(),
            PrincipalId::new_user_test_id(1),
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 42,
            },
            NOW,
        )
        .build();
        assert!(model_neuron.is_inactive(NOW), "{:#?}", model_neuron);

        // Case Some(positive): Active.
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = Some(42);
        assert!(!neuron.is_inactive(NOW), "{:#?}", neuron);

        // Case Some(0): Inactive.
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = Some(0);
        assert!(neuron.is_inactive(NOW), "{:#?}", neuron);

        // Case None: Same as Some(0), i.e. Inactive
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = None;
        assert!(neuron.is_inactive(NOW), "{:#?}", neuron);

        // This is just so that clone is always called in all of the above cases.
        drop(model_neuron);
    }

    #[test]
    fn test_neuron_is_inactive_based_on_dissolve_state() {
        const NOW: u64 = 123_456_789;

        let neuron_with_dissolve_state_and_age = |dissolve_state_and_age| {
            NeuronBuilder::new(
                NeuronId { id: 1 },
                Subaccount::try_from(&[0u8; 32] as &[u8]).unwrap(),
                PrincipalId::new_user_test_id(1),
                dissolve_state_and_age,
                NOW,
            )
            .build()
        };

        // Case 1a: Dissolved in the "distant" past: Inactive. This is the only case where
        // "inactive" is the expected result.
        let neuron =
            neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 42,
            });
        assert!(neuron.is_inactive(NOW), "{:#?}", neuron);

        // Case 1b: Dissolved right now: Active
        let neuron =
            neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW,
            });
        assert!(!neuron.is_inactive(NOW), "{:#?}", neuron);

        // Case 1c: Soon to be dissolved: Active (again).
        let neuron =
            neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 42,
            });
        assert!(!neuron.is_inactive(NOW), "{:#?}", neuron);

        // Case 2: DissolveDelay(positive): Active
        let neuron = neuron_with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 42,
            aging_since_timestamp_seconds: NOW,
        });
        assert!(!neuron.is_inactive(NOW), "{:#?}", neuron);
    }

    proptest! {
        #[test]
        fn test_neuron_is_inactive_based_on_funding(
            cached_neuron_stake_e8s in 0_u64..10,
            staked_maturity_e8s_equivalent in 0_u64..10,
            neuron_fees_e8s in 0_u64..10,
            maturity_e8s_equivalent in 0_u64..10,
        ) {
            let net_funding_e8s = (
                cached_neuron_stake_e8s
                    .saturating_sub(neuron_fees_e8s)
                    .saturating_add(staked_maturity_e8s_equivalent)
            )
            + maturity_e8s_equivalent;
            let is_funded = net_funding_e8s > 0;

            // The test subject will be WhenDissolved(reasonable_time). Therefore, by living in the
            // distant future, the test subject will be considered "dissolved in the sufficiently
            // distant past". Thus, the dissolve_state requirement to be "inactive" is met.
            let now = 123_456_789;

            let staked_maturity_e8s_equivalent = Some(staked_maturity_e8s_equivalent);
            let mut neuron = NeuronBuilder::new(
                NeuronId { id: 1 },
                Subaccount::try_from(&[0u8; 32] as &[u8]).unwrap(),
                PrincipalId::new_user_test_id(1),
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: 42,
                },
                now,
            ).build();
            neuron.cached_neuron_stake_e8s = cached_neuron_stake_e8s;
            neuron.neuron_fees_e8s = neuron_fees_e8s;
            neuron.maturity_e8s_equivalent = maturity_e8s_equivalent;
            neuron.staked_maturity_e8s_equivalent = staked_maturity_e8s_equivalent;

            assert_eq!(
                neuron.is_inactive(now),
                !is_funded,
                "cached stake: {cached_neuron_stake_e8s}\n\
                 staked maturity: {staked_maturity_e8s_equivalent:?}\n\
                 fees: {neuron_fees_e8s}\n\
                 maturity: {maturity_e8s_equivalent}\n\
                 net funding: {net_funding_e8s}\n\
                 Neuron:\n{neuron:#?}",
            );
        }
    } // end proptest
}

mod cast_vote_and_cascade_follow {
    use crate::{
        governance::{Governance, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
        neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
        neuron_store::NeuronStore,
        pb::v1::{neuron::Followees, Ballot, Topic, Vote},
    };
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::{NeuronId, ProposalId};
    use icp_ledger::Subaccount;
    use maplit::hashmap;
    use std::collections::{BTreeMap, HashMap};

    fn make_ballot(voting_power: u64, vote: Vote) -> Ballot {
        Ballot {
            voting_power,
            vote: vote as i32,
        }
    }

    fn make_test_neuron_with_followees(
        id: u64,
        topic: Topic,
        followees: Vec<u64>,
        aging_since_timestamp_seconds: u64,
    ) -> Neuron {
        NeuronBuilder::new(
            NeuronId { id },
            Subaccount::try_from(&[0u8; 32] as &[u8]).unwrap(),
            PrincipalId::new_user_test_id(1),
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
                aging_since_timestamp_seconds,
            },
            123_456_789,
        )
        .with_followees(hashmap! {
            topic as i32 => Followees {
                followees: followees.into_iter().map(|id| NeuronId { id }).collect()
            }
        })
        .build()
    }

    #[test]
    fn test_cast_vote_and_cascade_doesnt_cascade_neuron_management() {
        let now = 1000;
        let topic = Topic::NeuronManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_test_neuron_with_followees(id, topic, followees, now)
        };

        let add_neuron_with_ballot = |neuron_map: &mut BTreeMap<u64, Neuron>,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let voting_power = neuron.voting_power(now);
            neuron_map.insert(id, neuron);
            ballots.insert(id, make_ballot(voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_map: &mut BTreeMap<u64, Neuron>, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_map.insert(id, neuron);
            };

        let mut heap_neurons = BTreeMap::new();
        let mut ballots = HashMap::new();
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(
                &mut heap_neurons,
                &mut ballots,
                id,
                followees,
                Vote::Unspecified,
            );
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(
            &mut heap_neurons,
            &mut ballots,
            6,
            vec![1, 7],
            Vote::Unspecified,
        );

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut heap_neurons, 7, vec![1]);

        let mut neuron_store = NeuronStore::new(heap_neurons);

        Governance::cast_vote_and_cascade_follow(
            &ProposalId { id: 1 },
            &mut ballots,
            &NeuronId { id: 1 },
            Vote::Yes,
            topic,
            &mut neuron_store,
        );

        assert_eq!(
            ballots,
            hashmap! {
                1 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 1}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                2 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 2}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
                3 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 3}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
                4 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 4}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
                5 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 5}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
                6 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 6}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
            }
        );
    }

    #[test]
    fn test_cast_vote_and_cascade_works() {
        let now = 1000;
        let topic = Topic::NetworkCanisterManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_test_neuron_with_followees(id, topic, followees, now)
        };

        let add_neuron_with_ballot = |neuron_map: &mut BTreeMap<u64, Neuron>,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let voting_power = neuron.voting_power(now);
            neuron_map.insert(id, neuron);
            ballots.insert(id, make_ballot(voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_map: &mut BTreeMap<u64, Neuron>, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_map.insert(id, neuron);
            };

        let mut neurons = BTreeMap::new();
        let mut ballots = HashMap::new();
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(&mut neurons, &mut ballots, id, followees, Vote::Unspecified);
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(&mut neurons, &mut ballots, 6, vec![1, 7], Vote::Unspecified);

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut neurons, 7, vec![1]);

        let mut neuron_store = NeuronStore::new(neurons);

        Governance::cast_vote_and_cascade_follow(
            &ProposalId { id: 1 },
            &mut ballots,
            &NeuronId { id: 1 },
            Vote::Yes,
            topic,
            &mut neuron_store,
        );

        assert_eq!(
            ballots,
            hashmap! {
                1 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 1}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                2 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 2}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                3 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 3}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                4 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 4}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                5 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 5}, |n| n.voting_power(now)).unwrap(), Vote::Yes),
                6 => make_ballot(neuron_store.with_neuron(&NeuronId {id: 6}, |n| n.voting_power(now)).unwrap(), Vote::Unspecified),
            }
        );
    }
}

#[test]
fn test_pre_and_post_upgrade_first_time() {
    let neuron1 = NeuronProto {
        id: Some(NeuronId { id: 1 }),
        controller: Some(PrincipalId::new_user_test_id(1)),
        followees: hashmap! {
            2 => Followees {
                followees: vec![NeuronId { id : 3}]
            }
        },
        account: vec![0; 32],
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(42)),
        aging_since_timestamp_seconds: 1,
        ..Default::default()
    };
    let neurons = btreemap! { 1 => neuron1 };

    // This simulates the state of heap on first post_upgrade (empty topic_followee_index)
    let governance_proto = GovernanceProto {
        neurons,
        ..Default::default()
    };

    // Precondition
    assert_eq!(governance_proto.neurons.len(), 1);
    assert_eq!(governance_proto.topic_followee_index.len(), 0);

    // Then Governance is instantiated during upgrade with proto
    let mut governance = Governance::new(
        governance_proto,
        Box::<MockEnvironment>::default(),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );
    // On next pre-upgrade, we get the heap proto and store it in stable memory
    let mut extracted_proto = governance.take_heap_proto();

    // topic_followee_index should have been populated
    assert_eq!(extracted_proto.topic_followee_index.len(), 1);

    // We now modify it so that we can be assured that it is not rebuilding on the next post_upgrade
    extracted_proto.topic_followee_index.insert(
        4,
        FollowersMap {
            followers_map: hashmap! {5 => Followers { followers: vec![NeuronId { id : 6}]}},
        },
    );

    assert_eq!(extracted_proto.neurons.len(), 1);
    assert_eq!(extracted_proto.topic_followee_index.len(), 2);

    // We now simulate the post_upgrade
    let mut governance = Governance::new_restored(
        extracted_proto,
        Box::<MockEnvironment>::default(),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    // It should not rebuild during post_upgrade so it should still be mis-matched with neurons.
    let extracted_proto = governance.take_heap_proto();
    assert_eq!(extracted_proto.topic_followee_index.len(), 2);
}

#[test]
fn can_spawn_neurons_only_true_when_not_spawning_and_neurons_ready_to_spawn() {
    let proto = GovernanceProto {
        ..Default::default()
    };

    let mock_env = MockEnvironment::new(vec![], 100);

    let mut governance = Governance::new(
        proto,
        Box::new(mock_env),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );
    // No neurons to spawn...
    assert!(!governance.can_spawn_neurons());

    governance
        .neuron_store
        .add_neuron(
            NeuronBuilder::new(
                NeuronId { id: 1 },
                Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
                PrincipalId::new_user_test_id(1),
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 42,
                    aging_since_timestamp_seconds: 1,
                },
                123_456_789,
            )
            .with_spawn_at_timestamp_seconds(99)
            .build(),
        )
        .unwrap();

    governance.heap_data.spawning_neurons = Some(true);

    // spawning_neurons is true, so it shouldn't be able to spawn again.
    assert!(!governance.can_spawn_neurons());

    governance.heap_data.spawning_neurons = None;

    // Work to do, no lock, should say yes.
    assert!(governance.can_spawn_neurons());
}

#[test]
fn test_validate_execute_nns_function() {
    let governance = Governance::new(
        GovernanceProto {
            economics: Some(NetworkEconomics::with_default_values()),
            node_providers: vec![NodeProvider {
                id: Some(PrincipalId::new_node_test_id(1)),
                ..Default::default()
            }],
            ..Default::default()
        },
        Box::new(MockEnvironment::new(vec![], 100)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    let test_execute_nns_function_error =
        |execute_nns_function: ExecuteNnsFunction, error_message: String| {
            let actual_result = governance.validate_execute_nns_function(&execute_nns_function);
            let expected_result = Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                error_message,
            ));
            assert_eq!(actual_result, expected_result);
        };

    let error_test_cases = vec![
        (
            ExecuteNnsFunction {
                nns_function: i32::MAX,
                payload: vec![],
            },
            "Invalid NnsFunction id: 2147483647".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::CreateSubnet as i32,
                payload: vec![1u8; PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX + 1],
            },
            format!(
                "The maximum NNS function payload size in a proposal action is {} bytes, \
                 this payload is: {} bytes",
                PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX,
                PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX + 1,
            ),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::IcpXdrConversionRate as i32,
                payload: vec![],
            },
            "The payload could not be decoded into a UpdateIcpXdrConversionRatePayload: \
             Cannot parse header "
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::IcpXdrConversionRate as i32,
                payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                    xdr_permyriad_per_icp: 0,
                    ..Default::default()
                })
                .unwrap(),
            },
            "The proposed rate 0 is below the minimum allowable rate".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::AssignNoid as i32,
                payload: vec![],
            },
            "The payload could not be decoded into a AddNodeOperatorPayload: \
             Cannot parse header "
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::AssignNoid as i32,
                payload: Encode!(&AddNodeOperatorPayload {
                    node_provider_principal_id: None,
                    ..Default::default()
                })
                .unwrap(),
            },
            "The payload's node_provider_principal_id field was None".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::AssignNoid as i32,
                payload: Encode!(&AddNodeOperatorPayload {
                    node_provider_principal_id: Some(PrincipalId::new_node_test_id(2)),
                    ..Default::default()
                })
                .unwrap(),
            },
            "The node provider specified in the payload is not registered".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::AddOrRemoveDataCenters as i32,
                payload: Encode!(&AddOrRemoveDataCentersProposalPayload {
                    data_centers_to_add: vec![DataCenterRecord {
                        id: "a".repeat(1000),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .unwrap(),
            },
            "The given AddOrRemoveDataCentersProposalPayload is invalid: id must not be longer \
             than 255 characters"
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateAllowedPrincipals as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_ALLOWED_PRINCIPALS proposal is obsolete".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateApiBoundaryNodesVersion as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_API_BOUNDARY_NODES_VERSION proposal is obsolete".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateUnassignedNodesConfig as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_UNASSIGNED_NODES_CONFIG proposal is obsolete".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateElectedHostosVersions as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_ELECTED_HOSTOS_VERSIONS proposal is obsolete".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateNodesHostosVersion as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_NODES_HOSTOS_VERSION proposal is obsolete".to_string(),
        ),
    ];

    for (execute_nns_function, error_message) in error_test_cases {
        test_execute_nns_function_error(execute_nns_function, error_message);
    }

    let ok_test_cases = vec![
        ExecuteNnsFunction {
            nns_function: NnsFunction::CreateSubnet as i32,
            payload: vec![1u8; PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX],
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::IcpXdrConversionRate as i32,
            payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                xdr_permyriad_per_icp: 101,
                ..Default::default()
            })
            .unwrap(),
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::AssignNoid as i32,
            payload: Encode!(&AddNodeOperatorPayload {
                node_provider_principal_id: Some(PrincipalId::new_node_test_id(1)),
                ..Default::default()
            })
            .unwrap(),
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::AddOrRemoveDataCenters as i32,
            payload: Encode!(&AddOrRemoveDataCentersProposalPayload {
                data_centers_to_add: vec![DataCenterRecord {
                    id: "a".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap(),
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::DeployGuestosToSomeApiBoundaryNodes as i32,
            payload: vec![],
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::DeployGuestosToAllUnassignedNodes as i32,
            payload: vec![],
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes as i32,
            payload: vec![],
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::ReviseElectedHostosVersions as i32,
            payload: vec![],
        },
        ExecuteNnsFunction {
            nns_function: NnsFunction::DeployHostosToSomeNodes as i32,
            payload: vec![],
        },
    ];

    for execute_nns_function in ok_test_cases {
        let actual_result = governance.validate_execute_nns_function(&execute_nns_function);
        assert_eq!(actual_result, Ok(()));
    }
}

#[test]
fn topic_min_max_test() {
    use strum::IntoEnumIterator;

    for topic in Topic::iter() {
        assert!(topic >= Topic::MIN, "Topic::MIN needs to be updated");
        assert!(topic <= Topic::MAX, "Topic::MAX needs to be updated");
    }
}

#[cfg(feature = "test")]
#[test]
fn test_update_neuron_errors_out_expectedly() {
    fn build_neuron_proto(account: Vec<u8>) -> NeuronProto {
        NeuronProto {
            account,
            id: Some(NeuronId { id: 1 }),
            controller: Some(PrincipalId::new_user_test_id(1)),
            followees: hashmap! {
                2 => Followees {
                    followees: vec![NeuronId { id : 3}]
                }
            },
            aging_since_timestamp_seconds: 1,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(42)),
            ..Default::default()
        }
    }

    let neuron1_subaccount_blob = vec![1; 32];
    let neuron1_subaccount = Subaccount::try_from(neuron1_subaccount_blob.as_slice()).unwrap();
    let neuron1 = build_neuron_proto(neuron1_subaccount_blob.clone());
    let neurons = btreemap! { 1 => neuron1 };
    let governance_proto = GovernanceProto {
        neurons,
        ..Default::default()
    };
    let mut governance = Governance::new(
        governance_proto,
        Box::<MockEnvironment>::default(),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    assert_eq!(
        governance.update_neuron(build_neuron_proto(vec![0; 32])),
        Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "Cannot change the subaccount {} of a neuron.",
                neuron1_subaccount
            ),
        )),
    );
}
