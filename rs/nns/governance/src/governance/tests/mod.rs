use super::*;
use crate::pb::v1::ExecuteNnsFunction;
use crate::storage::with_voting_history_store;
use crate::test_utils::MockRandomness;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::{E8, assert_is_err, assert_is_ok};
#[cfg(feature = "test")]
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use ic_nns_common::pb::v1::NeuronId;
#[cfg(feature = "test")]
use ic_nns_governance_api::CreateServiceNervousSystem as ApiCreateServiceNervousSystem;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
#[cfg(feature = "test")]
use ic_sns_init::pb::v1::SnsInitPayload;
#[cfg(feature = "test")]
use ic_sns_init::pb::v1::{self as sns_init_pb};
use lazy_static::lazy_static;
use maplit::hashmap;
use std::{convert::TryFrom, time::Duration};

mod get_neuron_index;
mod list_neurons;
mod list_proposals;
mod neurons_fund;
mod node_provider_rewards;
mod stake_maturity;
mod update_node_provider;

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
    use SettleNeuronsFundParticipationRequest;
    use settle_neurons_fund_participation_request::{Aborted, Committed, Result};

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
            NeuronsFundNeuronPortion, NeuronsFundSnapshot,
            neurons_fund_neuron::MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON,
        },
        pb::v1 as gov_pb,
    };
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::NeuronId;
    use ic_nns_governance_api::SettleNeuronsFundParticipationResponse;

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

    /// This canister ID can be used as `specified_id` in tests on `state_machine_builder_for_nns_tests`.
    /// Canisters created in those tests without any `specified_id` are assigned to the default range
    /// from `CanisterId::from_u64(0x0000000)` to `CanisterId::from_u64(0x00FFFFF)` and thus
    /// canisters created with `specified_id` can only be assigned to the extra range
    /// from `CanisterId::from_u64(0x2100000)` to `CanisterId::from_u64(0x21FFFFE)`.
    const SPECIFIED_CANISTER_ID: CanisterId = CanisterId::from_u64(0x2100000);

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
        let converted = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone(),
        ))
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
                        id: Some(SPECIFIED_CANISTER_ID.get())
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
        let converted = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(original));

        // Step 3: Inspect the result: Err must contain "wait for quiet".
        match converted {
            Ok(ok) => panic!("Invalid data was not rejected. Result: {ok:#?}"),
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

    /// This canister ID can be used as `specified_id` in tests on `state_machine_builder_for_nns_tests`.
    /// Canisters created in those tests without any `specified_id` are assigned to the default range
    /// from `CanisterId::from_u64(0x0000000)` to `CanisterId::from_u64(0x00FFFFF)` and thus
    /// canisters created with `specified_id` can only be assigned to the extra range
    /// from `CanisterId::from_u64(0x2100000)` to `CanisterId::from_u64(0x21FFFFE)`.
    const SPECIFIED_CANISTER_ID: CanisterId = CanisterId::from_u64(0x2100000);

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

            let sns_init_payload = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(
                create_service_nervous_system,
            ))
            .unwrap();

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
                        id: Some(SPECIFIED_CANISTER_ID.get())
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
    use ic_nns_common::pb::v1::ProposalId;
    use std::sync::Arc;

    use crate::test_utils::MockRandomness;
    use crate::{
        encode_metrics,
        governance::Governance,
        pb::v1::{Motion, Proposal, ProposalData, Tally, Topic, proposal},
        test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
    };

    #[test]
    fn test_metrics_total_voting_power() {
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let proposal_1 = ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "Text for this motion".to_string(),
                })),
                ..Default::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 555,
            }),
            topic: Some(Topic::Governance as i32),
            ..Default::default()
        };

        let proposal_2 = ProposalData {
            id: Some(ProposalId { id: 2 }),
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::default())),

                ..Default::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: 0,
                yes: 0,
                no: 0,
                total: 1,
            }),
            topic: Some(Topic::NeuronManagement as i32),
            ..Default::default()
        };

        governance.heap_data.proposals.insert(1, proposal_1);
        governance.heap_data.proposals.insert(2, proposal_2);

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
        let mut governance = Governance::new(
            Default::default(),
            Arc::<MockEnvironment>::default(),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let manage_neuron_action = proposal::Action::ManageNeuron(Box::default());
        let motion_action = proposal::Action::Motion(Motion {
            motion_text: "Text for this motion".to_string(),
        });

        let open_proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposal: Some(Proposal {
                title: Some("open_proposal".to_string()),
                action: Some(manage_neuron_action.clone()),
                ..Proposal::default()
            }),
            topic: Some(Topic::NeuronManagement as i32),
            ..ProposalData::default()
        };

        let rejected_proposal = ProposalData {
            id: Some(ProposalId { id: 2 }),
            proposal: Some(Proposal {
                title: Some("rejected_proposal".to_string()),
                action: Some(manage_neuron_action.clone()),
                ..Proposal::default()
            }),
            decided_timestamp_seconds: 1,
            topic: Some(Topic::NeuronManagement as i32),
            ..ProposalData::default()
        };

        let motion_proposal = ProposalData {
            id: Some(ProposalId { id: 3 }),
            proposal: Some(Proposal {
                title: Some("Foo Foo Bar".to_string()),
                action: Some(motion_action.clone()),
                ..Proposal::default()
            }),
            topic: Some(Topic::Governance as i32),
            ..ProposalData::default()
        };

        governance
            .heap_data
            .proposals
            .insert(1, open_proposal.clone());
        governance.heap_data.proposals.insert(2, rejected_proposal);
        governance
            .heap_data
            .proposals
            .insert(3, motion_proposal.clone());

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
        assert!(model_neuron.is_inactive(NOW), "{model_neuron:#?}");

        // Case Some(positive): Active.
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = Some(42);
        assert!(!neuron.is_inactive(NOW), "{neuron:#?}");

        // Case Some(0): Inactive.
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = Some(0);
        assert!(neuron.is_inactive(NOW), "{neuron:#?}");

        // Case None: Same as Some(0), i.e. Inactive
        let mut neuron = model_neuron.clone();
        neuron.joined_community_fund_timestamp_seconds = None;
        assert!(neuron.is_inactive(NOW), "{neuron:#?}");

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
        assert!(neuron.is_inactive(NOW), "{neuron:#?}");

        // Case 1b: Dissolved right now: Active
        let neuron =
            neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW,
            });
        assert!(!neuron.is_inactive(NOW), "{neuron:#?}");

        // Case 1c: Soon to be dissolved: Active (again).
        let neuron =
            neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 42,
            });
        assert!(!neuron.is_inactive(NOW), "{neuron:#?}");

        // Case 2: DissolveDelay(positive): Active
        let neuron = neuron_with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 42,
            aging_since_timestamp_seconds: NOW,
        });
        assert!(!neuron.is_inactive(NOW), "{neuron:#?}");
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

#[test]
fn test_pre_and_post_upgrade_first_time() {
    // Then Governance is instantiated during upgrade with proto
    let mut governance = Governance::new(
        Default::default(),
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let neuron = NeuronBuilder::new_for_test(
        1,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 42,
            aging_since_timestamp_seconds: 0,
        },
    )
    .build();
    governance.add_neuron(1, neuron).unwrap();

    // Simulate seeding the randomness in a running governance canister.
    governance.randomness.seed_rng([12; 32]);

    assert_eq!(governance.neuron_store.len(), 1);
    // On next pre-upgrade, we get the heap proto and store it in stable memory
    let extracted_proto = governance.take_heap_proto();

    // We now simulate the post_upgrade
    let mut governance = Governance::new_restored(
        extracted_proto,
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    assert_eq!(governance.neuron_store.len(), 1);
    // It should not rebuild during post_upgrade so it should still be mis-matched with neurons.
    let extracted_proto = governance.take_heap_proto();
    assert_eq!(extracted_proto.rng_seed, Some(vec![12; 32]));
}

#[test]
fn can_spawn_neurons_only_true_when_not_spawning_and_neurons_ready_to_spawn() {
    let mock_env = MockEnvironment::new(vec![], 100);

    let mut governance = Governance::new(
        Default::default(),
        Arc::new(mock_env),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
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
        api::Governance {
            economics: Some(api::NetworkEconomics::with_default_values()),
            node_providers: vec![api::NodeProvider {
                id: Some(PrincipalId::new_node_test_id(1)),
                ..Default::default()
            }],
            ..Default::default()
        },
        Arc::new(MockEnvironment::new(vec![], 100)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let test_execute_nns_function_validate_error =
        |execute_nns_function: ExecuteNnsFunction, error_message: String| {
            // Test that validation fails with the expected error message
            let valid_execute_nns_function =
                ValidExecuteNnsFunction::try_from(execute_nns_function)
                    .expect("Failed to create ValidExecuteNnsFunction");
            let actual_result =
                governance.validate_execute_nns_function(&valid_execute_nns_function);
            let expected_result = Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                error_message,
            ));
            assert_eq!(actual_result, expected_result);
        };

    // Test cases that should fail during validation
    let validate_error_test_cases = vec![
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
    ];

    for (execute_nns_function, error_message) in validate_error_test_cases {
        test_execute_nns_function_validate_error(execute_nns_function, error_message);
    }

    let ok_test_cases = vec![
        ExecuteNnsFunction {
            nns_function: NnsFunction::CreateSubnet as i32,
            payload: vec![1u8; PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX],
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
        let valid_execute_nns_function = ValidExecuteNnsFunction::try_from(execute_nns_function)
            .expect("Failed to create ValidExecuteNnsFunction");
        let actual_result = governance.validate_execute_nns_function(&valid_execute_nns_function);
        assert_eq!(actual_result, Ok(()));
    }
}

#[test]
fn test_canister_and_function_no_unreachable() {
    use strum::IntoEnumIterator;

    for nns_function in NnsFunction::iter() {
        // This will return either `Ok(_)` for nns functions that are still used, or `Err(_)` for
        // obsolete ones. The test just makes sure that it doesn't panic.
        let execute_nns_function = ExecuteNnsFunction {
            nns_function: nns_function as i32,
            payload: vec![],
        };
        if let Ok(valid_execute) = ValidExecuteNnsFunction::try_from(execute_nns_function) {
            let _ = valid_execute.nns_function.canister_and_function();
        }
    }
}

#[test]
fn test_deciding_voting_power_adjustment_factor() {
    let voting_power_economics = VotingPowerEconomics {
        start_reducing_voting_power_after_seconds: Some(60),
        clear_following_after_seconds: Some(30),
        neuron_minimum_dissolve_delay_to_vote_seconds: Some(60),
    };

    let deciding_voting_power = |seconds_since_refresh| {
        let time_since_refresh = Duration::from_secs(seconds_since_refresh);
        voting_power_economics.deciding_voting_power_adjustment_factor(time_since_refresh)
    };

    // 100% at first.
    for seconds_since_refresh in 0..=60 {
        assert_eq!(
            deciding_voting_power(seconds_since_refresh),
            Decimal::from(1),
        );
    }

    // Slowly ramp down.
    for seconds_since_refresh in 60..=90 {
        let expected_value = Decimal::from(90 - seconds_since_refresh) / Decimal::from(30);

        assert_eq!(deciding_voting_power(seconds_since_refresh), expected_value);
    }
    assert_eq!(deciding_voting_power(75), Decimal::try_from(0.5).unwrap());

    // Stuck at 0% after a "very" long time.
    for seconds_since_refresh in 90..200 {
        assert_eq!(
            deciding_voting_power(seconds_since_refresh),
            Decimal::from(0),
        );
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
    fn new_neuron(account: Vec<u8>) -> Neuron {
        NeuronBuilder::new_for_test(
            1,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 42,
                aging_since_timestamp_seconds: 1,
            },
        )
        .with_subaccount(Subaccount::try_from(account.as_slice()).unwrap())
        .with_followees(hashmap! {
            2 => Followees {
                followees: vec![NeuronId { id : 3}]
            }
        })
        .build()
    }

    let mut governance = Governance::new(
        Default::default(),
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );
    let neuron = new_neuron(vec![1; 32]);
    let neuron_subaccount = neuron.subaccount();
    governance.add_neuron(1, neuron).unwrap();

    assert_eq!(
        governance.update_neuron(new_neuron(vec![0; 32]).into_api(0, &Default::default(), false)),
        Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!("Cannot change the subaccount {neuron_subaccount} of a neuron."),
        )),
    );
}

#[test]
fn test_compute_ballots_for_manage_neuron_proposal() {
    const CREATED_TIMESTAMP_SECONDS: u64 = 1729791574;

    fn new_neuron_builder(id: u64) -> NeuronBuilder {
        NeuronBuilder::new_for_test(
            id,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
                aging_since_timestamp_seconds: CREATED_TIMESTAMP_SECONDS + 42,
            },
        )
        .with_cached_neuron_stake_e8s(id * E8)
    }

    let neuron_10 = new_neuron_builder(10)
        .with_followees(hashmap! {
            Topic::NeuronManagement as i32 => Followees {
                followees: vec![
                    NeuronId { id: 10 },
                    NeuronId { id: 201 },
                    NeuronId { id: 202 },
                    NeuronId { id: 203 },
                    NeuronId { id: 204 },
                    NeuronId { id: 205 },
                    NeuronId { id: 206 },
                ]
            }
        })
        .build();

    let mut governance = Governance::new(
        Default::default(),
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    governance.add_neuron(10, neuron_10).unwrap();

    let managed_id = manage_neuron::NeuronIdOrSubaccount::NeuronId(NeuronId { id: 10 });
    let ballots = governance
        .compute_ballots_for_manage_neuron_proposal(&managed_id, &NeuronId { id: 10 })
        .expect("Failed computing ballots for manage neuron proposal");

    assert_eq!(
        ballots,
        hashmap! {
        10 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        201 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        202 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        203 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        204 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        205 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        206 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        }
    );
}

#[test]
fn test_compute_ballots_for_standard_proposal() {
    const CREATED_TIMESTAMP_SECONDS: u64 = 1729791574;
    let now_seconds = CREATED_TIMESTAMP_SECONDS + 999;

    fn new_neuron_builder(id: u64) -> NeuronBuilder {
        NeuronBuilder::new_for_test(
            id,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
                aging_since_timestamp_seconds: CREATED_TIMESTAMP_SECONDS + 42,
            },
        )
        .with_cached_neuron_stake_e8s(id * E8)
    }

    let mut governance = Governance::new(
        Default::default(),
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    governance
        .add_neuron(10, new_neuron_builder(10).build())
        .unwrap();
    governance
        .add_neuron(200, new_neuron_builder(200).build())
        .unwrap();
    governance
        .add_neuron(3_000, new_neuron_builder(3_000).build())
        .unwrap();

    let deciding_vote = |g: &Governance, id, now| {
        g.neuron_store
            .with_neuron(&NeuronId { id }, |n| {
                n.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now)
            })
            .unwrap()
    };

    // Test with initial timestamp
    let (ballots, total_potential_voting_power, _previous_ballots_timestamp_seconds) = governance
        .compute_ballots_for_standard_proposal(now_seconds)
        .expect("Failed computing ballots for standard proposal");

    let expected_potential_voting_power: u64 =
        governance.neuron_store.with_active_neurons_iter(|iter| {
            iter.map(|neuron| neuron.potential_voting_power(now_seconds))
                .sum()
        });

    assert_eq!(
        total_potential_voting_power,
        expected_potential_voting_power
    );
    assert_eq!(
        ballots,
        hashmap! {
            10 => Ballot { voting_power: deciding_vote(&governance,10, now_seconds), vote: Vote::Unspecified as i32 },
            200 => Ballot { voting_power: deciding_vote(&governance, 200, now_seconds), vote: Vote::Unspecified as i32 },
            3_000 => Ballot { voting_power: deciding_vote(&governance,3_000 , now_seconds), vote: Vote::Unspecified as i32 },
        }
    );

    // Test again with a much later timestamp (not affected by refresh)
    let now_seconds = CREATED_TIMESTAMP_SECONDS + 20 * ONE_YEAR_SECONDS;

    let (ballots, total_potential_voting_power, _previous_ballots_timestamp_seconds) = governance
        .compute_ballots_for_standard_proposal(now_seconds)
        .expect("Failed computing ballots for standard proposal");
    let expected: u64 = governance.neuron_store.with_active_neurons_iter(|iter| {
        iter.map(|neuron| neuron.potential_voting_power(now_seconds))
            .sum()
    });

    assert_eq!(total_potential_voting_power, expected);
    assert_eq!(
        ballots,
        hashmap! {
            10 => Ballot { voting_power: deciding_vote(&governance,10, now_seconds), vote: Vote::Unspecified as i32 },
            200 => Ballot { voting_power: deciding_vote(&governance, 200, now_seconds), vote: Vote::Unspecified as i32 },
            3_000 => Ballot { voting_power: deciding_vote(&governance,3_000 , now_seconds), vote: Vote::Unspecified as i32 },
        }
    );
}

#[test]
fn test_validate_add_or_remove_node_provider() {
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let existing_node_provider = api::NodeProvider {
        id: Some(node_provider_id),
        reward_account: None,
    };

    let governance = Governance::new(
        api::Governance {
            node_providers: vec![existing_node_provider.clone()],
            ..Default::default()
        },
        Arc::new(MockEnvironment::new(vec![], 100)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let existing_node_provider = NodeProvider::from(existing_node_provider);

    // Test case 1: No change field
    let add_or_remove_no_change = AddOrRemoveNodeProvider { change: None };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_no_change);
    assert!(result.is_err());

    // Test case 2: ToAdd with new node provider (should succeed)
    let new_node_provider_id = PrincipalId::new_user_test_id(2);
    let valid_account = AccountIdentifier::new(new_node_provider_id, None);

    let new_node_provider = NodeProvider {
        id: Some(new_node_provider_id),
        reward_account: Some(valid_account.into_proto_with_checksum()),
    };
    let add_or_remove_add_new = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(new_node_provider)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_add_new);
    assert!(
        result.is_ok(),
        "Expected to succeed, but got error: {result:?}"
    );

    // Test case 3: ToAdd with existing node provider (should fail)
    let add_or_remove_add_existing = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(existing_node_provider.clone())),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_add_existing);
    assert!(result.is_err());

    // Test case 4: ToAdd with invalid account identifier (should fail)
    let node_provider_with_invalid_account = NodeProvider {
        id: Some(PrincipalId::new_user_test_id(3)),
        reward_account: Some(icp_ledger::protobuf::AccountIdentifier {
            hash: vec![1, 2, 3], // Invalid length
        }),
    };
    let add_or_remove_invalid_account = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(node_provider_with_invalid_account)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_invalid_account);
    assert!(result.is_err());

    // Test case 5: ToAdd with 28-byte length (should fail)
    let node_provider_with_invalid_account = NodeProvider {
        id: Some(PrincipalId::new_user_test_id(3)),
        reward_account: Some(icp_ledger::protobuf::AccountIdentifier {
            hash: vec![1; 28], // 32-byte required, but only 28 bytes provided
        }),
    };
    let add_or_remove_invalid_account = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(node_provider_with_invalid_account)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_invalid_account);
    assert!(result.is_err());

    // Test case 6: ToRemove with existing node provider (should succeed)
    let add_or_remove_remove_existing = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(existing_node_provider)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_remove_existing);
    assert!(result.is_ok());

    // Test case 7: ToRemove with non-existing node provider (should fail)
    let non_existing_node_provider = NodeProvider {
        id: Some(PrincipalId::new_user_test_id(999)),
        reward_account: None,
    };
    let add_or_remove_remove_non_existing = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(non_existing_node_provider)),
    };
    let result =
        governance.validate_add_or_remove_node_provider(&add_or_remove_remove_non_existing);
    assert!(result.is_err());

    // Test Case 8: ToAdd with no NodeProvider ID (should fail)
    let node_provider_without_id = NodeProvider {
        id: None,
        reward_account: Some(valid_account.into_proto_with_checksum()),
    };
    let add_or_remove_no_id = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(node_provider_without_id)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_no_id);
    assert!(
        result.is_err(),
        "Expected to fail, but got success: {result:?}"
    );

    // Test Case 9: ToRemove with no NodeProvider ID (should fail)
    let node_provider_without_id = NodeProvider {
        id: None,
        reward_account: None,
    };
    let add_or_remove_no_id = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(node_provider_without_id)),
    };
    let result = governance.validate_add_or_remove_node_provider(&add_or_remove_no_id);
    assert!(
        result.is_err(),
        "Expected to fail, but got success: {result:?}"
    );
}

#[test]
fn test_record_known_neuron_abstentions() {
    record_known_neuron_abstentions(
        &[NeuronId { id: 1 }, NeuronId { id: 2 }],
        ProposalId { id: 1 },
        hashmap! {
            1 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
            2 => Ballot { voting_power: 1, vote: Vote::Yes as i32 },
            3 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
            4 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
        },
    );

    with_voting_history_store(|voting_history| {
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 1 }, None, Some(100)),
            vec![(ProposalId { id: 1 }, Vote::Unspecified)]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 2 }, None, Some(100)),
            vec![]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 3 }, None, Some(100)),
            vec![]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 4 }, None, Some(100)),
            vec![]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 5 }, None, Some(100)),
            vec![]
        );
    });

    record_known_neuron_abstentions(
        &[NeuronId { id: 1 }, NeuronId { id: 2 }, NeuronId { id: 3 }],
        ProposalId { id: 2 },
        hashmap! {
            1 => Ballot { voting_power: 1, vote: Vote::Yes as i32 },
            3 => Ballot { voting_power: 1, vote: Vote::Unspecified as i32 },
            4 => Ballot { voting_power: 1, vote: Vote::No as i32 },
        },
    );

    with_voting_history_store(|voting_history| {
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 1 }, None, Some(100)),
            vec![(ProposalId { id: 1 }, Vote::Unspecified),]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 2 }, None, Some(100)),
            vec![]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 3 }, None, Some(100)),
            vec![(ProposalId { id: 2 }, Vote::Unspecified)]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 4 }, None, Some(100)),
            vec![]
        );
        assert_eq!(
            voting_history.list_neuron_votes(NeuronId { id: 5 }, None, Some(100)),
            vec![]
        );
    });
}
