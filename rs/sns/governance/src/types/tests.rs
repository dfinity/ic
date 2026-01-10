use super::*;
use crate::pb::v1::{
    ExecuteGenericNervousSystemFunction, Proposal, ProposalData, VotingRewardsParameters,
    claim_swap_neurons_request::neuron_recipe,
    governance::Mode::PreInitializationSwap,
    nervous_system_function::{FunctionType, GenericNervousSystemFunction},
};
use candid::Nat;
use futures::FutureExt;
use ic_base_types::PrincipalId;
use ic_management_canister_types_private::ChunkHash;
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nervous_system_proto::pb::v1::Principals;
use ic_sns_governance_api::pb::v1::topics::Topic;
use lazy_static::lazy_static;
use maplit::{btreemap, hashset};
use std::convert::TryInto;
use test_helpers::NativeEnvironment;

#[test]
fn test_voting_period_parameters() {
    let non_critical_action = Action::Motion(Default::default());
    let critical_action = Action::TransferSnsTreasuryFunds(Default::default());

    let normal_nervous_system_parameters = NervousSystemParameters {
        initial_voting_period_seconds: Some(4 * ONE_DAY_SECONDS),
        wait_for_quiet_deadline_increase_seconds: Some(2 * ONE_DAY_SECONDS),
        ..Default::default()
    };
    assert_eq!(
        non_critical_action.voting_duration_parameters(
            &normal_nervous_system_parameters,
            ProposalCriticality::Normal
        ),
        VotingDurationParameters {
            initial_voting_period: PbDuration {
                seconds: Some(4 * ONE_DAY_SECONDS),
            },
            wait_for_quiet_deadline_increase: PbDuration {
                seconds: Some(2 * ONE_DAY_SECONDS),
            }
        },
    );
    assert_eq!(
        critical_action.voting_duration_parameters(
            &normal_nervous_system_parameters,
            ProposalCriticality::Critical
        ),
        VotingDurationParameters {
            initial_voting_period: PbDuration {
                seconds: Some(5 * ONE_DAY_SECONDS),
            },
            wait_for_quiet_deadline_increase: PbDuration {
                seconds: Some(2 * ONE_DAY_SECONDS + ONE_DAY_SECONDS / 2),
            }
        },
    );

    // This is even slower than the hard-coded values (5 days initial and 2.5 days wait for
    // quiet) for critical proposals. Therefore, these values are used for both normal and
    // critical proposals.
    let slow_nervous_system_parameters = NervousSystemParameters {
        initial_voting_period_seconds: Some(7 * ONE_DAY_SECONDS),
        wait_for_quiet_deadline_increase_seconds: Some(4 * ONE_DAY_SECONDS),
        ..Default::default()
    };
    assert_eq!(
        non_critical_action.voting_duration_parameters(
            &slow_nervous_system_parameters,
            ProposalCriticality::Normal
        ),
        VotingDurationParameters {
            initial_voting_period: PbDuration {
                seconds: Some(7 * ONE_DAY_SECONDS),
            },
            wait_for_quiet_deadline_increase: PbDuration {
                seconds: Some(4 * ONE_DAY_SECONDS),
            }
        },
    );
    assert_eq!(
        critical_action.voting_duration_parameters(
            &slow_nervous_system_parameters,
            ProposalCriticality::Critical
        ),
        VotingDurationParameters {
            initial_voting_period: PbDuration {
                seconds: Some(7 * ONE_DAY_SECONDS),
            },
            wait_for_quiet_deadline_increase: PbDuration {
                seconds: Some(4 * ONE_DAY_SECONDS),
            }
        },
    );
}

#[test]
fn test_nervous_system_parameters_validate() {
    NervousSystemParameters::with_default_values()
        .validate()
        .unwrap();

    let invalid_params = vec![
        NervousSystemParameters {
            neuron_minimum_stake_e8s: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            transaction_fee_e8s: Some(100),
            neuron_minimum_stake_e8s: Some(10),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            transaction_fee_e8s: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_proposals_to_keep_per_action: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_proposals_to_keep_per_action: Some(0),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_proposals_to_keep_per_action: Some(
                NervousSystemParameters::MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING + 1,
            ),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            initial_voting_period_seconds: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            initial_voting_period_seconds: Some(
                NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_FLOOR - 1,
            ),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            initial_voting_period_seconds: Some(
                NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_CEILING + 1,
            ),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            default_followees: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_neurons: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_neurons: Some(0),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_neurons: Some(NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING + 1),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            neuron_minimum_dissolve_delay_to_vote_seconds: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_dissolve_delay_seconds: Some(10),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(20),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_followees_per_function: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_followees_per_function: Some(
                NervousSystemParameters::MAX_FOLLOWEES_PER_FUNCTION_CEILING + 1,
            ),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_dissolve_delay_seconds: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_neuron_age_for_age_bonus: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_proposals_with_ballots: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_proposals_with_ballots: Some(0),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_proposals_with_ballots: Some(
                NervousSystemParameters::MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING + 1,
            ),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: vec![NeuronPermissionType::Vote as i32],
            }),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            neuron_claimer_permissions: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            neuron_grantable_permissions: None,
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_principals_per_neuron: Some(0),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_principals_per_neuron: Some(1000),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            voting_rewards_parameters: Some(VotingRewardsParameters {
                round_duration_seconds: None,
                ..Default::default()
            }),
            ..NervousSystemParameters::with_default_values()
        },
        NervousSystemParameters {
            max_number_of_principals_per_neuron: Some(4),
            ..NervousSystemParameters::with_default_values()
        },
    ];

    for params in invalid_params {
        params.validate().unwrap_err();
    }
}

#[test]
fn test_inherit_from() {
    let default_params = NervousSystemParameters::with_default_values();

    let proposed_params = NervousSystemParameters {
        transaction_fee_e8s: Some(124),
        max_number_of_neurons: Some(566),
        max_number_of_proposals_with_ballots: Some(9801),
        default_followees: Some(Default::default()),

        // Set all other fields to None.
        ..Default::default()
    };

    let new_params = proposed_params.inherit_from(&default_params);
    let expected_params = NervousSystemParameters {
        transaction_fee_e8s: Some(124),
        max_number_of_neurons: Some(566),
        max_number_of_proposals_with_ballots: Some(9801),
        default_followees: Some(Default::default()),
        ..default_params.clone()
    };

    assert_eq!(new_params, expected_params);

    assert_eq!(new_params.maturity_modulation_disabled, Some(false));

    let disable_maturity_modulation = NervousSystemParameters {
        maturity_modulation_disabled: Some(true),

        // Set all other fields to None.
        ..Default::default()
    };

    assert_eq!(
        disable_maturity_modulation.inherit_from(&default_params),
        NervousSystemParameters {
            maturity_modulation_disabled: Some(true),
            ..default_params
        },
    );
}

lazy_static! {
    static ref MANAGE_NEURON_COMMANDS: (Vec<manage_neuron::Command>, Vec<manage_neuron::Command>, manage_neuron::Command) = {
        use manage_neuron::Command;

        #[rustfmt::skip]
        let allowed_in_pre_initialization_swap = vec! [
            Command::Follow                  (Default::default()),
            Command::MakeProposal            (Default::default()),
            Command::RegisterVote            (Default::default()),
            Command::AddNeuronPermissions    (Default::default()),
            Command::RemoveNeuronPermissions (Default::default()),
        ];

        #[rustfmt::skip]
        let disallowed_in_pre_initialization_swap = vec! [
            Command::Configure        (Default::default()),
            Command::Disburse         (Default::default()),
            Command::Split            (Default::default()),
            Command::MergeMaturity    (Default::default()),
            Command::DisburseMaturity (Default::default()),
        ];

        // Only the swap canister is allowed to do this in PreInitializationSwap.
        let claim_or_refresh = Command::ClaimOrRefresh(Default::default());

        (allowed_in_pre_initialization_swap, disallowed_in_pre_initialization_swap, claim_or_refresh)
    };
}

#[should_panic]
#[test]
fn test_mode_allows_manage_neuron_command_or_err_unspecified_kaboom() {
    let caller_is_swap_canister = true;
    let innocuous_command = &MANAGE_NEURON_COMMANDS.0[0];
    let _clippy = governance::Mode::Unspecified
        .allows_manage_neuron_command_or_err(innocuous_command, caller_is_swap_canister);
}

#[test]
fn test_mode_allows_manage_neuron_command_or_err_normal_is_generally_ok() {
    let mut commands = MANAGE_NEURON_COMMANDS.0.clone();
    commands.append(&mut MANAGE_NEURON_COMMANDS.1.clone());
    commands.push(MANAGE_NEURON_COMMANDS.2.clone());

    for command in commands {
        for caller_is_swap_canister in [true, false] {
            let result = governance::Mode::Normal
                .allows_manage_neuron_command_or_err(&command, caller_is_swap_canister);
            assert!(result.is_ok(), "{result:#?}");
        }
    }
}

#[test]
fn test_mode_allows_manage_neuron_command_or_err_pre_initialization_swap_ok() {
    let allowed = &MANAGE_NEURON_COMMANDS.0;
    for command in allowed {
        for caller_is_swap_canister in [true, false] {
            let result = PreInitializationSwap
                .allows_manage_neuron_command_or_err(command, caller_is_swap_canister);
            assert!(result.is_ok(), "{result:#?}");
        }
    }
}

#[test]
fn test_mode_allows_manage_neuron_command_or_err_pre_initialization_swap_verboten() {
    let disallowed = &MANAGE_NEURON_COMMANDS.1;
    for command in disallowed {
        for caller_is_swap_canister in [true, false] {
            let result = PreInitializationSwap
                .allows_manage_neuron_command_or_err(command, caller_is_swap_canister);
            assert!(result.is_err(), "{result:#?}");
        }
    }
}

#[test]
fn test_mode_allows_manage_neuron_command_or_err_pre_initialization_swap_claim_or_refresh() {
    let claim_or_refresh = &MANAGE_NEURON_COMMANDS.2;

    let caller_is_swap_canister = false;
    let result = PreInitializationSwap
        .allows_manage_neuron_command_or_err(claim_or_refresh, caller_is_swap_canister);
    assert!(result.is_err(), "{result:#?}");

    let caller_is_swap_canister = true;
    let result = PreInitializationSwap
        .allows_manage_neuron_command_or_err(claim_or_refresh, caller_is_swap_canister);
    assert!(result.is_ok(), "{result:#?}");
}

const ROOT_TARGETING_FUNCTION_ID: u64 = 1001;
const GOVERNANCE_TARGETING_FUNCTION_ID: u64 = 1002;
const LEDGER_TARGETING_FUNCTION_ID: u64 = 1003;
const RANDOM_CANISTER_TARGETING_FUNCTION_ID: u64 = 1004;

#[rustfmt::skip]
lazy_static! {
    static ref       ROOT_CANISTER_ID: PrincipalId =                    [101][..].try_into().unwrap();
    static ref GOVERNANCE_CANISTER_ID: PrincipalId =                    [102][..].try_into().unwrap();
    static ref     LEDGER_CANISTER_ID: PrincipalId =                    [103][..].try_into().unwrap();
    static ref     RANDOM_CANISTER_ID: PrincipalId = [0xDE, 0xAD, 0xBE, 0xEF][..].try_into().unwrap();

    static ref PROPOSAL_ACTIONS: (
        Vec<Action>, // Allowed    in PreInitializationSwap.
        Vec<Action>, // Disallowed in PreInitializationSwap.
        Vec<Action>, // ExecuteGenericNervousSystemFunction where target is root, governance, or ledger
        Action,      // ExecuteGenericNervousSystemFunction, but target is not one of the distinguished canisters.
    ) = {
        let allowed_in_pre_initialization_swap = vec! [
            Action::Motion(Default::default()),
            Action::AddGenericNervousSystemFunction(Default::default()),
            Action::RemoveGenericNervousSystemFunction(Default::default()),
        ]; 

        let disallowed_in_pre_initialization_swap = vec! [
            Action::ManageNervousSystemParameters(Default::default()),
            Action::TransferSnsTreasuryFunds(Default::default()),
            Action::MintSnsTokens(Default::default()),
            Action::UpgradeSnsControlledCanister(Default::default()),
            Action::RegisterDappCanisters(Default::default()),
            Action::DeregisterDappCanisters(Default::default()),
        ];

        // Conditionally allow: No targeting SNS canisters.
        fn execute(function_id: u64) -> Action {
            Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
                function_id,
                ..Default::default()
            })
        }

        let target_sns_canister_actions = vec! [
            execute(      ROOT_TARGETING_FUNCTION_ID),
            execute(GOVERNANCE_TARGETING_FUNCTION_ID),
            execute(    LEDGER_TARGETING_FUNCTION_ID),
        ];

        let target_random_canister_action = execute(RANDOM_CANISTER_TARGETING_FUNCTION_ID);

        (
            allowed_in_pre_initialization_swap,
            disallowed_in_pre_initialization_swap,
            target_sns_canister_actions,
            target_random_canister_action
        )
    };

    static ref ID_TO_NERVOUS_SYSTEM_FUNCTION: BTreeMap<u64, NervousSystemFunction> = {
        fn new_fn(function_id: u64, target_canister_id: &PrincipalId) -> NervousSystemFunction {
            NervousSystemFunction {
                id: function_id,
                name: "Amaze".to_string(),
                description: Some("Best function evar.".to_string()),
                function_type: Some(FunctionType::GenericNervousSystemFunction(GenericNervousSystemFunction {
                    target_canister_id: Some(*target_canister_id),
                    target_method_name: Some("Foo".to_string()),
                    validator_canister_id: Some(*target_canister_id),
                    validator_method_name: Some("Bar".to_string()),
                    topic: Some(Topic::Governance as i32),
                })),
            }
        }

        vec![
            new_fn(           ROOT_TARGETING_FUNCTION_ID,       &ROOT_CANISTER_ID),
            new_fn(     GOVERNANCE_TARGETING_FUNCTION_ID, &GOVERNANCE_CANISTER_ID),
            new_fn(         LEDGER_TARGETING_FUNCTION_ID,     &LEDGER_CANISTER_ID),
            new_fn(RANDOM_CANISTER_TARGETING_FUNCTION_ID,     &RANDOM_CANISTER_ID),
        ]
        .into_iter()
        .map(|f| (f.id, f))
        .collect()
    };

    static ref DISALLOWED_TARGET_CANISTER_IDS: HashSet<CanisterId> = hashset! {
        CanisterId::unchecked_from_principal(*ROOT_CANISTER_ID),
        CanisterId::unchecked_from_principal(*GOVERNANCE_CANISTER_ID),
        CanisterId::unchecked_from_principal(*LEDGER_CANISTER_ID),
    };
}

#[should_panic]
#[test]
fn test_mode_allows_proposal_action_or_err_unspecified_kaboom() {
    let innocuous_action = &PROPOSAL_ACTIONS.0[0];
    let _clippy = governance::Mode::Unspecified.allows_proposal_action_or_err(
        innocuous_action,
        &DISALLOWED_TARGET_CANISTER_IDS,
        &ID_TO_NERVOUS_SYSTEM_FUNCTION,
    );
}

#[test]
fn test_mode_allows_proposal_action_or_err_normal_is_always_ok() {
    // Flatten PROPOSAL_ACTIONS into one big Vec.
    let mut actions = PROPOSAL_ACTIONS.0.clone();
    actions.append(&mut PROPOSAL_ACTIONS.1.clone());
    actions.append(&mut PROPOSAL_ACTIONS.2.clone());
    actions.push(PROPOSAL_ACTIONS.3.clone());

    for action in actions {
        let result = governance::Mode::Normal.allows_proposal_action_or_err(
            &action,
            &DISALLOWED_TARGET_CANISTER_IDS,
            &ID_TO_NERVOUS_SYSTEM_FUNCTION,
        );
        assert!(result.is_ok(), "{result:#?} {action:#?}");
    }
}

#[test]
fn test_mode_allows_proposal_action_or_err_pre_initialization_swap_happy() {
    for action in &PROPOSAL_ACTIONS.0 {
        let result = PreInitializationSwap.allows_proposal_action_or_err(
            action,
            &DISALLOWED_TARGET_CANISTER_IDS,
            &ID_TO_NERVOUS_SYSTEM_FUNCTION,
        );
        assert!(result.is_ok(), "{result:#?} {action:#?}");
    }
}

#[test]
fn test_mode_allows_proposal_action_or_err_pre_initialization_swap_sad() {
    for action in &PROPOSAL_ACTIONS.1 {
        let result = PreInitializationSwap.allows_proposal_action_or_err(
            action,
            &DISALLOWED_TARGET_CANISTER_IDS,
            &ID_TO_NERVOUS_SYSTEM_FUNCTION,
        );
        assert!(result.is_err(), "{action:#?}");
    }
}

#[test]
fn test_mode_allows_proposal_action_or_err_pre_initialization_swap_disallows_targeting_an_sns_canister()
 {
    for action in &PROPOSAL_ACTIONS.2 {
        let result = PreInitializationSwap.allows_proposal_action_or_err(
            action,
            &DISALLOWED_TARGET_CANISTER_IDS,
            &ID_TO_NERVOUS_SYSTEM_FUNCTION,
        );
        assert!(result.is_err(), "{action:#?}");
    }
}

#[test]
fn test_mode_allows_proposal_action_or_err_pre_initialization_swap_allows_targeting_a_random_canister()
 {
    let action = &PROPOSAL_ACTIONS.3;
    let result = PreInitializationSwap.allows_proposal_action_or_err(
        action,
        &DISALLOWED_TARGET_CANISTER_IDS,
        &ID_TO_NERVOUS_SYSTEM_FUNCTION,
    );
    assert!(result.is_ok(), "{result:#?} {action:#?}");
}

#[test]
fn test_mode_allows_proposal_action_or_err_function_not_found() {
    let execute =
        Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
            function_id: 0xDEADBEF,
            ..Default::default()
        });

    let result = governance::Mode::PreInitializationSwap.allows_proposal_action_or_err(
        &execute,
        &DISALLOWED_TARGET_CANISTER_IDS,
        &ID_TO_NERVOUS_SYSTEM_FUNCTION,
    );

    let err = match result {
        Err(err) => err,
        Ok(_) => panic!(
            "Make proposal is supposed to result in NotFound when \
                it specifies an unknown function ID."
        ),
    };
    assert_eq!(err.error_type, ErrorType::NotFound as i32, "{err:#?}");
}

#[should_panic]
#[test]
fn test_mode_allows_proposal_action_or_err_panic_when_function_has_no_type() {
    let function_id = 42;

    let execute =
        Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
            function_id,
            ..Default::default()
        });

    let mut functions = ID_TO_NERVOUS_SYSTEM_FUNCTION.clone();
    functions.insert(
        function_id,
        NervousSystemFunction {
            id: function_id,
            function_type: None, // This is evil.
            name: "Toxic".to_string(),
            description: None,
        },
    );

    let _unused = governance::Mode::PreInitializationSwap.allows_proposal_action_or_err(
        &execute,
        &DISALLOWED_TARGET_CANISTER_IDS,
        &functions,
    );
}

#[should_panic]
#[test]
fn test_mode_allows_proposal_action_or_err_panic_when_function_has_no_target_canister_id() {
    let function_id = 42;

    let execute =
        Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
            function_id,
            ..Default::default()
        });

    let mut functions = ID_TO_NERVOUS_SYSTEM_FUNCTION.clone();
    functions.insert(
        function_id,
        NervousSystemFunction {
            id: function_id,
            name: "Toxic".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: None, // This is evil.
                    ..Default::default()
                },
            )),
        },
    );

    let _unused = governance::Mode::PreInitializationSwap.allows_proposal_action_or_err(
        &execute,
        &DISALLOWED_TARGET_CANISTER_IDS,
        &functions,
    );
}

#[test]
fn test_sns_metadata_validate() {
    let default = SnsMetadata {
        logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
        url: Some("https://forum.dfinity.org".to_string()),
        name: Some("X".repeat(SnsMetadata::MIN_NAME_LENGTH)),
        description: Some("X".repeat(SnsMetadata::MIN_DESCRIPTION_LENGTH)),
    };

    let valid_sns_metadata = vec![
        default.clone(),
        SnsMetadata {
            url: Some("https://forum.dfinity.org/foo/bar/?".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("https://forum.dfinity.org/foo/bar/?".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("https://any-url.com/foo/bar/?".to_string()),
            ..default.clone()
        },
    ];

    let invalid_sns_metadata = vec![
        SnsMetadata {
            name: None,
            ..default.clone()
        },
        SnsMetadata {
            name: Some("X".repeat(SnsMetadata::MAX_NAME_LENGTH + 1)),
            ..default.clone()
        },
        SnsMetadata {
            name: Some("X".repeat(SnsMetadata::MIN_NAME_LENGTH - 1)),
            ..default.clone()
        },
        SnsMetadata {
            description: None,
            ..default.clone()
        },
        SnsMetadata {
            description: Some("X".repeat(SnsMetadata::MAX_DESCRIPTION_LENGTH + 1)),
            ..default.clone()
        },
        SnsMetadata {
            description: Some("X".repeat(SnsMetadata::MIN_DESCRIPTION_LENGTH - 1)),
            ..default.clone()
        },
        SnsMetadata {
            logo: Some("X".repeat(MAX_LOGO_LENGTH + 1)),
            ..default.clone()
        },
        SnsMetadata {
            url: None,
            ..default.clone()
        },
        SnsMetadata {
            url: Some("X".repeat(SnsMetadata::MAX_URL_LENGTH + 1)),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("X".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("X".repeat(SnsMetadata::MIN_URL_LENGTH - 1)),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("file://forum.dfinity.org".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("https://".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("https://forum.dfinity.org/https://forum.dfinity.org".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("https://example@forum.dfinity.org".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("http://internetcomputer".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("mailto:example@internetcomputer.org".to_string()),
            ..default.clone()
        },
        SnsMetadata {
            url: Some("internetcomputer".to_string()),
            ..default
        },
    ];

    for sns_metadata in invalid_sns_metadata {
        if sns_metadata.validate().is_ok() {
            panic!("Invalid metadata passed validation: {sns_metadata:?}");
        }
    }

    for sns_metadata in valid_sns_metadata {
        if sns_metadata.validate().is_err() {
            panic!("Valid metadata failed validation: {sns_metadata:?}");
        }
    }
}

impl NeuronRecipe {
    fn validate_default_direct_participant() -> Self {
        Self {
            controller: Some(*TEST_USER1_PRINCIPAL),
            neuron_id: Some(NeuronId::new_test_neuron_id(0)),
            stake_e8s: Some(E8S_PER_TOKEN),
            dissolve_delay_seconds: Some(3 * ONE_MONTH_SECONDS),
            followees: Some(NeuronIds::from(vec![NeuronId::new_test_neuron_id(1)])),
            participant: Some(Participant::Direct(neuron_recipe::Direct {})),
        }
    }

    fn validate_default_neurons_fund() -> Self {
        Self {
            controller: Some(PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID)),
            neuron_id: Some(NeuronId::new_test_neuron_id(0)),
            stake_e8s: Some(E8S_PER_TOKEN),
            dissolve_delay_seconds: Some(3 * ONE_MONTH_SECONDS),
            followees: Some(NeuronIds::from(vec![NeuronId::new_test_neuron_id(1)])),
            participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id: Some(2),
                nns_neuron_controller: Some(PrincipalId::new_user_test_id(13847)),
                nns_neuron_hotkeys: Some(Principals::from(vec![
                    PrincipalId::new_user_test_id(13848),
                    PrincipalId::new_user_test_id(13849),
                ])),
            })),
        }
    }
}

mod neuron_recipe_validate_tests {
    use super::*;

    const NEURON_MINIMUM_STAKE_E8S: u64 = E8S_PER_TOKEN;
    const MAX_FOLLOWEES_PER_FUNCTION: u64 = 1;
    const MAX_NUMBER_OF_PRINCIPALS_PER_NEURON: u64 = 5;

    fn validate_recipe(recipe: &NeuronRecipe) -> Result<(), String> {
        recipe.validate(
            NEURON_MINIMUM_STAKE_E8S,
            MAX_FOLLOWEES_PER_FUNCTION,
            MAX_NUMBER_OF_PRINCIPALS_PER_NEURON,
        )
    }

    #[test]
    fn test_default_direct_participant_is_valid() {
        validate_recipe(&NeuronRecipe::validate_default_direct_participant()).unwrap();
    }

    #[test]
    fn test_default_neurons_fund_is_valid() {
        validate_recipe(&NeuronRecipe::validate_default_neurons_fund()).unwrap();
    }

    #[test]
    fn test_invalid_missing_controller() {
        let recipe = NeuronRecipe {
            controller: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_missing_neuron_id() {
        let recipe = NeuronRecipe {
            neuron_id: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_missing_stake() {
        let recipe = NeuronRecipe {
            stake_e8s: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_low_stake() {
        let recipe = NeuronRecipe {
            stake_e8s: Some(NEURON_MINIMUM_STAKE_E8S - 1),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_missing_dissolve_delay() {
        let recipe = NeuronRecipe {
            dissolve_delay_seconds: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_missing_followees() {
        let recipe = NeuronRecipe {
            followees: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_too_many_followees() {
        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![
                NeuronId::new_test_neuron_id(1),
                NeuronId::new_test_neuron_id(2),
            ])),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_missing_participant() {
        let recipe = NeuronRecipe {
            participant: None,
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_neurons_fund_missing_nns_neuron_id() {
        let recipe = NeuronRecipe {
            participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id: None,
                nns_neuron_controller: Some(PrincipalId::new_user_test_id(13847)),
                nns_neuron_hotkeys: Some(Principals::from(vec![PrincipalId::new_user_test_id(
                    13848,
                )])),
            })),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_neurons_fund_missing_controller() {
        let recipe = NeuronRecipe {
            participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id: Some(2),
                nns_neuron_controller: None,
                nns_neuron_hotkeys: Some(Principals::from(vec![PrincipalId::new_user_test_id(
                    13848,
                )])),
            })),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_neurons_fund_missing_hotkeys() {
        let recipe = NeuronRecipe {
            participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id: Some(2),
                nns_neuron_controller: Some(PrincipalId::new_user_test_id(13847)),
                nns_neuron_hotkeys: None,
            })),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_invalid_neurons_fund_too_many_hotkeys() {
        let recipe = NeuronRecipe {
            participant: Some(Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                nns_neuron_id: Some(2),
                nns_neuron_controller: Some(PrincipalId::new_user_test_id(13847)),
                nns_neuron_hotkeys: Some(Principals::from(vec![
                    PrincipalId::new_user_test_id(13848),
                    PrincipalId::new_user_test_id(13849),
                    PrincipalId::new_user_test_id(13810),
                    PrincipalId::new_user_test_id(13811),
                    PrincipalId::new_user_test_id(13812),
                ])),
            })),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        validate_recipe(&recipe).unwrap_err();
    }

    #[test]
    fn test_valid_zero_dissolve_delay() {
        let recipe = NeuronRecipe {
            dissolve_delay_seconds: Some(0),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap();
    }

    #[test]
    fn test_valid_empty_followees() {
        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![])),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        validate_recipe(&recipe).unwrap();
    }

    #[test]
    fn test_valid_minimum_stake() {
        let recipe = NeuronRecipe {
            stake_e8s: Some(NEURON_MINIMUM_STAKE_E8S),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        validate_recipe(&recipe).unwrap();
    }
}

#[test]
fn test_voting_rewards_parameters_set_to_zero_by_default() {
    let parameters = NervousSystemParameters::with_default_values();
    parameters.validate().unwrap();
    let voting_rewards_parameters = parameters.voting_rewards_parameters.unwrap();
    assert_eq!(
        voting_rewards_parameters
            .initial_reward_rate_basis_points
            .unwrap(),
        0
    );
    assert_eq!(
        voting_rewards_parameters
            .final_reward_rate_basis_points
            .unwrap(),
        0
    );
}

#[test]
#[should_panic]
fn test_nervous_system_parameters_wont_validate_without_voting_rewards_parameters() {
    let mut parameters = NervousSystemParameters::with_default_values();
    parameters.voting_rewards_parameters = None;
    // This is where we expect to panic.
    parameters.validate().unwrap();
}

#[test]
fn test_nervous_system_parameters_wont_validate_without_the_required_claimer_permissions() {
    for permission_to_omit in NervousSystemParameters::REQUIRED_NEURON_CLAIMER_PERMISSIONS {
        let mut parameters = NervousSystemParameters::with_default_values();
        parameters.neuron_claimer_permissions = Some(
            NervousSystemParameters::REQUIRED_NEURON_CLAIMER_PERMISSIONS
                .iter()
                .filter(|p| *p != permission_to_omit)
                .cloned()
                .collect::<Vec<_>>()
                .into(),
        );
        parameters.validate().unwrap_err();
    }
}

#[test]
fn test_validate_logo_lets_base64_through() {
    SnsMetadata::validate_logo("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==").unwrap();
}

#[test]
fn test_validate_logo_doesnt_let_non_base64_through() {
    // `_` is not in the base64 character set we're using
    // so we should panic here.
    SnsMetadata::validate_logo("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==_").unwrap_err();
}

#[test]
fn test_neuron_permission_list_display_impl() {
    let neuron_permission_list = NeuronPermissionList::all();
    assert_eq!(
        format!("permissions: {neuron_permission_list}"),
        format!(
            "permissions: [Unspecified, ConfigureDissolveState, ManagePrincipals, SubmitProposal, Vote, Disburse, Split, MergeMaturity, DisburseMaturity, StakeMaturity, ManageVotingPermission]"
        )
    );
}

#[test]
fn test_neuron_permission_list_display_impl_doesnt_panic_unknown_permission() {
    let invalid_permission = 10000;
    let neuron_permission_list = {
        let mut neuron_permission_list = NeuronPermissionList::all();
        neuron_permission_list.permissions.push(invalid_permission); // Add an unknown permission to the list
        neuron_permission_list
    };
    assert_eq!(
        format!("permissions: {neuron_permission_list}"),
        format!(
            "permissions: [Unspecified, ConfigureDissolveState, ManagePrincipals, SubmitProposal, Vote, Disburse, Split, MergeMaturity, DisburseMaturity, StakeMaturity, ManageVotingPermission, <Invalid permission ({invalid_permission})>]"
        )
    );
}

mod neuron_recipe_construct_topic_followees_tests {
    use super::*;

    #[test]
    fn test_direct_participant_empty_followees() {
        let [b0] = NeuronId::test_neuron_ids();
        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![])),
            neuron_id: Some(b0.clone()),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees::default()
        );
    }

    #[test]
    fn test_direct_participant_single_followee() {
        let [b0, b1] = NeuronId::test_neuron_ids();

        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![b0.clone()])),
            neuron_id: Some(b1.clone()),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees {
                topic_id_to_followees: btreemap! {
                    1 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(1) },
                    2 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(2) },
                    3 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(3) },
                    4 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(4) },
                    5 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(5) },
                    6 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(6) },
                    7 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(7) },
                }
            }
        );
    }

    #[test]
    fn test_direct_participant_multiple_followees() {
        let [b0, b1, b2] = NeuronId::test_neuron_ids();

        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![b0.clone(), b1.clone()])),
            neuron_id: Some(b2.clone()),
            ..NeuronRecipe::validate_default_direct_participant()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees {
                topic_id_to_followees: btreemap! {
                    1 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(1) },
                    2 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(2) },
                    3 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(3) },
                    4 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(4) },
                    5 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(5) },
                    6 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(6) },
                    7 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }], topic: Some(7) },
                }
            }
        );
    }

    #[test]
    fn test_neurons_fund_empty_followees() {
        let [b1] = NeuronId::test_neuron_ids();
        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![])),
            neuron_id: Some(b1.clone()),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees::default()
        );
    }

    #[test]
    fn test_neurons_fund_single_followee() {
        let [b0, b1] = NeuronId::test_neuron_ids();

        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![b0.clone()])),
            neuron_id: Some(b1.clone()),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees {
                topic_id_to_followees: btreemap! {
                    1 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(1) },
                    2 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(2) },
                    3 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(3) },
                    4 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(4) },
                    5 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(5) },
                    6 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(6) },
                    7 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Neuron-basket-main".to_string()) }], topic: Some(7) },
                }
            }
        );
    }

    #[test]
    fn test_neurons_fund_multiple_followees() {
        let [b0, b1, b2, b3] = NeuronId::test_neuron_ids();

        let recipe = NeuronRecipe {
            followees: Some(NeuronIds::from(vec![b0.clone(), b1.clone(), b2.clone()])),
            neuron_id: Some(b3.clone()),
            ..NeuronRecipe::validate_default_neurons_fund()
        };
        assert_eq!(
            recipe.construct_topic_followees(),
            TopicFollowees {
                topic_id_to_followees: btreemap! {
                    1 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(1) },
                    2 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(2) },
                    3 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(3) },
                    4 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(4) },
                    5 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(5) },
                    6 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(6) },
                    7 => FolloweesForTopic { followees: vec![Followee { neuron_id: Some(b0.clone()), alias: Some("Followee-0".to_string()) }, Followee { neuron_id: Some(b1.clone()), alias: Some("Followee-1".to_string()) }, Followee { neuron_id: Some(b2.clone()), alias: Some("Followee-2".to_string()) }], topic: Some(7) },
                }
            }
        );
    }
}

#[test]
fn test_summarize_blob_field() {
    for len in 0..=64 {
        let direct_copy_input = (0..len).collect::<Vec<u8>>();

        assert_eq!(summarize_blob_field(&direct_copy_input), direct_copy_input);
    }

    let too_long = (0..65).collect::<Vec<u8>>();
    let result = summarize_blob_field(&too_long);
    assert_ne!(result, too_long);
    assert!(result.len() > 64, "{result:X?}");

    let result = String::from_utf8(summarize_blob_field(&too_long)).unwrap();
    assert!(
        result.contains("⚠️ NOT THE ORIGINAL CONTENTS OF THIS FIELD ⚠"),
        "{result:X?}",
    );
    assert!(result.contains("00 01 02 03"), "{result:X?}");
    assert!(result.contains("3D 3E 3F 40"), "{result:X?}");
    assert!(result.contains("Length: 65"), "{result:X?}");
    assert!(
        // SHA256
        result.contains(
            // Independently calculating using Python.
            "4B FD 2C 8B 6F 1E EC 7A \
                2A FE B4 8B 93 4E E4 B2 \
                69 41 82 02 7E 6D 0F C0 \
                75 07 4F 2F AB B3 17 81",
        ),
        "{result:X?}",
    );
}

#[test]
fn test_limited_for_get_proposal() {
    let motion_proposal = ProposalData {
        proposal: Some(Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: "Hello, world!".to_string(),
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(motion_proposal.limited_for_get_proposal(), motion_proposal,);

    let upgrade_sns_controlled_canister_proposal = ProposalData {
        proposal: Some(Proposal {
            action: Some(Action::UpgradeSnsControlledCanister(
                UpgradeSnsControlledCanister {
                    new_canister_wasm: (0..=255).collect(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_ne!(
        upgrade_sns_controlled_canister_proposal.limited_for_get_proposal(),
        upgrade_sns_controlled_canister_proposal,
    );

    let execute_generic_nervous_system_function_proposal = ProposalData {
        proposal: Some(Proposal {
            action: Some(Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    payload: (0..=255).collect(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_ne!(
        execute_generic_nervous_system_function_proposal.limited_for_get_proposal(),
        execute_generic_nervous_system_function_proposal,
    );
}

#[test]
fn test_validate_chunked_wasm_happy() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();
    let response = Ok(Encode!(&StoredChunksReply(vec![
        ChunkHash {
            hash: vec![4, 4, 4]
        },
        ChunkHash {
            hash: vec![2, 2, 2]
        },
        ChunkHash {
            hash: vec![3, 3, 3]
        },
        ChunkHash {
            hash: vec![1, 1, 1]
        },
    ]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    let chunk_hashes_list = vec![vec![1, 1, 1], vec![2, 2, 2], vec![3, 3, 3]];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Ok(()),
    );
}

// TODO[NNS1-3550]: Enable stored chunks validation on mainnet.
#[cfg(feature = "test")]
#[test]
fn test_validate_chunked_wasm_not_uploaded_some_chunks() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();
    let response = Ok(Encode!(&StoredChunksReply(vec![
        ChunkHash {
            hash: vec![4, 4, 4]
        },
        ChunkHash {
            hash: vec![2, 2, 2]
        },
        ChunkHash {
            hash: vec![3, 3, 3]
        },
        ChunkHash {
            hash: vec![1, 1, 1]
        },
    ]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    let chunk_hashes_list = vec![
        vec![1, 1, 1],
        // The problem is here.
        vec![3, 2, 1],
        vec![3, 3, 3],
    ];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Err(vec![
            "1 out of 3 expected WASM chunks were not uploaded to the store canister: 030201"
                .to_string()
        ]),
    );
}

#[test]
fn test_validate_chunked_wasm_one_chunk_happy() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();
    let response = Ok(Encode!(&StoredChunksReply(vec![
        ChunkHash {
            hash: vec![4, 4, 4]
        },
        ChunkHash {
            hash: vec![1, 2, 3]
        },
        ChunkHash {
            hash: vec![3, 3, 3]
        },
        ChunkHash {
            hash: vec![1, 1, 1]
        },
    ]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    let chunk_hashes_list = vec![vec![1, 2, 3]];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Ok(()),
    );
}

#[test]
fn test_validate_chunked_wasm_one_chunk_hash_mismatch() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();
    let response = Ok(Encode!(&StoredChunksReply(vec![
        ChunkHash {
            hash: vec![4, 4, 4]
        },
        ChunkHash {
            hash: vec![2, 2, 2]
        },
        ChunkHash {
            hash: vec![3, 3, 3]
        },
        ChunkHash {
            hash: vec![1, 1, 1]
        },
    ]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    // The issue is here.
    let wasm_module_hash = vec![1, 2, 3];
    let chunk_hashes_list = vec![vec![2, 2, 2]];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Err(vec![
            "chunked_canister_wasm.chunk_hashes_list specifies only one hash (020202), but it \
             differs from chunked_canister_wasm.wasm_module_hash (010203)."
                .to_string()
        ]),
    );
}

#[test]
fn test_validate_chunked_wasm_chunk_hashes_list_empty() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();
    let response = Ok(Encode!(&StoredChunksReply(vec![
        ChunkHash {
            hash: vec![4, 4, 4]
        },
        ChunkHash {
            hash: vec![1, 2, 3]
        },
        ChunkHash {
            hash: vec![3, 3, 3]
        },
        ChunkHash {
            hash: vec![1, 1, 1]
        },
    ]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    // The issue is here.
    let chunk_hashes_list = vec![];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Err(vec![
            "chunked_canister_wasm.chunk_hashes_list cannot be empty.".to_string()
        ]),
    );
}

// TODO[NNS1-3550]: Enable stored chunks validation on mainnet.
#[cfg(feature = "test")]
#[test]
fn test_validate_chunked_wasm_management_canister_call_fails() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);
    let arg = Encode!(&CanisterIdRecord::from(store_canister_id)).unwrap();

    // This is the problem.
    let response = Err((Some(404), "No such canister".to_string()));
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    // The issue is here.
    let chunk_hashes_list = vec![vec![1, 2, 3]];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Err(vec![format!(
            "Cannot call stored_chunks for {}: (Some(404), \"No such canister\")",
            store_canister_id
        )]),
    );
}

// TODO[NNS1-3550]: Enable stored chunks validation on mainnet.
#[cfg(feature = "test")]
#[test]
fn test_validate_chunked_wasm_management_canister_call_returns_junk() {
    let store_canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(42));

    let mut env = NativeEnvironment::new(None);

    // This is causing the problem (incorrect response type `PrincipalId` / `CanisterIdRecord`).
    let arg = Encode!(&PrincipalId::new_user_test_id(888)).unwrap();

    let response = Ok(Encode!(&StoredChunksReply(vec![ChunkHash {
        hash: vec![1, 2, 3]
    },]))
    .unwrap());
    env.set_call_canister_response(CanisterId::ic_00(), "stored_chunks", arg, response);

    let wasm_module_hash = vec![1, 2, 3];

    // The issue is here.
    let chunk_hashes_list = vec![vec![1, 2, 3]];

    assert_eq!(
        validate_chunked_wasm(
            &env,
            &wasm_module_hash,
            store_canister_id,
            &chunk_hashes_list
        )
        .now_or_never()
        .unwrap(),
        Err(vec![format!(
            "Cannot decode response from calling stored_chunks for {}: Cannot parse header ",
            store_canister_id
        )]),
    );
}

#[test]
fn test_from_manage_ledger_parameters_into_ledger_upgrade_args() {
    let manage_ledger_parameters = ManageLedgerParameters {
        transfer_fee: Some(111),
        token_name: Some("abc".to_string()),
        token_symbol: Some("xyz".to_string()),
        token_logo: Some("<logo>".to_string()),
    };

    let observed = LedgerUpgradeArgs::from(manage_ledger_parameters);

    assert_eq!(
        observed,
        LedgerUpgradeArgs {
            metadata: Some(vec![(
                MetadataKey::ICRC1_LOGO.to_string(),
                MetadataValue::Text("<logo>".to_string())
            )]),
            token_name: Some("abc".to_string()),
            token_symbol: Some("xyz".to_string()),
            transfer_fee: Some(Nat::from(111_u64)),
            change_fee_collector: None,
            max_memo_length: None,
            feature_flags: None,
            change_archive_options: None,
            index_principal: None,
        }
    );
}

#[test]
fn test_from_manage_ledger_parameters_into_ledger_upgrade_args_no_logo() {
    let manage_ledger_parameters = ManageLedgerParameters {
        transfer_fee: Some(111),
        token_name: Some("abc".to_string()),
        token_symbol: Some("xyz".to_string()),
        token_logo: None,
    };

    let observed = LedgerUpgradeArgs::from(manage_ledger_parameters);

    assert_eq!(
        observed,
        LedgerUpgradeArgs {
            metadata: None,
            token_name: Some("abc".to_string()),
            token_symbol: Some("xyz".to_string()),
            transfer_fee: Some(Nat::from(111_u64)),
            change_fee_collector: None,
            max_memo_length: None,
            feature_flags: None,
            change_archive_options: None,
            index_principal: None,
        }
    );
}
