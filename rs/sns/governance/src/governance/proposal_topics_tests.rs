use crate::{
    extensions::{ExtensionSpec, ExtensionType::TreasuryManager, ExtensionVersion},
    governance::{
        Governance, ValidGovernanceProto,
        test_helpers::{DoNothingLedger, basic_governance_proto},
    },
    pb::v1::{
        self as pb, ExecuteExtensionOperation, Topic::TreasuryAssetManagement,
        nervous_system_function,
    },
    storage::cache_registered_extension,
    types::{native_action_ids::nervous_system_functions, test_helpers::NativeEnvironment},
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_sns_governance_proposal_criticality::ProposalCriticality;
use maplit::btreemap;
use pb::{ExecuteGenericNervousSystemFunction, NervousSystemFunction};

#[test]
fn test_all_topics() {
    // Used to set the fields that are orthogonal to the test but required by the validation.
    let generic_proposal = nervous_system_function::GenericNervousSystemFunction {
        target_canister_id: Some(PrincipalId::new_user_test_id(111)),
        validator_canister_id: Some(PrincipalId::new_user_test_id(222)),
        target_method_name: Some("foo".to_string()),
        validator_method_name: Some("bar".to_string()),
        ..Default::default()
    };

    let custom_proposal_without_topic = NervousSystemFunction {
        id: 1002,
        name: "Custom proposal for tests".to_string(),
        description: None,
        function_type: Some(
            nervous_system_function::FunctionType::GenericNervousSystemFunction(
                nervous_system_function::GenericNervousSystemFunction {
                    topic: None,
                    // The following fields are orthogonal to the test but required in validation.
                    ..generic_proposal.clone()
                },
            ),
        ),
    };

    let custom_proposal_with_valid_topic = NervousSystemFunction {
        id: 1001,
        name: "Custom proposal for tests".to_string(),
        description: None,
        function_type: Some(
            nervous_system_function::FunctionType::GenericNervousSystemFunction(
                nervous_system_function::GenericNervousSystemFunction {
                    topic: Some(pb::Topic::ApplicationBusinessLogic as i32),
                    ..generic_proposal.clone()
                },
            ),
        ),
    };

    let governance_proto = pb::Governance {
        id_to_nervous_system_functions: btreemap! {
            1001 => custom_proposal_with_valid_topic,
            1002 => custom_proposal_without_topic,
        },
        ..basic_governance_proto()
    };

    let governance_proto = ValidGovernanceProto::try_from(governance_proto).unwrap();

    let governance = Governance::new(
        governance_proto,
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let mut test_cases = vec![
        // DaoCommunitySettings
        (
            pb::proposal::Action::ManageNervousSystemParameters(Default::default()),
            Ok((
                Some(pb::Topic::DaoCommunitySettings),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::ManageLedgerParameters(Default::default()),
            Ok((
                Some(pb::Topic::DaoCommunitySettings),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::ManageSnsMetadata(Default::default()),
            Ok((
                Some(pb::Topic::DaoCommunitySettings),
                ProposalCriticality::Critical,
            )),
        ),
        // SnsFrameworkManagement
        (
            pb::proposal::Action::UpgradeSnsToNextVersion(Default::default()),
            Ok((
                Some(pb::Topic::SnsFrameworkManagement),
                ProposalCriticality::Normal,
            )),
        ),
        (
            pb::proposal::Action::AdvanceSnsTargetVersion(Default::default()),
            Ok((
                Some(pb::Topic::SnsFrameworkManagement),
                ProposalCriticality::Normal,
            )),
        ),
        // DappCanisterManagement
        (
            pb::proposal::Action::UpgradeSnsControlledCanister(Default::default()),
            Ok((
                Some(pb::Topic::DappCanisterManagement),
                ProposalCriticality::Normal,
            )),
        ),
        (
            pb::proposal::Action::RegisterDappCanisters(Default::default()),
            Ok((
                Some(pb::Topic::DappCanisterManagement),
                ProposalCriticality::Normal,
            )),
        ),
        (
            pb::proposal::Action::ManageDappCanisterSettings(Default::default()),
            Ok((
                Some(pb::Topic::DappCanisterManagement),
                ProposalCriticality::Normal,
            )),
        ),
        // ApplicationBusinessLogic - skipped, since this topic is for custom proposals.

        // Governance
        (
            pb::proposal::Action::Motion(Default::default()),
            Ok((Some(pb::Topic::Governance), ProposalCriticality::Normal)),
        ),
        // TreasuryAssetManagement
        (
            pb::proposal::Action::TransferSnsTreasuryFunds(Default::default()),
            Ok((
                Some(pb::Topic::TreasuryAssetManagement),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::MintSnsTokens(Default::default()),
            Ok((
                Some(pb::Topic::TreasuryAssetManagement),
                ProposalCriticality::Critical,
            )),
        ),
        // CriticalDappOperations
        (
            pb::proposal::Action::DeregisterDappCanisters(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::AddGenericNervousSystemFunction(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::RemoveGenericNervousSystemFunction(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::SetTopicsForCustomProposals(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::RegisterExtension(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
        (
            pb::proposal::Action::UpgradeExtension(Default::default()),
            Ok((
                Some(pb::Topic::CriticalDappOperations),
                ProposalCriticality::Critical,
            )),
        ),
    ];

    // Smoke test
    assert_eq!(
        test_cases.len(),
        nervous_system_functions().len() - 2,
        "Missing some test cases for native proposals."
    );

    // Extension Test Cases
    let extension_canister_id = CanisterId::from_u64(100_000);
    let extension_spec = ExtensionSpec {
        name: "foo".to_string(),
        version: ExtensionVersion(1),
        topic: TreasuryAssetManagement,
        extension_type: TreasuryManager,
    };
    cache_registered_extension(extension_canister_id, extension_spec);
    test_cases.push((
        pb::proposal::Action::ExecuteExtensionOperation(ExecuteExtensionOperation {
            extension_canister_id: Some(extension_canister_id.get()),
            operation_name: Some("deposit".to_string()),
            operation_arg: None,
        }),
        Ok((
            Some(pb::Topic::TreasuryAssetManagement),
            ProposalCriticality::Critical,
        )),
    ));
    test_cases.push((
        pb::proposal::Action::ExecuteExtensionOperation(ExecuteExtensionOperation {
            extension_canister_id: Some(extension_canister_id.get()),
            operation_name: Some("withdraw".to_string()),
            operation_arg: None,
        }),
        Ok((
            Some(pb::Topic::TreasuryAssetManagement),
            ProposalCriticality::Critical,
        )),
    ));
    test_cases.push((
        pb::proposal::Action::ExecuteExtensionOperation(ExecuteExtensionOperation {
            extension_canister_id: Some(PrincipalId::new_user_test_id(11)),
            operation_name: Some("withdraw".to_string()),
            operation_arg: None,
        }),
        Err("Cannot interpret extension_canister_id as canister ID: \
            Got an invalid principal id Byte 8 (9th) of Principal ID \
            4zjg6-jalaa-aaaaa-aaaap-4ai is not 0x01: 0b00000000000000fe01"
            .to_string()),
    ));
    test_cases.push((
        pb::proposal::Action::ExecuteExtensionOperation(ExecuteExtensionOperation {
            extension_canister_id: Some(extension_canister_id.get()),
            operation_name: None,
            operation_arg: None,
        }),
        Err("operation_name is required.".to_string()),
    ));

    test_cases.push((
        pb::proposal::Action::ExecuteExtensionOperation(ExecuteExtensionOperation {
            extension_canister_id: Some(extension_canister_id.get()),
            operation_name: Some("other_op".to_string()),
            operation_arg: None,
        }),
        Err("No operation found called 'other_op' for extension with canister id: ug6pj-fqaaa-aaaaa-bq2qa-cai".to_string()),
    ));

    // Special case: Undefined function.
    test_cases.push((
        pb::proposal::Action::Unspecified(Default::default()),
        Err("Invalid action with ID 0.".to_string()),
    ));

    // Add test cases for custom proposals.
    test_cases.push((
        pb::proposal::Action::ExecuteGenericNervousSystemFunction(
            ExecuteGenericNervousSystemFunction {
                function_id: 1001,
                ..Default::default()
            },
        ),
        Ok((
            Some(pb::Topic::ApplicationBusinessLogic),
            ProposalCriticality::Normal,
        )),
    ));
    test_cases.push((
        pb::proposal::Action::ExecuteGenericNervousSystemFunction(
            ExecuteGenericNervousSystemFunction {
                function_id: 1002,
                ..Default::default()
            },
        ),
        // Fallback to ProposalCriticality::Normal; it happens when the function corresponds to
        // a custom proposal type for which a topic has not yet been selected.
        Ok((None, ProposalCriticality::Normal)),
    ));

    // Run code under test.
    for (action, expected) in test_cases.into_iter() {
        let observed = governance.get_topic_and_criticality_for_action(&action);
        assert_eq!(observed, expected);
    }
}
