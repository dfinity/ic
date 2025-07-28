use crate::governance::test_helpers::basic_governance_proto;
use crate::governance::ValidGovernanceProto;
use crate::governance::{test_helpers::DoNothingLedger, Governance};
use crate::pb::v1::{self as pb, nervous_system_function};
use crate::types::{native_action_ids::nervous_system_functions, test_helpers::NativeEnvironment};
use ic_base_types::PrincipalId;
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
        // TODO[NNS1-4002]. Criticality should depends on the topic of the extension.
        (
            pb::proposal::Action::ExecuteExtensionOperation(Default::default()),
            Ok((
                Some(pb::Topic::TreasuryAssetManagement),
                ProposalCriticality::Critical,
            )),
        ),
    ];

    // Smoke test
    assert_eq!(
        test_cases.len(),
        nervous_system_functions().len() - 1,
        "Missing some test cases for native proposals."
    );

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
