use super::test_helpers::{
    DoNothingLedger, TEST_GOVERNANCE_CANISTER_ID, TEST_ROOT_CANISTER_ID, basic_governance_proto,
};
use crate::{
    governance::{Governance, ValidGovernanceProto},
    pb::v1::{
        Ballot, FailStuckUpgradeInProgressRequest, FailStuckUpgradeInProgressResponse, GetProposal,
        Governance as GovernanceProto, Proposal, ProposalData, ProposalId, Tally,
        UpgradeSnsToNextVersion, Vote, WaitForQuietState, get_proposal_response,
        governance::{PendingVersion, Version},
        governance_error::ErrorType,
        proposal::Action,
    },
    types::test_helpers::NativeEnvironment,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_canisters::cmc::FakeCmc;
use lazy_static::lazy_static;
use maplit::btreemap;

const UPGRADE_DEADLINE_TIMESTAMP_SECONDS: u64 = 1_680_912_227;

const UPGRADE_PROPOSAL_ID: u64 = 12;

lazy_static! {
    static ref SNS_VERSION_1: Version = Version {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    static ref SNS_VERSION_2: Version = Version {
        archive_wasm_hash: vec![99, 99, 99],
        ..SNS_VERSION_1.clone()
    };

    static ref GOVERNANCE_PROTO: GovernanceProto = {
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});

        let proposal_data = ProposalData {
            action: (&action).into(),
            id: Some(ProposalId { id: UPGRADE_PROPOSAL_ID }),
            ballots: btreemap! {
                "neuron 1".to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 9001,
                    cast_timestamp_seconds: 1,
                },
            },
            wait_for_quiet_state: Some(WaitForQuietState::default()),
            decided_timestamp_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS - 60,
            proposal: Some(Proposal {
                title: "Upgrade Proposal".to_string(),
                action: Some(action),
                ..Default::default()
            }),
            latest_tally: Some(Tally {
                timestamp_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS - 60,
                yes: 100000000,
                no: 0,
                total: 100000000
            }),
            ..Default::default()
        };

        GovernanceProto {
            root_canister_id: Some(PrincipalId::from(*TEST_ROOT_CANISTER_ID)),
            deployed_version: Some(SNS_VERSION_1.clone()),
            pending_version: Some(PendingVersion {
                target_version: Some(SNS_VERSION_2.clone()),
                mark_failed_at_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS,
                checking_upgrade_lock: 10,
                proposal_id: Some(UPGRADE_PROPOSAL_ID),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
            proposals: btreemap! { UPGRADE_PROPOSAL_ID => proposal_data },
            ..basic_governance_proto()
        }
    };
}

#[test]
fn test_does_nothing_if_there_is_no_upgrade_in_progress() {
    // Step 1: Prepare the world

    let env = {
        let mut env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));

        // Note that NativeEnvironment only advances time when you tell it
        // to. Therefore, this is the time that Governance will see
        // throughout this test.
        env.now = UPGRADE_DEADLINE_TIMESTAMP_SECONDS;

        env
    };

    let governance_proto = GovernanceProto {
        deployed_version: Some(SNS_VERSION_1.clone()),
        ..basic_governance_proto()
    };
    let mut governance = Governance::new(
        ValidGovernanceProto::try_from(governance_proto).unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // The code being tested is supposed to affect these fields. We
    // inspect them here to make sure that any expected changes are
    // real, not just because the world was (accidentally) already the
    // way we expected them afterwards.
    assert_eq!(governance.proto.pending_version.clone(), None);
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone(),
    );

    // Step 2: Run the code being tested.
    assert_eq!(
        governance.fail_stuck_upgrade_in_progress(FailStuckUpgradeInProgressRequest {}),
        FailStuckUpgradeInProgressResponse {},
    );

    // Step 3: Inspect results.

    // Assert pending_version and deployed_version remain unchanged.
    assert_eq!(governance.proto.pending_version.clone(), None);
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );
}

#[test]
fn test_does_nothing_if_upgrade_attempt_not_expired() {
    // Step 1: Prepare the world

    let env = {
        let mut env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));

        // Note that NativeEnvironment only advances time when you tell it
        // to. Therefore, this is the time that Governance will see
        // throughout this test.
        env.now = UPGRADE_DEADLINE_TIMESTAMP_SECONDS - 1;

        env
    };

    let mut governance = Governance::new(
        ValidGovernanceProto::try_from(GOVERNANCE_PROTO.clone()).unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // The code being tested is supposed to affect these fields. We
    // inspect them here to make sure that any expected changes are
    // real, not just because the world was (accidentally) already the
    // way we expected them afterwards.
    let expected_upgrade_in_progress = PendingVersion {
        target_version: Some(SNS_VERSION_2.clone()),
        mark_failed_at_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS,
        checking_upgrade_lock: 10,
        proposal_id: Some(UPGRADE_PROPOSAL_ID),
    };
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        expected_upgrade_in_progress,
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone(),
    );

    // Step 2: Run the code being tested.
    assert_eq!(
        governance.fail_stuck_upgrade_in_progress(FailStuckUpgradeInProgressRequest {}),
        FailStuckUpgradeInProgressResponse {},
    );

    // Step 3: Inspect results.

    // Assert pending_version and deployed_version remain unchanged.
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        expected_upgrade_in_progress,
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );

    // Assert proposal execution continues.
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId {
            id: UPGRADE_PROPOSAL_ID,
        }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);
    assert_eq!(proposal_data.failure_reason, None);
}

#[test]
fn test_fails_proposal_and_removes_upgrade_if_upgrade_attempt_is_expired() {
    // Step 1: Prepare the world

    let env = {
        let mut env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));

        // Note that NativeEnvironment only advances time when you tell it
        // to. Therefore, this is the time that Governance will see
        // throughout this test.
        env.now = UPGRADE_DEADLINE_TIMESTAMP_SECONDS + 1;

        env
    };

    let mut governance = Governance::new(
        ValidGovernanceProto::try_from(GOVERNANCE_PROTO.clone()).unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // The code being tested is supposed to affect these fields. We
    // inspect them here to make sure that any expected changes are
    // real, not just because the world was (accidentally) already the
    // way we expected them afterwards.
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(SNS_VERSION_2.clone()),
            mark_failed_at_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS,
            checking_upgrade_lock: 10,
            proposal_id: Some(UPGRADE_PROPOSAL_ID),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );

    // Step 2: Run the code being tested.
    assert_eq!(
        governance.fail_stuck_upgrade_in_progress(FailStuckUpgradeInProgressRequest {}),
        FailStuckUpgradeInProgressResponse {},
    );

    // Step 3: Inspect results.

    // Assert pending version has been cleared.
    let pending_version = &governance.proto.pending_version;
    assert!(pending_version.is_none(), "{pending_version:#?}");
    // Assert deployed_version unchanged from before.
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );

    // Assert proposal failed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId {
            id: UPGRADE_PROPOSAL_ID,
        }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_ne!(proposal_data.failed_timestamp_seconds, 0);

    // Inspect the proposal's failure_reason.
    let governance_error = proposal_data.failure_reason.unwrap();
    assert_eq!(
        ErrorType::try_from(governance_error.error_type),
        Ok(ErrorType::External),
        "{governance_error:#?}",
    );
    assert!(
        governance_error.error_message.contains("manually aborted"),
        "{governance_error:#?}",
    );
}
