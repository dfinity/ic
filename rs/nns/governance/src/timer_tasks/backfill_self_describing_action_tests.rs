use super::*;

use crate::{
    pb::v1::{
        Motion, Proposal, ProposalData, SelfDescribingProposalAction, SelfDescribingValue,
        proposal::Action,
    },
    test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger},
};

use ic_nns_governance_api::Governance as ApiGovernance;
use std::sync::Arc;

thread_local! {
    static MOCK_ENVIRONMENT: Arc<MockEnvironment> = Arc::new(
        MockEnvironment::new(vec![], 0));
    static TEST_GOVERNANCE: RefCell<Governance> = RefCell::new(new_governance_for_test());
}

fn new_governance_for_test() -> Governance {
    Governance::new(
        ApiGovernance::default(),
        MOCK_ENVIRONMENT.with(|env| env.clone()),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}

fn motion_to_self_describing_action(motion: &Motion) -> SelfDescribingProposalAction {
    SelfDescribingProposalAction {
        type_name: "Motion".to_string(),
        type_description: "Propose a text that can be adopted or rejected. \
            No code is executed when a motion is adopted. An adopted motion should guide the future \
            strategy of the Internet Computer ecosystem."
            .to_string(),
        value: Some(SelfDescribingValue::from(motion.clone())),
    }
}

fn add_proposal_without_self_describing(proposal_id: u64, action: Action) {
    TEST_GOVERNANCE.with_borrow_mut(|governance| {
        governance.heap_data.proposals.insert(
            proposal_id,
            ProposalData {
                id: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id }),
                proposal: Some(Proposal {
                    title: Some(format!("Proposal {}", proposal_id)),
                    summary: format!("Summary for proposal {}", proposal_id),
                    url: String::new(),
                    action: Some(action),
                    self_describing_action: None,
                }),
                ..Default::default()
            },
        );
    });
}

fn add_proposal_with_self_describing(proposal_id: u64) {
    let motion = Motion {
        motion_text: "Already backfilled".to_string(),
    };
    let self_describing_action = motion_to_self_describing_action(&motion);
    TEST_GOVERNANCE.with_borrow_mut(|governance| {
        governance.heap_data.proposals.insert(
            proposal_id,
            ProposalData {
                id: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id }),
                proposal: Some(Proposal {
                    title: Some(format!("Proposal {}", proposal_id)),
                    summary: format!("Summary for proposal {}", proposal_id),
                    url: String::new(),
                    action: Some(Action::Motion(motion)),
                    self_describing_action: Some(self_describing_action),
                }),
                ..Default::default()
            },
        );
    });
}

fn get_proposal_self_describing_action(
    proposal_id: u64,
) -> Option<crate::pb::v1::SelfDescribingProposalAction> {
    TEST_GOVERNANCE.with_borrow(|governance| {
        governance
            .heap_data
            .proposals
            .get(&proposal_id)?
            .proposal
            .as_ref()?
            .self_describing_action
            .clone()
    })
}

#[tokio::test]
async fn test_all_proposals_already_backfilled_returns_24_hour_delay() {
    // Add proposals that already have self_describing_action
    add_proposal_with_self_describing(1);
    add_proposal_with_self_describing(2);
    add_proposal_with_self_describing(3);

    let task = BackfillSelfDescribingActionTask::new(&TEST_GOVERNANCE);
    let (delay, new_task) = task.execute().await;

    assert_eq!(delay, NO_PROPOSALS_TO_BACKFILL_INTERVAL);
    assert_eq!(new_task.start_bound, Bound::Unbounded);
}

#[tokio::test]
async fn test_finds_first_proposal_needing_backfill_from_beginning() {
    // Add proposals: 1 and 3 already backfilled, 2 needs backfilling
    let motion = Motion {
        motion_text: "Test motion".to_string(),
    };
    let self_describing_action = motion_to_self_describing_action(&motion);
    add_proposal_with_self_describing(1);
    add_proposal_without_self_describing(2, Action::Motion(motion));
    add_proposal_with_self_describing(3);

    let task = BackfillSelfDescribingActionTask::new(&TEST_GOVERNANCE);
    let (delay, new_task) = task.execute().await;

    // Motion is a locally describable action, so it should succeed
    assert_eq!(delay, BACKFILL_INTERVAL);
    assert_eq!(new_task.start_bound, Bound::Excluded(2));

    // Verify proposal 2 was backfilled
    assert_eq!(
        get_proposal_self_describing_action(2).unwrap(),
        self_describing_action
    );
}

#[tokio::test]
async fn test_finds_proposal_after_specified_id() {
    // Setup 3 proposals all needing backfilling
    add_proposal_without_self_describing(
        1,
        Action::Motion(Motion {
            motion_text: "Motion 1".to_string(),
        }),
    );
    let motion2 = Motion {
        motion_text: "Motion 2".to_string(),
    };
    add_proposal_without_self_describing(2, Action::Motion(motion2.clone()));
    let motion2_self_describing_action = motion_to_self_describing_action(&motion2);
    add_proposal_without_self_describing(
        3,
        Action::Motion(Motion {
            motion_text: "Motion 3".to_string(),
        }),
    );

    // Start after proposal 1
    let task = BackfillSelfDescribingActionTask::new(&TEST_GOVERNANCE)
        .with_start_bound(Bound::Excluded(1));

    let (delay, new_task) = task.execute().await;

    // Should find and backfill proposal 2 (skipping 1)
    assert_eq!(delay, BACKFILL_INTERVAL);
    assert_eq!(new_task.start_bound, Bound::Excluded(2));

    // Verify proposal 2 was backfilled but proposal 1 and 3 were not
    assert_eq!(
        get_proposal_self_describing_action(2).unwrap(),
        motion2_self_describing_action
    );
    assert_eq!(get_proposal_self_describing_action(1), None);
    assert_eq!(get_proposal_self_describing_action(3), None);
}
