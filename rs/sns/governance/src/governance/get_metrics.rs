use crate::governance::test_helpers::basic_governance_proto;
use crate::governance::ValidGovernanceProto;
use crate::governance::{test_helpers::DoNothingLedger, Governance};
use crate::pb::v1::{self as pb, ProposalData};
use crate::types::test_helpers::NativeEnvironment;
use ic_nervous_system_canisters::cmc::FakeCmc;
use maplit::btreemap;

#[test]
fn test_recent_proposals() {
    use maplit::btreemap;
    pub const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

    const ONE_MONTH: u64 = 30 * 24 * 3600;

    #[allow(clippy::identity_op)]
    let proposal1 = ProposalData {
        proposal_creation_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS - 1 * ONE_MONTH,
        ..Default::default()
    };
    let proposal2 = ProposalData {
        proposal_creation_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS - 2 * ONE_MONTH,
        ..Default::default()
    };
    let proposal3 = ProposalData {
        proposal_creation_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS - 3 * ONE_MONTH,
        ..Default::default()
    };

    let governance_proto = pb::Governance {
        proposals: btreemap! {
            1_u64 => proposal3,
            2_u64 => proposal2,
            3_u64 => proposal1
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

    #[allow(clippy::identity_op)]
    let test_cases = [
        ("zero-size window", 0_u64, 0),
        ("one-month window", 1 * ONE_MONTH, 1),
        ("two-months window", 2 * ONE_MONTH, 2),
        ("three-months window", 3 * ONE_MONTH, 3),
        ("primeval", u64::MAX, 3),
    ];

    for (lable, time_window, proposals) in test_cases {
        assert_eq!(
            governance.recent_proposals(time_window),
            proposals,
            "Expected {} proposals for {}",
            proposals,
            lable
        );
    }
}
