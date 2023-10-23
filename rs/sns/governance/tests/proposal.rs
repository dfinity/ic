use ic_nervous_system_proto::pb::v1::Percentage;
use ic_sns_governance::pb::v1::{ProposalData, Tally};

mod can_make_decision {
    use super::*;

    #[test]
    fn doesnt_overflow() {
        let now_seconds = 2;
        let p1 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX,
                no: 0,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: u64::MAX,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p3 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX / 2,
                no: u64::MAX / 2,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(3.0)),
            ..Default::default()
        };

        assert!(p1.can_make_decision(now_seconds));
        assert!(p2.can_make_decision(now_seconds));
        assert!(!p3.can_make_decision(now_seconds));
    }
}

mod is_accepted {

    use super::*;

    #[test]
    fn doesnt_overflow() {
        let p1 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX,
                no: 0,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: u64::MAX,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p3 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX / 2,
                no: u64::MAX / 2,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(3.0)),
            ..Default::default()
        };

        assert!(p1.is_accepted());
        assert!(!p2.is_accepted());
        assert!(!p3.is_accepted());
    }

    #[test]
    fn quorum_size_variation() {
        let p0 = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p1 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(10.0)),
            ..Default::default()
        };

        let p3 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(20.0)),
            ..Default::default()
        };

        let p4 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(30.0)),
            ..Default::default()
        };

        assert!(!p0.is_accepted());
        assert!(p1.is_accepted());
        assert!(p2.is_accepted());
        assert!(p3.is_accepted());
        assert!(!p4.is_accepted());
    }
}
