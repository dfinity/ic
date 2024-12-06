use super::*;
use crate::pb::v1::{Governance as GovernanceProto, NetworkEconomics, VotingPowerEconomics};
use lazy_static::lazy_static;

mod set_initial_voting_power_economics {
    use super::*;

    lazy_static! {
        static ref GOVERNANCE_PROTO: GovernanceProto = GovernanceProto {
            economics: Some(NetworkEconomics::with_default_values()),
            ..Default::default()
        };
    }

    #[test]
    fn test_typical() {
        let mut governance_proto = GOVERNANCE_PROTO.clone();
        governance_proto
            .economics
            .as_mut()
            .unwrap()
            .voting_power_economics = None;

        set_initial_voting_power_economics(&mut governance_proto);

        assert_eq!(
            governance_proto.economics.unwrap().voting_power_economics,
            Some(VotingPowerEconomics {
                start_reducing_voting_power_after_seconds: Some(15_778_800), // 0.5 * 365.25 days.
                clear_following_after_seconds: Some(2_629_800),              // 1/12 * 365.25 days
            }),
        );
    }

    #[test]
    fn test_weird() {
        let mut governance_proto = GOVERNANCE_PROTO.clone();
        {
            let voting_power_economics = governance_proto
                .economics
                .as_mut()
                .unwrap()
                .voting_power_economics
                .as_mut()
                .unwrap();

            voting_power_economics.start_reducing_voting_power_after_seconds = Some(42);
            voting_power_economics.clear_following_after_seconds = None;
        }

        set_initial_voting_power_economics(&mut governance_proto);

        assert_eq!(
            governance_proto.economics.unwrap().voting_power_economics,
            Some(VotingPowerEconomics {
                start_reducing_voting_power_after_seconds: Some(42), // Do not touch.
                clear_following_after_seconds: Some(2_629_800),      // 1/12 * 365.25 days
            }),
        );
    }
} // mod set_initial_voting_power_economics
