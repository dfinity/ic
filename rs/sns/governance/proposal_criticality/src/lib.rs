use ic_nervous_system_proto::pb::v1::{Duration, Percentage};

/// It is more difficult to pass critical proposals. This controls voting power thresholds and
/// voting duration parameters on proposals.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ProposalCriticality {
    Normal,
    Critical,
}

impl ProposalCriticality {
    pub fn voting_power_thresholds(self) -> VotingPowerThresholds {
        match self {
            Self::Normal => VotingPowerThresholds {
                minimum_yes_proportion_of_total: Percentage {
                    basis_points: Some(300), // 3%
                },
                minimum_yes_proportion_of_exercised: Percentage {
                    basis_points: Some(5000), // 50%
                },
            },

            Self::Critical => VotingPowerThresholds {
                minimum_yes_proportion_of_total: Percentage {
                    basis_points: Some(2000), // 20%
                },
                minimum_yes_proportion_of_exercised: Percentage {
                    basis_points: Some(6700), // 67%
                },
            },
        }
    }
}

/// Both fields must be < 100%. Of course, that is the only "hard" limit. But a "limit of sanity"
/// would be even lower. The problem is, there is no hard transition from sane to insane; it's a
/// gradient. Nevertheless, we can probably safely say that values > 85% are "insane".
///
/// It also does not make much sense for *_of_total to be greater than *_of_exercised, since the
/// denominator of the former is not less than that of the latter (and the numerator for both is the
/// same). However, if such a thing were to occur, it would still be possible for a proposal to
/// pass. It's just that that *_of_exercised requirement would be superfluous.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VotingPowerThresholds {
    /// Out of the total available voting power, this much must vote to adopt.
    pub minimum_yes_proportion_of_total: Percentage,

    /// Out of the exercised voting power, the amount that votes to adopt must exceed this.
    pub minimum_yes_proportion_of_exercised: Percentage,
}

/// If an SNS wants to be like NNS, the values here would be 4 days and 2 days respectively.
///
/// Wait for quiet is a deadline extension mechanism that gets triggered when the yes vs. exercised
/// voting power ratio crosses the minimum_yes_proportion_of_exercised threshold in either direction
/// (i.e. becomes greater or becomes less than or equal). The amount that gets added to the deadline
/// is complicated and described elsewhere. However, one notable property of wait for quiet is that
/// the total amount of increase is at most 2 * wait_for_quiet_deadline_increase.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VotingDurationParameters {
    pub initial_voting_period: Duration,
    pub wait_for_quiet_deadline_increase: Duration,
}
