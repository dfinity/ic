use crate::pb::v1::{
    governance::migration::MigrationStatus, governance_error::ErrorType, manage_neuron_response,
    neuron::DissolveState, CreateServiceNervousSystem, GovernanceError, ManageNeuronResponse,
    NetworkEconomics, Neuron, NeuronState, NeuronsFundEconomics,
    NeuronsFundMatchedFundingCurveCoefficients, VotingPowerEconomics, XdrConversionRate,
};
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
use ic_nervous_system_proto::pb::v1::{Decimal, Duration, GlobalTimeOfDay, Percentage};
use icp_ledger::{DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY};
use std::fmt;

#[allow(clippy::all)]
#[path = "./ic_nns_governance.pb.v1.rs"]
pub mod v1;

/// The number of e8s per ICP;
const E8S_PER_ICP: u64 = TOKEN_SUBDIVIDABLE_BY;

impl ManageNeuronResponse {
    pub fn panic_if_error(self, msg: &str) -> Self {
        if let Some(manage_neuron_response::Command::Error(err)) = &self.command {
            panic!("{}: {:?}", msg, err);
        }
        self
    }
}

impl GovernanceError {
    pub fn new(error_type: ErrorType) -> Self {
        Self {
            error_type: error_type as i32,
            ..Default::default()
        }
    }

    pub fn new_with_message(error_type: ErrorType, message: impl ToString) -> Self {
        Self {
            error_type: error_type as i32,
            error_message: message.to_string(),
        }
    }
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_type(), self.error_message)
    }
}

impl std::error::Error for GovernanceError {}

impl NeuronsFundEconomics {
    /// The default values for network economics (until we initialize it).
    /// Can't implement Default since it conflicts with Prost's.
    /// The values here are computed under the assumption that 1 XDR = 0.75 USD. See also:
    /// https://dashboard.internetcomputer.org/proposal/124822
    pub fn with_default_values() -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: Some(Decimal {
                human_readable: Some("750_000.0".to_string()),
            }),
            neurons_fund_matched_funding_curve_coefficients: Some(
                NeuronsFundMatchedFundingCurveCoefficients {
                    contribution_threshold_xdr: Some(Decimal {
                        human_readable: Some("75_000.0".to_string()),
                    }),
                    one_third_participation_milestone_xdr: Some(Decimal {
                        human_readable: Some("225_000.0".to_string()),
                    }),
                    full_participation_milestone_xdr: Some(Decimal {
                        human_readable: Some("375_000.0".to_string()),
                    }),
                },
            ),
            minimum_icp_xdr_rate: Some(Percentage {
                basis_points: Some(10_000), // 1:1
            }),
            maximum_icp_xdr_rate: Some(Percentage {
                basis_points: Some(1_000_000), // 1:100
            }),
        }
    }
}

impl NetworkEconomics {
    /// The multiplier applied to minimum_icp_xdr_rate to convert the XDR unit to basis_points
    pub const ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER: u64 = 100;

    // The default values for network economics (until we initialize it).
    // Can't implement Default since it conflicts with Prost's.
    pub fn with_default_values() -> Self {
        Self {
            reject_cost_e8s: E8S_PER_ICP,                               // 1 ICP
            neuron_management_fee_per_proposal_e8s: 1_000_000,          // 0.01 ICP
            neuron_minimum_stake_e8s: E8S_PER_ICP,                      // 1 ICP
            neuron_spawn_dissolve_delay_seconds: ONE_DAY_SECONDS * 7,   // 7 days
            maximum_node_provider_rewards_e8s: 1_000_000 * 100_000_000, // 1M ICP
            minimum_icp_xdr_rate: 100,                                  // 1 XDR
            transaction_fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
            max_proposals_to_keep_per_topic: 100,
            neurons_fund_economics: Some(NeuronsFundEconomics::with_default_values()),
            voting_power_economics: Some(VotingPowerEconomics::with_default_values()),
        }
    }
}

impl VotingPowerEconomics {
    pub fn with_default_values() -> Self {
        Self {
            start_reducing_voting_power_after_seconds: Some(6 * ONE_MONTH_SECONDS),
            clear_following_after_seconds: Some(ONE_MONTH_SECONDS),
        }
    }
}

impl XdrConversionRate {
    /// This constructor should be used only at canister creation, and not, e.g., after upgrades.
    /// The reason this function exists is because `Default::default` is already defined by prost.
    /// However, the Governance canister relies on the fields of this structure being `Some`.
    pub fn with_default_values() -> Self {
        Self {
            timestamp_seconds: Some(0),
            xdr_permyriad_per_icp: Some(10_000),
        }
    }
}

// The following methods are conceptually methods for the API type of the neuron.
impl Neuron {
    pub fn state(&self, now_seconds: u64) -> NeuronState {
        if self.spawn_at_timestamp_seconds.is_some() {
            return NeuronState::Spawning;
        }
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)) => {
                if dissolve_delay_seconds > 0 {
                    NeuronState::NotDissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(
                when_dissolved_timestamp_seconds,
            )) => {
                if when_dissolved_timestamp_seconds > now_seconds {
                    NeuronState::Dissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            None => NeuronState::Dissolved,
        }
    }

    pub fn dissolve_delay_seconds(&self, now_seconds: u64) -> u64 {
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)) => {
                dissolve_delay_seconds
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(
                when_dissolved_timestamp_seconds,
            )) => when_dissolved_timestamp_seconds.saturating_sub(now_seconds),
            None => 0,
        }
    }

    pub fn stake_e8s(&self) -> u64 {
        let cached_neuron_stake_e8s = self.cached_neuron_stake_e8s;
        let neuron_fees_e8s = self.neuron_fees_e8s;
        let staked_maturity_e8s_equivalent = self.staked_maturity_e8s_equivalent;
        cached_neuron_stake_e8s
            .saturating_sub(neuron_fees_e8s)
            .saturating_add(staked_maturity_e8s_equivalent.unwrap_or(0))
    }
}

impl MigrationStatus {
    pub fn is_terminal(self) -> bool {
        match self {
            Self::Unspecified | Self::InProgress => false,
            Self::Succeeded | Self::Failed => true,
        }
    }
}

impl CreateServiceNervousSystem {
    pub fn sns_token_e8s(&self) -> Option<u64> {
        self.initial_token_distribution
            .as_ref()?
            .swap_distribution
            .as_ref()?
            .total
            .as_ref()?
            .e8s
    }

    pub fn transaction_fee_e8s(&self) -> Option<u64> {
        self.ledger_parameters
            .as_ref()?
            .transaction_fee
            .as_ref()?
            .e8s
    }

    pub fn neuron_minimum_stake_e8s(&self) -> Option<u64> {
        self.governance_parameters
            .as_ref()?
            .neuron_minimum_stake
            .as_ref()?
            .e8s
    }

    /// Computes timestamps for when the SNS token swap will start, and will be
    /// due, based on the start and end times.
    ///
    /// The swap will start on the first `start_time_of_day` that is more than
    /// 24h after the swap was approved.
    ///
    /// The end time is calculated by adding `duration` to the computed start time.
    ///
    /// if start_time_of_day is None, then randomly_pick_swap_start is used to
    /// pick a start time.
    pub fn swap_start_and_due_timestamps(
        start_time_of_day: GlobalTimeOfDay,
        duration: Duration,
        swap_approved_timestamp_seconds: u64,
    ) -> Result<(u64, u64), String> {
        let start_time_of_day = start_time_of_day
            .seconds_after_utc_midnight
            .ok_or("`seconds_after_utc_midnight` should not be None")?;
        let duration = duration.seconds.ok_or("`seconds` should not be None")?;

        // TODO(NNS1-2298): we should also add 27 leap seconds to this, to avoid
        // having the swap start half a minute earlier than expected.
        let midnight_after_swap_approved_timestamp_seconds = swap_approved_timestamp_seconds
            .saturating_sub(swap_approved_timestamp_seconds % ONE_DAY_SECONDS) // floor to midnight
            .saturating_add(ONE_DAY_SECONDS); // add one day

        let swap_start_timestamp_seconds = {
            let mut possible_swap_starts = (0..2).map(|i| {
                midnight_after_swap_approved_timestamp_seconds
                    .saturating_add(ONE_DAY_SECONDS * i)
                    .saturating_add(start_time_of_day)
            });
            // Find the earliest time that's at least 24h after the swap was approved.
            possible_swap_starts
                .find(|&timestamp| timestamp > swap_approved_timestamp_seconds + ONE_DAY_SECONDS)
                .ok_or(format!(
                    "Unable to find a swap start time after the swap was approved. \
                     swap_approved_timestamp_seconds = {}, \
                     midnight_after_swap_approved_timestamp_seconds = {}, \
                     start_time_of_day = {}, \
                     duration = {} \
                     This is probably a bug.",
                    swap_approved_timestamp_seconds,
                    midnight_after_swap_approved_timestamp_seconds,
                    start_time_of_day,
                    duration,
                ))?
        };

        let swap_due_timestamp_seconds = duration
            .checked_add(swap_start_timestamp_seconds)
            .ok_or("`duration` should not be None")?;

        Ok((swap_start_timestamp_seconds, swap_due_timestamp_seconds))
    }
}
