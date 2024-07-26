use crate::pb::v1::{
    governance_error::ErrorType, manage_neuron_response, GovernanceError, ManageNeuronResponse,
    NetworkEconomics, NeuronsFundEconomics, NeuronsFundMatchedFundingCurveCoefficients,
    XdrConversionRate,
};
use ic_nervous_system_proto::pb::v1::{Decimal, Percentage};
use icp_ledger::{DEFAULT_TRANSFER_FEE, TOKEN_SUBDIVIDABLE_BY};

#[allow(clippy::all)]
#[path = "./ic_nns_governance.pb.v1.rs"]
pub mod v1;

/// The number of e8s per ICP;
const E8S_PER_ICP: u64 = TOKEN_SUBDIVIDABLE_BY;
// TODO get this from nervous_system/common/consts after we migrate consts out of nervous_system/common
pub const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;

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
