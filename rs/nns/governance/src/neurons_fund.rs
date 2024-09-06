//! Implementation of NNS Governance-specific functions for Matched Funding.

use ic_base_types::PrincipalId;
use ic_nervous_system_governance::maturity_modulation::BASIS_POINTS_PER_UNITY;
use ic_nervous_system_proto::pb::v1::{Decimal as DecimalPb, Percentage as PercentagePb};
use ic_neurons_fund::{
    dec_to_u64, rescale_to_icp, u64_to_dec, DeserializableFunction, HalfOpenInterval,
    IdealMatchingFunction, NeuronsFundParticipationLimits, PolynomialMatchingFunction,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_sns_swap::pb::v1::{
    IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionSwapPb,
    LinearScalingCoefficient, NeuronsFundParticipationConstraints,
};
use num_traits::ops::inv::Inv;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

use crate::{
    governance,
    neuron_store::{NeuronStore, NeuronsFundNeuron},
    pb::v1::{
        create_service_nervous_system::SwapParameters, governance_error,
        neurons_fund_snapshot::NeuronsFundNeuronPortion as NeuronsFundNeuronPortionPb,
        GovernanceError, IdealMatchedParticipationFunction,
        NeuronsFundEconomics as NeuronsFundEconomicsPb,
        NeuronsFundMatchedFundingCurveCoefficients as NeuronsFundMatchedFundingCurveCoefficientsPb,
        NeuronsFundParticipation as NeuronsFundParticipationPb,
        NeuronsFundSnapshot as NeuronsFundSnapshotPb,
        SwapParticipationLimits as SwapParticipationLimitsPb,
    },
    Governance,
};

/// The Neurons' Fund should not participate in any SNS swap with more than this portion of its
/// overall maturity.
pub const MAX_NEURONS_FUND_PARTICIPATION_BASIS_POINTS: u16 = 1_000; // 10%

pub fn take_percentile_of(x: u64, percentile: u16) -> u64 {
    ((x as u128)
        .saturating_mul(percentile as u128)
        .saturating_div(BASIS_POINTS_PER_UNITY)
        .min(u64::MAX as u128)) as u64
}

pub fn take_max_initial_neurons_fund_participation_percentage(x: u64) -> u64 {
    take_percentile_of(x, MAX_NEURONS_FUND_PARTICIPATION_BASIS_POINTS)
}

// -------------------------------------------------------------------------------------------------
// ------------------- NeuronsFundEconomics --------------------------------------------------------
// -------------------------------------------------------------------------------------------------

impl NeuronsFundEconomicsPb {
    /// The default values for network economics (until we initialize it).
    /// Can't implement Default since it conflicts with Prost's.
    /// The values here are computed under the assumption that 1 XDR = 0.75 USD. See also:
    /// https://dashboard.internetcomputer.org/proposal/124822
    pub fn with_default_values() -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: Some(DecimalPb {
                human_readable: Some("750_000.0".to_string()),
            }),
            neurons_fund_matched_funding_curve_coefficients: Some(
                NeuronsFundMatchedFundingCurveCoefficientsPb {
                    contribution_threshold_xdr: Some(DecimalPb {
                        human_readable: Some("75_000.0".to_string()),
                    }),
                    one_third_participation_milestone_xdr: Some(DecimalPb {
                        human_readable: Some("225_000.0".to_string()),
                    }),
                    full_participation_milestone_xdr: Some(DecimalPb {
                        human_readable: Some("375_000.0".to_string()),
                    }),
                },
            ),
            minimum_icp_xdr_rate: Some(PercentagePb {
                basis_points: Some(10_000), // 1:1
            }),
            maximum_icp_xdr_rate: Some(PercentagePb {
                basis_points: Some(1_000_000), // 1:100
            }),
        }
    }
}

pub struct NeuronsFundEconomics {
    pub max_theoretical_neurons_fund_participation_amount_xdr: Decimal,
    pub contribution_threshold_xdr: Decimal,
    pub one_third_participation_milestone_xdr: Decimal,
    pub full_participation_milestone_xdr: Decimal,
    pub minimum_icp_xdr_rate: Decimal,
    pub maximum_icp_xdr_rate: Decimal,
}

impl NeuronsFundEconomics {
    fn missing_field(field_name: &str) -> String {
        format!("NeuronsFundEconomics.{} must be specified.", field_name)
    }

    fn convert_to_rust_decimal_or_err(
        field_name: &str,
        field_value_pb: DecimalPb,
    ) -> Result<Decimal, String> {
        Decimal::try_from(field_value_pb).map_err(|err| {
            format!(
                "NeuronsFundEconomics.{} must be parsed as Decimal: {}",
                field_name, err,
            )
        })
    }
}

impl TryFrom<&NeuronsFundEconomicsPb> for NeuronsFundEconomics {
    type Error = String;

    fn try_from(src: &NeuronsFundEconomicsPb) -> Result<Self, Self::Error> {
        // First, deconstruct the protobuf.

        let NeuronsFundEconomicsPb {
            minimum_icp_xdr_rate,
            maximum_icp_xdr_rate,
            max_theoretical_neurons_fund_participation_amount_xdr,
            neurons_fund_matched_funding_curve_coefficients,
        } = src;

        let minimum_icp_xdr_rate = Decimal::from(
            minimum_icp_xdr_rate
                .ok_or_else(|| Self::missing_field("minimum_icp_xdr_rate"))?
                .basis_points
                .ok_or_else(|| Self::missing_field("minimum_icp_xdr_rate.basis_points"))?,
        ) / dec!(10_000);

        let maximum_icp_xdr_rate = Decimal::from(
            maximum_icp_xdr_rate
                .ok_or_else(|| Self::missing_field("maximum_icp_xdr_rate"))?
                .basis_points
                .ok_or_else(|| Self::missing_field("maximum_icp_xdr_rate.basis_points"))?,
        ) / dec!(10_000);

        let max_theoretical_neurons_fund_participation_amount_xdr =
            max_theoretical_neurons_fund_participation_amount_xdr
                .clone()
                .ok_or_else(|| {
                    Self::missing_field("max_theoretical_neurons_fund_participation_amount_xdr")
                })?;

        let neurons_fund_matched_funding_curve_coefficients =
            neurons_fund_matched_funding_curve_coefficients
                .clone()
                .ok_or_else(|| {
                    Self::missing_field("neurons_fund_matched_funding_curve_coefficients")
                })?;

        let NeuronsFundMatchedFundingCurveCoefficientsPb {
            contribution_threshold_xdr,
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
        } = neurons_fund_matched_funding_curve_coefficients;

        let contribution_threshold_xdr = contribution_threshold_xdr
            .clone()
            .ok_or_else(|| Self::missing_field("contribution_threshold_xdr"))?;

        let one_third_participation_milestone_xdr =
            one_third_participation_milestone_xdr
                .clone()
                .ok_or_else(|| Self::missing_field("one_third_participation_milestone_xdr"))?;

        let full_participation_milestone_xdr = full_participation_milestone_xdr
            .clone()
            .ok_or_else(|| Self::missing_field("full_participation_milestone_xdr"))?;

        // Second, convert all serialized Decimals into internal Rust types.

        let max_theoretical_neurons_fund_participation_amount_xdr =
            Self::convert_to_rust_decimal_or_err(
                "max_theoretical_neurons_fund_participation_amount_xdr",
                max_theoretical_neurons_fund_participation_amount_xdr,
            )?;

        let contribution_threshold_xdr = Self::convert_to_rust_decimal_or_err(
            "contribution_threshold_xdr",
            contribution_threshold_xdr,
        )?;

        let one_third_participation_milestone_xdr = Self::convert_to_rust_decimal_or_err(
            "one_third_participation_milestone_xdr",
            one_third_participation_milestone_xdr,
        )?;

        let full_participation_milestone_xdr = Self::convert_to_rust_decimal_or_err(
            "full_participation_milestone_xdr",
            full_participation_milestone_xdr,
        )?;

        Ok(Self {
            max_theoretical_neurons_fund_participation_amount_xdr,
            contribution_threshold_xdr,
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
            minimum_icp_xdr_rate,
            maximum_icp_xdr_rate,
        })
    }
}

#[cfg(test)]
mod test_neurons_fund_economics_pb {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn threasholds_can_be_parsed() {
        let default_neurons_fund_network_economics = NeuronsFundEconomicsPb::with_default_values();

        let NeuronsFundEconomics {
            max_theoretical_neurons_fund_participation_amount_xdr,
            contribution_threshold_xdr,
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
            minimum_icp_xdr_rate,
            maximum_icp_xdr_rate,
        } = NeuronsFundEconomics::try_from(&default_neurons_fund_network_economics).unwrap();

        assert_eq!(
            max_theoretical_neurons_fund_participation_amount_xdr,
            dec!(750_000)
        );
        assert_eq!(contribution_threshold_xdr, dec!(75_000));
        assert_eq!(one_third_participation_milestone_xdr, dec!(225_000));
        assert_eq!(full_participation_milestone_xdr, dec!(375_000));

        assert_eq!(minimum_icp_xdr_rate, dec!(1.0));
        assert_eq!(maximum_icp_xdr_rate, dec!(100.0));
    }
}

impl Governance {
    fn try_derive_neurons_fund_participation_limits_impl(
        neurons_fund_economics: &NeuronsFundEconomicsPb,
        icp_xdr_rate: Decimal,
    ) -> Result<NeuronsFundParticipationLimits, String> {
        let NeuronsFundEconomics {
            max_theoretical_neurons_fund_participation_amount_xdr,
            contribution_threshold_xdr,
            one_third_participation_milestone_xdr,
            full_participation_milestone_xdr,
            minimum_icp_xdr_rate,
            maximum_icp_xdr_rate,
        } = NeuronsFundEconomics::try_from(neurons_fund_economics)?;

        if icp_xdr_rate <= minimum_icp_xdr_rate {
            println!(
                "{}WARNING: icp_xdr_rate ({}) is being clamped at the lower bound ({}).",
                governance::LOG_PREFIX,
                icp_xdr_rate,
                minimum_icp_xdr_rate,
            );
        }
        if icp_xdr_rate >= maximum_icp_xdr_rate {
            println!(
                "{}WARNING: icp_xdr_rate ({}) is being clamped at the upper bound ({}).",
                governance::LOG_PREFIX,
                icp_xdr_rate,
                maximum_icp_xdr_rate,
            );
        }
        let icp_xdr_rate = icp_xdr_rate.clamp(minimum_icp_xdr_rate, maximum_icp_xdr_rate);

        if icp_xdr_rate.is_zero() {
            // We don't expect this to ever happen in practice.
            return Err("icp_xdr_rate must be greater than zero.".to_string());
        }
        let xdr_icp_rate = icp_xdr_rate.inv();

        let convert_xdr_to_icp = |amount_xdr: Decimal| -> Result<Decimal, String> {
            amount_xdr.checked_mul(xdr_icp_rate).ok_or_else(|| {
                format!(
                    "Cannot convert {} XDR to ICP due to a Decimal overflow. xdr_icp_rate = {}.",
                    amount_xdr, xdr_icp_rate,
                )
            })
        };

        let max_theoretical_neurons_fund_participation_amount_icp =
            convert_xdr_to_icp(max_theoretical_neurons_fund_participation_amount_xdr)?;

        let contribution_threshold_icp = convert_xdr_to_icp(contribution_threshold_xdr)?;

        let one_third_participation_milestone_icp =
            convert_xdr_to_icp(one_third_participation_milestone_xdr)?;

        let full_participation_milestone_icp =
            convert_xdr_to_icp(full_participation_milestone_xdr)?;

        Ok(NeuronsFundParticipationLimits {
            max_theoretical_neurons_fund_participation_amount_icp,
            contribution_threshold_icp,
            one_third_participation_milestone_icp,
            full_participation_milestone_icp,
        })
    }

    pub fn try_derive_neurons_fund_participation_limits(
        &self,
    ) -> Result<NeuronsFundParticipationLimits, String> {
        let Some(ref economics) = self.heap_data.economics else {
            return Err("Network Economics must be specified.".to_string());
        };

        // The initial values are expected to be populated in `canister_post_upgrade`.
        let Some(ref neurons_fund_economics) = economics.neurons_fund_economics else {
            return Err("Neurons' Fund economics must be specified.".to_string());
        };

        let icp_xdr_rate = self.icp_xdr_rate();

        Self::try_derive_neurons_fund_participation_limits_impl(
            neurons_fund_economics,
            icp_xdr_rate,
        )
    }
}

// -------------------------------------------------------------------------------------------------
// ------------------- NeuronsFundNeuronPortion ----------------------------------------------------
// -------------------------------------------------------------------------------------------------

/// This structure represents an arbitrary portion of a Neurons' Fund neuron, be that the whole
/// neuron (in which case `amount_icp_e8s` equals `maturity_equivalent_icp_e8s`) or a portion
/// thereof that may either participate in an SNS swap or be refunded.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NeuronsFundNeuronPortion {
    /// The NNS neuron ID of the participating neuron.
    pub id: NeuronId,
    /// Portion of maturity taken from this neuron. Must be less than or equal to
    /// `maturity_equivalent_icp_e8s`.
    pub amount_icp_e8s: u64,
    /// Overall amount of maturity of the neuron from which this portion is taken.
    pub maturity_equivalent_icp_e8s: u64,
    /// Controller of the neuron from which this portion is taken.
    pub controller: PrincipalId,
    /// Hotkeys of the neuron from which this portion is taken.
    /// TOOD(NNS1-3198): This field is not currently populated.
    pub hotkeys: Vec<PrincipalId>,
    /// Indicates whether the portion specified by `amount_icp_e8s` is limited due to SNS-specific
    /// participation constraints.
    pub is_capped: bool,
}

// By-default, Neurons' Fund neuron portions should be ordered lexicographically, first by
// `controller`, then by `maturity_equivalent_icp_e8s`.
impl Ord for NeuronsFundNeuronPortion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.controller.cmp(&other.controller) {
            Ordering::Equal => self
                .maturity_equivalent_icp_e8s
                .cmp(&other.maturity_equivalent_icp_e8s),
            ordering => ordering,
        }
    }
}

impl PartialOrd for NeuronsFundNeuronPortion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(PartialEq, Debug)]
pub enum NeuronsFundNeuronPortionError {
    UnspecifiedField(String),
    AmountTooBig {
        amount_icp_e8s: u64,
        maturity_equivalent_icp_e8s: u64,
    },
}

impl std::fmt::Display for NeuronsFundNeuronPortionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = "Invalid NeuronsFundNeuronPortion: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                write!(f, "{}field `{}` is not specified.", prefix, field_name)
            }
            Self::AmountTooBig {
                amount_icp_e8s,
                maturity_equivalent_icp_e8s,
            } => {
                write!(
                    f,
                    "{}`amount_icp_e8s` ({}) exceeds `maturity_equivalent_icp_e8s` ({})",
                    prefix, amount_icp_e8s, maturity_equivalent_icp_e8s,
                )
            }
        }
    }
}

impl NeuronsFundNeuronPortionPb {
    pub fn validate(&self) -> Result<NeuronsFundNeuronPortion, NeuronsFundNeuronPortionError> {
        let id = self.nns_neuron_id.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("nns_neuron_id".to_string())
        })?;
        let amount_icp_e8s = self.amount_icp_e8s.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("amount_icp_e8s".to_string())
        })?;
        let maturity_equivalent_icp_e8s = self.maturity_equivalent_icp_e8s.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField(
                "maturity_equivalent_icp_e8s".to_string(),
            )
        })?;
        if maturity_equivalent_icp_e8s < amount_icp_e8s {
            return Err(NeuronsFundNeuronPortionError::AmountTooBig {
                amount_icp_e8s,
                maturity_equivalent_icp_e8s,
            });
        }
        #[allow(deprecated)] // TODO(NNS1-3198): remove .or(hotkey_principal)
        let controller = self.controller.or(self.hotkey_principal).ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("hotkey_principal".to_string())
        })?;
        let hotkeys = self.hotkeys.clone();
        let is_capped = self.is_capped.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("is_capped".to_string())
        })?;
        Ok(NeuronsFundNeuronPortion {
            id,
            amount_icp_e8s,
            maturity_equivalent_icp_e8s,
            controller,
            hotkeys,
            is_capped,
        })
    }

    /// Returns a clone of `self` without sensitive data, specifically, `nns_neuron_id`.
    pub fn anonymized(&self) -> Self {
        Self {
            nns_neuron_id: None,
            ..self.clone()
        }
    }
}

pub trait NeuronsFund {
    fn draw_maturity_from_neurons_fund(
        &mut self,
        snapshot: &NeuronsFundSnapshot,
    ) -> Result<(), String>;

    fn refund_maturity_to_neurons_fund(
        &mut self,
        snapshot: &NeuronsFundSnapshot,
    ) -> Result<(), String>;
}

impl NeuronsFund for NeuronStore {
    fn draw_maturity_from_neurons_fund(
        &mut self,
        snapshot: &NeuronsFundSnapshot,
    ) -> Result<(), String> {
        apply_neurons_fund_snapshot(self, snapshot, NeuronsFundAction::DrawMaturity)
    }

    fn refund_maturity_to_neurons_fund(
        &mut self,
        snapshot: &NeuronsFundSnapshot,
    ) -> Result<(), String> {
        apply_neurons_fund_snapshot(self, snapshot, NeuronsFundAction::RefundMaturity)
    }
}

// -------------------------------------------------------------------------------------------------
// ------------------- NeuronsFundSnapshot ---------------------------------------------------------
// -------------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq, Debug)]
pub struct NeuronsFundSnapshot {
    neurons: BTreeMap<NeuronId, NeuronsFundNeuronPortion>,
}

impl NeuronsFundSnapshot {
    pub fn empty() -> Self {
        let neurons = BTreeMap::new();
        Self { neurons }
    }

    pub fn is_empty(&self) -> bool {
        self.neurons.is_empty()
    }

    pub fn num_neurons(&self) -> usize {
        self.neurons.len()
    }

    pub fn new<I>(neurons: I) -> Self
    where
        I: IntoIterator<Item = NeuronsFundNeuronPortion>,
    {
        let neurons = neurons.into_iter().map(|n| (n.id, n)).collect();
        Self { neurons }
    }

    pub fn neurons(&self) -> &BTreeMap<NeuronId, NeuronsFundNeuronPortion> {
        &self.neurons
    }

    pub fn total_amount_icp_e8s(&self) -> Result<u64, String> {
        self.neurons.values().try_fold(0_u64, |a, n| {
            a.checked_add(n.amount_icp_e8s).ok_or_else(|| {
                "u64 overflow while trying to compute NeuronsFundSnapshot.total_amount_icp_e8s"
                    .to_string()
            })
        })
    }

    pub fn into_vec(self) -> Vec<NeuronsFundNeuronPortion> {
        self.neurons.into_values().collect()
    }

    /// Implements the `self - other` semantics for calculating Neurons' Fund refunds, consuming
    /// `self`. This means that the resulting snapshot is comprised of neuron portions with maturity
    /// amounts set to the difference between the corresponding neuron portions from `self`
    /// and `other`.
    ///
    /// Example A:
    /// self = { (N1, amount=100), (N2, amount=200), (N3, amount=300) }
    /// other = { (N1, amount=80), (N3, amount=300) }
    /// result = Ok({ (N1, amount=20), (N2, amount=200) })
    ///
    /// All remaining fields in the resulting snapshot's neuron portions are taken from `other`.
    /// `maturity_equivalent_icp_e8s` and `controller` are properties of the neuron itself, so they
    /// remain the same for all of this neuron's portions. However, the value of `is_capped` is
    /// taken from `other` for a different reason: The snapshot returned by this function
    /// corresponds to the final state of an SNS Swap (in which the Neurons' Fund is participating),
    /// and since final is a subset of initially reserved snapshot, consider `initial.diff(final)`.
    ///
    /// Example B:
    /// self = { (N1, amount=100) }
    /// other = { (N1, amount=80), (N3, amount=300) }
    /// result = Err("Cannot compute diff ...")
    #[allow(clippy::manual_try_fold)]
    pub fn diff(self, other: &Self) -> Result<Self, String> {
        let mut deductible_neurons = other.neurons().clone();
        let err_prefix = || "Cannot compute diff of two Neurons' Fund snapshots".to_string();
        let neurons = self
            .neurons
            .into_iter()
            .filter_map(|(id, left)| {
                let (amount_icp_e8s, maturity_equivalent_icp_e8s, controller, hotkeys, is_capped) =
                    if let Some(right) = deductible_neurons.remove(&id) {
                        let err_prefix =
                            || format!("Cannot compute diff of two portions of neuron {:?}: ", id);
                        let Some(amount_icp_e8s) =
                            left.amount_icp_e8s.checked_sub(right.amount_icp_e8s)
                        else {
                            return Some(Err(format!(
                                "{}left.amount_icp_e8s={:?}, right.amount_icp_e8s={:?}.",
                                err_prefix(),
                                left.amount_icp_e8s,
                                right.amount_icp_e8s,
                            )));
                        };
                        let maturity_equivalent_icp_e8s = {
                            if left.maturity_equivalent_icp_e8s != right.maturity_equivalent_icp_e8s
                            {
                                return Some(Err(format!(
                                    "{}left.maturity_equivalent_icp_e8s={:?} != \
                                right.maturity_equivalent_icp_e8s={:?}.",
                                    err_prefix(),
                                    left.maturity_equivalent_icp_e8s,
                                    right.maturity_equivalent_icp_e8s,
                                )));
                            }
                            right.maturity_equivalent_icp_e8s
                        };
                        let controller = {
                            if left.controller != right.controller {
                                return Some(Err(format!(
                                    "{}left.controller={:?}, right.controller={:?}.",
                                    err_prefix(),
                                    left.controller,
                                    right.controller,
                                )));
                            };
                            right.controller
                        };
                        let hotkeys = {
                            if left.hotkeys != right.hotkeys {
                                return Some(Err(format!(
                                    "{}left.hotkeys={:?}, right.hotkeys={:?}.",
                                    err_prefix(),
                                    left.hotkeys,
                                    right.hotkeys,
                                )));
                            };
                            right.hotkeys
                        };
                        let is_capped = {
                            if !left.is_capped && right.is_capped {
                                return Some(Err(format!(
                                    "{}left.is_capped=false, right.is_capped=true.",
                                    err_prefix()
                                )));
                            }
                            // Taking right.is_capped, as that corresponds to the capping of
                            // the effectively taken portion of the neuron (left.is_capped is
                            // whether the originally reserved portion has been capped).
                            right.is_capped
                        };
                        (
                            amount_icp_e8s,
                            maturity_equivalent_icp_e8s,
                            controller,
                            hotkeys,
                            is_capped,
                        )
                    } else {
                        (
                            left.amount_icp_e8s,
                            left.maturity_equivalent_icp_e8s,
                            left.controller,
                            left.hotkeys,
                            // The effectively taken portion of this neuron is zero, so it cannot
                            // be capped.
                            false,
                        )
                    };
                if amount_icp_e8s == 0 {
                    // Nothing to refund for this neuron.
                    None
                } else {
                    let portion = NeuronsFundNeuronPortion {
                        id,
                        amount_icp_e8s,
                        controller,
                        hotkeys,
                        maturity_equivalent_icp_e8s,
                        is_capped,
                    };
                    Some(Ok((id, portion)))
                }
            })
            // Avoid using `try_fold` here as we should not short-circuit errors.
            .fold(Ok(BTreeMap::new()), |overall_result, sub_result| {
                match (overall_result, sub_result) {
                    (Ok(mut portions), Ok((id, portion))) => {
                        portions.insert(id, portion);
                        Ok(portions)
                    }
                    (Ok(_), Err(error)) => Err(vec![error]),
                    (Err(errors), Ok(_)) => Err(errors),
                    (Err(mut errors), Err(error)) => {
                        errors.push(error);
                        Err(errors)
                    }
                }
            })
            .map_err(|errors| format!("{}:\n  - {}", err_prefix(), errors.join("\n  - ")))?;
        if !deductible_neurons.is_empty() {
            let extra_neuron_portions_str = deductible_neurons
                .keys()
                .map(|n| format!("{:?}", n))
                .collect::<Vec<String>>()
                .join(", ");
            return Err(format!(
                "{}: right-hand side \
                contains {} extra neuron portions: {}",
                err_prefix(),
                deductible_neurons.len(),
                extra_neuron_portions_str,
            ));
        }
        Ok(Self { neurons })
    }
}

impl From<NeuronsFundSnapshot> for NeuronsFundSnapshotPb {
    fn from(snapshot: NeuronsFundSnapshot) -> Self {
        let neurons_fund_neuron_portions = snapshot
            .into_vec()
            .into_iter()
            .map(Into::<NeuronsFundNeuronPortionPb>::into)
            .collect();
        Self {
            neurons_fund_neuron_portions,
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum NeuronsFundSnapshotValidationError {
    NeuronsFundNeuronPortionError(usize, NeuronsFundNeuronPortionError),
}

impl std::fmt::Display for NeuronsFundSnapshotValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = "Cannot validate NeuronsFundSnapshot: ";
        match self {
            Self::NeuronsFundNeuronPortionError(index, error) => {
                write!(
                    f,
                    "{}neurons_fund_neuron_portions[{}]: {}",
                    prefix, index, error
                )
            }
        }
    }
}

impl NeuronsFundSnapshotPb {
    pub fn validate(&self) -> Result<NeuronsFundSnapshot, NeuronsFundSnapshotValidationError> {
        let neurons_fund = self
            .neurons_fund_neuron_portions
            .iter()
            .enumerate()
            .map(|(i, n)| {
                n.validate().map_err(|err| {
                    NeuronsFundSnapshotValidationError::NeuronsFundNeuronPortionError(i, err)
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(NeuronsFundSnapshot::new(neurons_fund))
    }

    /// Returns a clone of `self` without sensitive data, specifically, `nns_neuron_id`.
    pub fn anonymized(&self) -> Self {
        Self {
            neurons_fund_neuron_portions: self
                .neurons_fund_neuron_portions
                .iter()
                .map(NeuronsFundNeuronPortionPb::anonymized)
                .collect(),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// ------------------- NeuronsFundParticipation ----------------------------------------------------
// -------------------------------------------------------------------------------------------------

/// Absolute constraints of this swap needed in Matched Funding computations.
#[derive(Clone, PartialEq, Debug)]
pub struct SwapParticipationLimits {
    pub min_direct_participation_icp_e8s: u64,
    pub max_direct_participation_icp_e8s: u64,
    pub min_participant_icp_e8s: u64,
    pub max_participant_icp_e8s: u64,
}

#[derive(PartialEq, Debug)]
pub enum SwapParametersError {
    /// We expect this to never occur, and can ensure this, since the caller is Swap, and we control
    /// the code that the Swap canisters run.
    UnspecifiedField(String),
    MaxIsLessThanOrEqualMinParticipationIcp {
        min_direct_participation_icp_e8s: u64,
        max_direct_participation_icp_e8s: u64,
    },
    MinIsLessThanOrEqualMaxParticipantIcp {
        min_participant_icp_e8s: u64,
        max_participant_icp_e8s: u64,
    },
}

impl std::fmt::Display for SwapParametersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = "Cannot extract data from SwapParameters: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                write!(f, "{}field `{}` is not specified.", prefix, field_name,)
            }
            Self::MaxIsLessThanOrEqualMinParticipationIcp {
                min_direct_participation_icp_e8s,
                max_direct_participation_icp_e8s,
            } => {
                write!(
                    f,
                    "{}invariant violated: min_direct_participation_icp_e8s ({}) \
                    <= max_direct_participation_icp_e8s ({}).",
                    prefix, min_direct_participation_icp_e8s, max_direct_participation_icp_e8s,
                )
            }
            Self::MinIsLessThanOrEqualMaxParticipantIcp {
                min_participant_icp_e8s,
                max_participant_icp_e8s,
            } => {
                write!(
                    f,
                    "{}invariant violated: min_participant_icp_e8s ({}) \
                    <= max_participant_icp_e8s ({}).",
                    prefix, min_participant_icp_e8s, max_participant_icp_e8s,
                )
            }
        }
    }
}

impl From<SwapParametersError> for GovernanceError {
    fn from(swap_parameters_error: SwapParametersError) -> Self {
        Self {
            error_type: governance_error::ErrorType::InvalidCommand as i32,
            error_message: swap_parameters_error.to_string(),
        }
    }
}

impl SwapParticipationLimits {
    pub fn validate(&self) -> Result<(), SwapParametersError> {
        if self.min_direct_participation_icp_e8s > self.max_direct_participation_icp_e8s {
            return Err(
                SwapParametersError::MaxIsLessThanOrEqualMinParticipationIcp {
                    min_direct_participation_icp_e8s: self.min_direct_participation_icp_e8s,
                    max_direct_participation_icp_e8s: self.max_direct_participation_icp_e8s,
                },
            );
        }
        if self.min_participant_icp_e8s > self.max_participant_icp_e8s {
            return Err(SwapParametersError::MinIsLessThanOrEqualMaxParticipantIcp {
                min_participant_icp_e8s: self.min_participant_icp_e8s,
                max_participant_icp_e8s: self.max_participant_icp_e8s,
            });
        }
        Ok(())
    }

    pub fn try_from_swap_parameters(
        swap_parameters: &SwapParameters,
    ) -> Result<Self, SwapParametersError> {
        let min_direct_participation_icp_e8s = swap_parameters
            .minimum_direct_participation_icp
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField(
                    "minimum_direct_participation_icp".to_string(),
                )
            })?
            .e8s
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField(
                    "minimum_direct_participation_icp.e8s".to_string(),
                )
            })?;
        let max_direct_participation_icp_e8s = swap_parameters
            .maximum_direct_participation_icp
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField(
                    "maximum_direct_participation_icp".to_string(),
                )
            })?
            .e8s
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField(
                    "maximum_direct_participation_icp.e8s".to_string(),
                )
            })?;
        let min_participant_icp_e8s = swap_parameters
            .minimum_participant_icp
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField("minimum_participant_icp".to_string())
            })?
            .e8s
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField("minimum_participant_icp.e8s".to_string())
            })?;
        let max_participant_icp_e8s = swap_parameters
            .maximum_participant_icp
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField("maximum_participant_icp".to_string())
            })?
            .e8s
            .ok_or_else(|| {
                SwapParametersError::UnspecifiedField("maximum_participant_icp.e8s".to_string())
            })?;
        let result = Self {
            min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s,
            min_participant_icp_e8s,
            max_participant_icp_e8s,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Information for deciding how the Neurons' Fund should participate in an SNS Swap.
#[derive(Debug)]
pub struct NeuronsFundParticipation<F> {
    swap_participation_limits: SwapParticipationLimits,
    ideal_matched_participation_function: Box<F>,
    /// Represents the participation amount per Neurons' Fund neuron.
    neurons_fund_reserves: NeuronsFundSnapshot,
    /// Neurons' Fund participation is computed for this amount of direct participation.
    direct_participation_icp_e8s: u64,
    /// Total amount of maturity in the Neurons' Fund at the time when the Neurons' Fund
    /// participation was created.
    total_maturity_equivalent_icp_e8s: u64,
    /// Maximum amount that the Neurons' Fund will participate with in this SNS swap, regardless of
    /// how large the value of `direct_participation_icp_e8s` is. This value is capped by whichever
    /// of the two is the smallest value:
    /// * `ideal_matched_participation_function.apply(swap_participation_limits.max_direct_participation_icp_e8s)`,
    /// * 10% of the total Neurons' Fund maturity ICP equivalent.
    ///
    /// Warning: This value does not take into account limiting the participation of individual
    /// Neurons' Fund neurons, i.e., capping and dropping. To compute the precise Neurons' Fund
    /// participation amount, use `allocated_neurons_fund_participation_icp_e8s`.
    max_neurons_fund_swap_participation_icp_e8s: u64,
    /// How much the Neurons' Fund would ideally like to participate with in this SNS swap,
    /// given the direct participation amount (`direct_participation_icp_e8s`) and matching function
    /// (`ideal_matched_participation_function`).
    ///
    /// Warning: This value does not take into account limiting the participation of individual
    /// Neurons' Fund neurons, i.e., capping and dropping. To compute the precise Neurons' Fund
    /// participation amount, use `allocated_neurons_fund_participation_icp_e8s`.
    intended_neurons_fund_participation_icp_e8s: u64,

    /// How much from `intended_neurons_fund_participation_icp_e8s` was the Neurons' Fund actually
    /// able to allocate, given the specific composition of neurons at the time of execution of
    /// the proposal through which this SNS was created and the participation limits of this SNS.
    allocated_neurons_fund_participation_icp_e8s: u64,
}

impl<F> NeuronsFundParticipation<F>
where
    F: IdealMatchingFunction,
{
    /// Returns whether there is some participation at all.
    pub fn is_empty(&self) -> bool {
        self.neurons_fund_reserves.is_empty()
    }

    /// Returns the total Neurons' Fund participation amount.
    pub fn total_amount_icp_e8s(&self) -> u64 {
        self.allocated_neurons_fund_participation_icp_e8s
    }

    pub fn num_neurons(&self) -> usize {
        self.neurons_fund_reserves.num_neurons()
    }

    fn count_neurons_fund_total_maturity_equivalent_icp_e8s(
        neurons_fund: &[NeuronsFundNeuron],
    ) -> Result<u64, String> {
        neurons_fund
            .iter()
            .map(|neuron| neuron.maturity_equivalent_icp_e8s)
            .try_fold(0_u64, |a, n| {
                a.checked_add(n).ok_or_else(|| {
                    "u64 overflow while trying to compute Neurons' Fund total maturity.".to_string()
                })
            })
    }

    /// Create a new Neurons' Fund participation for the given `swap_participation_limits`
    /// and `ideal_matched_participation_function`.
    #[cfg(test)]
    pub fn new_for_test(
        swap_participation_limits: SwapParticipationLimits,
        neurons_fund: Vec<NeuronsFundNeuron>,
        ideal_matched_participation_function: Box<F>,
    ) -> Result<Self, String> {
        let total_maturity_equivalent_icp_e8s =
            Self::count_neurons_fund_total_maturity_equivalent_icp_e8s(&neurons_fund)?;
        Self::new_impl(
            total_maturity_equivalent_icp_e8s,
            swap_participation_limits.max_direct_participation_icp_e8s, // best case scenario
            swap_participation_limits,
            neurons_fund,
            ideal_matched_participation_function,
        )
    }

    /// Consumes self, returning the contained `NeuronsFundSnapshot`.
    pub fn into_snapshot(self) -> NeuronsFundSnapshot {
        self.neurons_fund_reserves
    }

    /// Borrows self, returning a reference to the contained `NeuronsFundSnapshot`.
    pub fn snapshot(&self) -> &NeuronsFundSnapshot {
        &self.neurons_fund_reserves
    }

    /// Retains self, returning a cloned version of the contained `NeuronsFundSnapshot`.
    pub fn snapshot_cloned(&self) -> NeuronsFundSnapshot {
        self.neurons_fund_reserves.clone()
    }

    /// Create a new Neurons' Fund participation matching given `direct_participation_icp_e8s` with
    /// `ideal_matched_participation_function`. All other parameters are taken from `self`.
    #[cfg(test)]
    pub fn from_initial_participation_for_test(
        &self,
        direct_participation_icp_e8s: u64,
        ideal_matched_participation_function: Box<F>,
    ) -> Result<Self, String> {
        let neurons_fund = self
            .snapshot()
            .neurons()
            .values()
            .map(
                |NeuronsFundNeuronPortion {
                     id,
                     maturity_equivalent_icp_e8s,
                     controller,
                     hotkeys,
                     ..
                 }| {
                    NeuronsFundNeuron {
                        id: *id,
                        maturity_equivalent_icp_e8s: *maturity_equivalent_icp_e8s,
                        controller: *controller,
                        hotkeys: hotkeys.clone(),
                    }
                },
            )
            .collect();
        Self::new_impl(
            self.total_maturity_equivalent_icp_e8s,
            direct_participation_icp_e8s,
            self.swap_participation_limits.clone(),
            neurons_fund,
            ideal_matched_participation_function,
        )
    }

    fn new_impl(
        total_maturity_equivalent_icp_e8s: u64,
        direct_participation_icp_e8s: u64,
        swap_participation_limits: SwapParticipationLimits,
        neurons_fund: Vec<NeuronsFundNeuron>,
        ideal_matched_participation_function: Box<F>,
    ) -> Result<Self, String> {
        // Take 10% of overall Neurons' Fund maturity.
        let max_neurons_fund_swap_participation_icp_e8s =
            take_max_initial_neurons_fund_participation_percentage(
                total_maturity_equivalent_icp_e8s,
            );
        // Apply cap dictated by `ideal_matched_participation_function`.
        let max_neurons_fund_swap_participation_icp_e8s = u64::min(
            max_neurons_fund_swap_participation_icp_e8s,
            ideal_matched_participation_function.apply_and_rescale_to_icp_e8s(
                swap_participation_limits.max_direct_participation_icp_e8s,
            )?,
        );
        let ideal_matched_participation_function_value_icp_e8s =
            ideal_matched_participation_function
                .apply_and_rescale_to_icp_e8s(direct_participation_icp_e8s)?;
        if ideal_matched_participation_function_value_icp_e8s > direct_participation_icp_e8s {
            return Err(format!(
                "ideal_matched_participation_function_value_icp_e8s ({}) is greater than \
                direct_participation_icp_e8s ({}). ideal_matched_participation_function = {:?}\n \
                Plot: \n{:?}",
                ideal_matched_participation_function_value_icp_e8s,
                direct_participation_icp_e8s,
                ideal_matched_participation_function,
                ideal_matched_participation_function
                    .plot(NonZeroU64::try_from(50).unwrap())
                    .map(|plot| format!("{:?}", plot))
                    .unwrap_or_else(|e| e)
            ));
        }
        let intended_neurons_fund_participation_icp_e8s = u64::min(
            ideal_matched_participation_function_value_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
        );
        // After the `neurons_fund_reserves` collection is fully computed, `allocated_neurons_fund_participation_icp_e8s`
        // will contain the sum of per-neuron amounts before they are converted from `Decimal` to
        // `u64`, so we keep the sum as precise as possible. This gives us more precision than
        // `neurons_fund_reserves.total_amount_icp_e8s()`, the sum of (pre-rounded) `u64` values.
        let (neurons_fund_reserves, allocated_neurons_fund_participation_icp_e8s) =
            if total_maturity_equivalent_icp_e8s == 0 {
                (NeuronsFundSnapshot::empty(), Decimal::ZERO)
            } else if intended_neurons_fund_participation_icp_e8s == 0 {
                (NeuronsFundSnapshot::empty(), Decimal::ZERO)
            } else {
                // Unlike in most other places, here we keep the ICP values in e8s (even after converting
                // to Decimal). This mitigates rounding errors.
                let intended_neurons_fund_participation_icp_e8s =
                    u64_to_dec(intended_neurons_fund_participation_icp_e8s)?;
                let total_maturity_equivalent_icp_e8s =
                    u64_to_dec(total_maturity_equivalent_icp_e8s)?;
                let min_participant_icp_e8s =
                    u64_to_dec(swap_participation_limits.min_participant_icp_e8s)?;
                let max_participant_icp_e8s =
                    u64_to_dec(swap_participation_limits.max_participant_icp_e8s)?;

                // `try_fold` will short-circuit if an error occurs; otherwise, collect eligible neuron
                // portions into a `BTreeMap` with neuron ID keys and `NeuronsFundNeuronPortion` values.
                let (neurons, allocated_neurons_fund_participation_icp_e8s) = neurons_fund.into_iter().try_fold(
                (BTreeMap::new(), Decimal::ZERO),
                |(mut overall_neuron_portions, allocated_neurons_fund_participation_icp_e8s), NeuronsFundNeuron {
                     id,
                     maturity_equivalent_icp_e8s,
                     controller,
                     hotkeys,
                 }| {
                    // Division is safe, as `total_maturity_equivalent_icp_e8s != 0` in this branch.
                    let proportion_to_overall_neurons_fund = u64_to_dec(maturity_equivalent_icp_e8s)?
                        .checked_div(total_maturity_equivalent_icp_e8s)
                        .ok_or_else(|| {
                            "NeuronsFundParticipation cannot be created due to division error."
                                .to_string()
                        })?;
                    // Multiplication is safe because the left factor is a value between 0.0 and 1.0.
                    let ideal_participation_amount_icp_e8s = proportion_to_overall_neurons_fund
                        .checked_mul(intended_neurons_fund_participation_icp_e8s)
                        .ok_or_else(|| {
                            "NeuronsFundParticipation cannot be created due to multiplication error."
                                .to_string()
                        })?;
                    // Checking `ideal_participation_amount_icp_e8s == 0` here is probably only needed
                    // in testing, as in practice `min_participant_icp_e8s` is expected to be greater
                    // than zero, e.g., to cover the transaction fees. However, here we avoid making
                    // additional assumptions about the range of possible values of `min_participant_icp_e8s`
                    // to be extra safe.
                    if ideal_participation_amount_icp_e8s < min_participant_icp_e8s
                        || ideal_participation_amount_icp_e8s < Decimal::ONE {
                        // Do not include neurons that cannot participate under any circumstances.
                        return Ok((overall_neuron_portions, allocated_neurons_fund_participation_icp_e8s));
                    }
                    let (amount_icp_e8s, is_capped) = if ideal_participation_amount_icp_e8s > max_participant_icp_e8s {
                        (max_participant_icp_e8s, true)
                    } else {
                        (ideal_participation_amount_icp_e8s, false)
                    };
                    // Addition is safe because the sum is bounded by `total_maturity_equivalent_icp_e8s`,
                    // which was converted from `u64`.
                    let allocated_neurons_fund_participation_icp_e8s = allocated_neurons_fund_participation_icp_e8s
                        .checked_add(amount_icp_e8s)
                        .ok_or_else(|| {
                            "NeuronsFundParticipation cannot be created due to addition error."
                                .to_string()
                        })?;
                    // Conversion is safe because `amount_icp_e8s` is bounded by `intended_neurons_fund_participation_icp_e8s`
                    // and `max_participant_icp_e8s`, both of which were converted from `u64`.
                    let amount_icp_e8s = dec_to_u64(amount_icp_e8s)
                        .map_err(|err| {
                            format!("NeuronsFundParticipation cannot be created: {}", err)
                        })?;
                    let new_neuron_portion = NeuronsFundNeuronPortion {
                        id,
                        amount_icp_e8s,
                        maturity_equivalent_icp_e8s,
                        controller,
                        hotkeys,
                        is_capped,
                    };
                    if let Some(old_neuron_portion) = overall_neuron_portions.insert(id, new_neuron_portion) {
                        // This should not happen as `neurons_fund` should contain unique values.
                        return Err(format!(
                            "Duplicate Neurons' Fund neurons for {:?}: {:?}.",
                            id, old_neuron_portion
                        ));
                    }
                    Ok((overall_neuron_portions, allocated_neurons_fund_participation_icp_e8s))
                }
            )?;
                (
                    NeuronsFundSnapshot { neurons },
                    allocated_neurons_fund_participation_icp_e8s,
                )
            };
        let allocated_neurons_fund_participation_icp_e8s = dec_to_u64(allocated_neurons_fund_participation_icp_e8s)
            .map_err(|err| {
                // This should never actually happen, as the value is at most `intended_neurons_fund_participation_icp_e8s`
                // which has been converted from `u64`.
                format!(
                    "Cannot convert allocated_neurons_fund_participation_icp_e8s from Decimal to u64: {}",
                    err
                )
            })?;
        Ok(Self {
            swap_participation_limits,
            ideal_matched_participation_function,
            neurons_fund_reserves,
            direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s,
        })
    }

    /// Attempts to compute the most-accurate `NeuronsFundParticipationConstraints`, enabling
    /// Neurons' Fund clients (e.g., the SNS Swap canister) to track the overall Neurons' Fund
    /// participation amount in real time, provided the as the only input parameter.
    ///
    /// See `ic_neurons_fund::ValidatedNeuronsFundParticipationConstraints::<F>::apply` for
    /// a concrete example of how the output of this function can be used.
    ///
    /// The worst-case complexity of this function is O(N^2), where N is the number of neurons in
    /// the Neurons' Fund. This function needs to be called just once per SNS Swap, so this
    /// complexity should not be prohibitive in practice.
    pub fn compute_constraints(&self) -> Result<NeuronsFundParticipationConstraints, String> {
        let min_direct_participation_threshold_icp_e8s = Some(
            self.swap_participation_limits
                .min_direct_participation_icp_e8s,
        );
        let max_neurons_fund_participation_icp_e8s =
            Some(self.allocated_neurons_fund_participation_icp_e8s);
        let coefficient_intervals = self.compute_linear_scaling_coefficients()?;
        let ideal_matched_participation_function = Some(IdealMatchedParticipationFunctionSwapPb {
            serialized_representation: Some(self.ideal_matched_participation_function.serialize()),
        });
        Ok(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s,
            max_neurons_fund_participation_icp_e8s,
            coefficient_intervals,
            ideal_matched_participation_function,
        })
    }

    /// Returned value is a sequence of coefficients for mapping an ideal total matching amount
    /// (in ICP e8s) to the matched amount that would actually be achieved, based on: (a) the per-
    /// participantion limits of the swap, and b) the "size" of neurons in
    /// the Neuron's Fund (in this context, "size" refers to the amount of maturity in the neuron
    /// relative to the total amount of maturity held by all Neurons' Fund neurons when the SNS/swap
    /// was created). Under all circumstances, the resulting amount must never be greater than
    /// the ideal amount. If there are many "medium"-sized neurons, then the ideal vs. achieved
    /// matching will be close. "Big" and "small" neurons create a greater discrepancy due to
    /// capping and dropping (i.e., not being eligible to participate due to insufficient maturity).
    /// These adjustments ensure that the resulting participation amount, estimated by the Swap
    /// canister, respect limits of this SNS swap (specifically, `max_participant_icp_e8s` and
    /// `min_participant_icp_e8s`).
    ///
    /// Errors indicate one of the following cases:
    /// 1. `total_maturity_equivalent_icp_e8s == 0`.
    /// 2. `ideal_matched_participation_function` is not non-decreasing.
    /// 3. Arithmetic error while computing `ideal_matched_participation_function.apply` or
    ///    `ideal_matched_participation_function.invert`.
    /// 4. Failure in `HalfOpenInterval::find` (this should not happen, unless there is a bug).
    fn compute_linear_scaling_coefficients(&self) -> Result<Vec<LinearScalingCoefficient>, String> {
        let min_participant_icp =
            rescale_to_icp(self.swap_participation_limits.min_participant_icp_e8s)?;
        let max_participant_icp =
            rescale_to_icp(self.swap_participation_limits.max_participant_icp_e8s)?;
        let eligibility_intervals = self
            .compute_neuron_partition_intervals(min_participant_icp)
            .map_err(|err| format!("Error while computing eligibility intervals: {}", err))?;
        let capping_intervals = self
            .compute_neuron_partition_intervals(max_participant_icp)
            .map_err(|err| format!("Error while computing capping intervals: {}", err))?;
        // Merge all steps into a single vector, removing duplicates (a duplicate step occurs if
        // a neuron becomes eligible exactly exactly when another neuron becomes capped).
        // First, merge the steps from `eligibility_intervals` and `capping_intervals` and sort them.
        let steps: BTreeSet<u64> = eligibility_intervals
            .iter()
            .map(|interval| interval.from_direct_participation_icp_e8s)
            .chain(
                capping_intervals
                    .iter()
                    .map(|interval| interval.from_direct_participation_icp_e8s),
            )
            .collect();
        // Second, pre-compute the upper bounds for the intervals defined by the merged steps.
        let upper_bounds: Vec<u64> = steps
            .iter()
            .skip(1) // 2nd element is the upper bound of the 1st, etc.
            .chain(std::iter::once(&u64::MAX)) // ensure the iterator has the right legnth
            .cloned()
            .collect();
        // Finally, form the ultimate linear scaling coefficient intervals.
        let slope_denominator = Some(self.total_maturity_equivalent_icp_e8s);
        let linear_scaling_coefficients = steps
            .into_iter()
            .zip(upper_bounds)
            .map(
                |(from_direct_participation_icp_e8s, to_direct_participation_icp_e8s)| {
                    // This search should not fail unless there is a bug, as
                    // `from_direct_participation_icp_e8s` comes either from `eligibility_intervals`
                    // or `capping_intervals`, which we merged to create `steps`.
                    let eligible = HalfOpenInterval::find(
                        &eligibility_intervals,
                        from_direct_participation_icp_e8s,
                    )
                    .ok_or_else(|| {
                        format!(
                            "Cannot find the set of eligible neurons for \
                        direct_participation_icp_e8s in [{}, {})",
                            from_direct_participation_icp_e8s, to_direct_participation_icp_e8s
                        )
                    })?;
                    let capped = HalfOpenInterval::find(
                        &capping_intervals,
                        from_direct_participation_icp_e8s,
                    )
                    .ok_or_else(|| {
                        format!(
                            "Cannot find the set of capped neurons for \
                        direct_participation_icp_e8s in [{}, {})",
                            from_direct_participation_icp_e8s, to_direct_participation_icp_e8s
                        )
                    })?;
                    let intercept_icp_e8s = Some(
                        (capped.neurons.len() as u64)
                            .saturating_mul(self.swap_participation_limits.max_participant_icp_e8s),
                    );
                    let slope_numerator = Some(
                        eligible
                            .neurons
                            .iter()
                            .filter_map(|neuron| {
                                if capped.neurons.contains(neuron) {
                                    None
                                } else {
                                    Some(neuron.1) // maturity_equivalent_icp_e8s
                                }
                            })
                            .fold(0_u64, |sum, maturity_equivalent_icp_e8s| {
                                sum.saturating_add(maturity_equivalent_icp_e8s)
                            }),
                    );
                    Ok(LinearScalingCoefficient {
                        from_direct_participation_icp_e8s: Some(from_direct_participation_icp_e8s),
                        to_direct_participation_icp_e8s: Some(to_direct_participation_icp_e8s),
                        slope_numerator,
                        slope_denominator,
                        intercept_icp_e8s,
                    })
                },
            )
            .collect::<Result<Vec<_>, String>>()?;
        Ok(linear_scaling_coefficients)
    }

    /// Attempts to compute the sequence of `NeuronParticipationInterval`s in which fixed sets of
    /// neurons have their (proportional) maturity above the specified threshold.
    ///
    /// Example: Consider the Neurons' Fund neurons to be `{ N1: 700 ICP, N2: 300 ICP }`, with
    /// the total amount 1000 ICP. Thus, the proportional maturities are at 0.7 and 0.3 for
    /// N1 and N2, resp. Let the ideal matching function be defined as `f(x) = x` and let
    /// `threshold_icp == 200`. Finally, let the minimum direct participation amount be 100 ICP.
    /// Then this function should return the following intervals:
    /// 1. Direct participation from 0 till (200 / 0.7) ICP: {} // no neurons are above threshold
    /// 2. Direct participation from (200 / 0.7) ICP till (200 / 0.3) ICP: { N1 }
    /// 3. Direct participation from (200 / 0.3) ICP till +inf: { N1, N2 }
    ///
    /// Explanation for the `(200 / 0.7)` value above. When direct participation is 200 / 0.7,
    /// the ideal matching is also 200 / 0.7 (per the ideal matching function). Thus, N1 tries
    /// to participate at (200 / 0.7) * 0.7 = 200, which is enough to reach the threshold.
    fn compute_neuron_partition_intervals(
        &self,
        threshold_icp: Decimal,
    ) -> Result<Vec<NeuronParticipationInterval>, String> {
        if self.total_maturity_equivalent_icp_e8s == 0 {
            return Err("Cannot compute Neurons' Fund participation intervals, \
                as total_maturity_equivalent_icp_e8s = 0."
                .to_string());
        }

        // Maps `direct_participation_icp_e8s` to a set of
        // `(neuron_id, maturity_equivalent_icp_e8s)` pairs. Represented via `Vec` to make it
        // efficiently extendable in the loop.
        let mut steps: Vec<(u64, Vec<(NeuronId, u64)>)> = vec![];
        // Buffer containing previously computed neurons with maturity above threshold.
        let mut neurons_above_threshold: Vec<(NeuronId, u64)> = vec![];

        // Sort participating neurons in *descending* order of their `maturity_equivalent_icp_e8s`.
        // The descending allows adding largest neurons first, intuitively, because they become
        // big enough to reach the threshold, while the whole fund matches
        // `direct_participation_icp_e8s`. Those neurons remain above the threshold while
        // `direct_participation_icp_e8s` increases.
        let sorted_neurons = {
            let mut neurons = self.neurons_fund_reserves.clone().into_vec();
            neurons.sort_unstable_by_key(|neuron| 0 - (neuron.maturity_equivalent_icp_e8s as i128));
            neurons
        };

        // Unlike in most other places, here we keep the ICP value in e8s (even after converting to
        // Decimal). This mitigates rounding errors in the calculation of `proportion_to_overall_neurons_fund`.
        let total_maturity_equivalent_icp_e8s = u64_to_dec(self.total_maturity_equivalent_icp_e8s)?;

        // Start with `direct_participation_icp_e8s == 0`, then increase in the loop.
        let mut direct_participation_icp_e8s = 0;

        let matching_function_min_value_icp = self
            .ideal_matched_participation_function
            .apply(direct_participation_icp_e8s)?;

        let matching_function_max_value_icp =
            rescale_to_icp(self.max_neurons_fund_swap_participation_icp_e8s)?;

        // Track the intended amount, matching `direct_participation_icp`, that is to be allocated.
        // initialize `intended_amount_icp` with the minimal direct participation amount starting
        // from which the Neurons' Fund participation becomes possible.
        let mut intended_amount_icp = matching_function_min_value_icp;

        // Intuition behind how this loop works: At what `intended_amount_icp` would the next-
        // biggest neuron reach the threshold? Reaching the threshold happens when
        // `intended_amount_icp == threshold_icp / proportion_to_overall_neurons_fund`.
        // From that, we need to figure out what `direct_participation_icp_e8s` this value would
        // correspond to. We need the invert function to make use of the following two equations:
        // 1. `intended_amount_icp == ideal_matched_participation_function.apply(direct_participation_icp_e8s)`
        // 2. `intended_amount_icp == threshold_icp / proportion_to_overall_neurons_fund`
        // From these two equations, it follows that:
        // `ideal_matched_participation_function.apply(direct_participation_icp_e8s) == threshold_icp / proportion_to_overall_neurons_fund`.
        // From which follows the ultimate formula:
        // `direct_participation_icp_e8s == ideal_matched_participation_function.invert(threshold_icp / proportion_to_overall_neurons_fund)`.
        for NeuronsFundNeuronPortion {
            id,
            maturity_equivalent_icp_e8s,
            ..
        } in sorted_neurons
        {
            let proportion_to_overall_neurons_fund: Decimal =
                u64_to_dec(maturity_equivalent_icp_e8s)? / total_maturity_equivalent_icp_e8s;
            let ideal_participation_icp = intended_amount_icp * proportion_to_overall_neurons_fund;
            if ideal_participation_icp < threshold_icp {
                // This neuron starts participating exactly at `threshold_icp`. This corresponds
                // to the *whole* Neurons' Fund participating with
                // `threshold_icp / proportion_to_overall_neurons_fund` ICP.
                intended_amount_icp = threshold_icp / proportion_to_overall_neurons_fund;
                if intended_amount_icp < matching_function_min_value_icp {
                    // Since `intended_amount_icp` has been initialized with
                    // `matching_function_min_value_icp` and could only have been increased since
                    // then, this should never happen, unless the assumption that
                    // `ideal_matched_participation_function` is monotonically non-decreasing
                    // is violated.
                    return Err(format!(
                        "intended_amount_icp ({}) < matching_function_min_value_icp ({}); this is \
                        likely related to ideal_matched_participation_function not being \
                        monotonically non-decreasing.",
                        intended_amount_icp, matching_function_min_value_icp,
                    ));
                }
                if intended_amount_icp > matching_function_max_value_icp {
                    // No more steps can occur (`intended_amount_icp` cannot be inverted).
                    break;
                }
                // Save neurons above threshold at the current step.
                steps.push((
                    direct_participation_icp_e8s,
                    neurons_above_threshold.clone(),
                ));
                // Update `direct_participation_icp_e8s`, forming the next step.
                direct_participation_icp_e8s = self
                    .ideal_matched_participation_function
                    .invert(intended_amount_icp)
                    .map_err(|err| err.to_string())?;
            }
            neurons_above_threshold.push((id, maturity_equivalent_icp_e8s));
        }
        // Take into account that the neurons from the last step have not been saved yet.
        steps.push((
            direct_participation_icp_e8s,
            neurons_above_threshold.clone(),
        ));

        // Convert steps into (efficiently searchable) intervals.
        let upper_bounds: Vec<u64> = steps
            .iter()
            .map(|(to_direct_participation_icp_e8s, _)| *to_direct_participation_icp_e8s)
            .skip(1) // 2nd element is the upper bound of the 1st, etc.
            .chain(std::iter::once(u64::MAX)) // ensure the iterator has the right length
            .collect();
        let intervals: Vec<NeuronParticipationInterval> = steps
            .into_iter()
            .zip(upper_bounds)
            .map(
                |(
                    (from_direct_participation_icp_e8s, neurons),
                    to_direct_participation_icp_e8s,
                )| {
                    // Transform neurons into sets to make lookups more efficient. Note the requirements
                    // that we are trading off: (1) efficient lookups, (2) efficient full traversals,
                    // and (3) simple data structures (in the future, one could optimize further by
                    // maintaining each node inside a `Vec` and a `HashMap` at the same time).
                    let neurons = neurons.into_iter().collect();
                    NeuronParticipationInterval {
                        from_direct_participation_icp_e8s,
                        to_direct_participation_icp_e8s,
                        neurons,
                    }
                },
            )
            .collect();
        Ok(intervals)
    }
}

/// Represents one step in the step function
#[derive(PartialEq, Debug)]
struct NeuronParticipationInterval {
    from_direct_participation_icp_e8s: u64,
    to_direct_participation_icp_e8s: u64,
    /// Each neuron is represented as a `(neuron_id, maturity_equivalent_icp_e8s)` pair.
    pub neurons: BTreeSet<(NeuronId, u64)>,
}

impl HalfOpenInterval for NeuronParticipationInterval {
    fn from(&self) -> u64 {
        self.from_direct_participation_icp_e8s
    }
    fn to(&self) -> u64 {
        self.to_direct_participation_icp_e8s
    }
}

pub type PolynomialNeuronsFundParticipation = NeuronsFundParticipation<PolynomialMatchingFunction>;

impl PolynomialNeuronsFundParticipation {
    /// Create a new Neurons' Fund participation for the given `swap_participation_limits`.
    pub fn new(
        neurons_fund_participation_limits: NeuronsFundParticipationLimits,
        swap_participation_limits: SwapParticipationLimits,
        neurons_fund: Vec<NeuronsFundNeuron>,
    ) -> Result<Self, String> {
        let total_maturity_equivalent_icp_e8s =
            Self::count_neurons_fund_total_maturity_equivalent_icp_e8s(&neurons_fund)?;
        let ideal_matched_participation_function = Box::from(PolynomialMatchingFunction::new(
            total_maturity_equivalent_icp_e8s,
            neurons_fund_participation_limits,
            cfg!(not(test)),
        )?);
        Self::new_impl(
            total_maturity_equivalent_icp_e8s,
            swap_participation_limits.max_direct_participation_icp_e8s, // best case scenario
            swap_participation_limits,
            neurons_fund,
            ideal_matched_participation_function,
        )
    }

    /// Create a new Neurons' Fund participation matching given `direct_participation_icp_e8s` with
    /// `ideal_matched_participation_function`.  All other parameters are taken from `self`.
    pub fn from_initial_participation(
        &self,
        direct_participation_icp_e8s: u64,
    ) -> Result<Self, String> {
        let neurons_fund = self
            .snapshot()
            .neurons()
            .values()
            .map(
                |NeuronsFundNeuronPortion {
                     id,
                     maturity_equivalent_icp_e8s,
                     controller,
                     hotkeys,
                     ..
                 }| {
                    NeuronsFundNeuron {
                        id: *id,
                        maturity_equivalent_icp_e8s: *maturity_equivalent_icp_e8s,
                        controller: *controller,
                        hotkeys: hotkeys.clone(),
                    }
                },
            )
            .collect();
        Self::new_impl(
            self.total_maturity_equivalent_icp_e8s,
            direct_participation_icp_e8s,
            self.swap_participation_limits.clone(),
            neurons_fund,
            self.ideal_matched_participation_function.clone(),
        )
    }
}

#[derive(PartialEq, Debug)]
pub enum NeuronsFundParticipationValidationError {
    UnspecifiedField(String),
    NeuronsFundSnapshotValidationError(NeuronsFundSnapshotValidationError),
    MatchFunctionDeserializationFailed(String),
    SwapParametersError(SwapParametersError),
    NeuronsFundParticipationGreaterThanDirectParticipation {
        allocated_neurons_fund_participation_icp_e8s: u64,
        direct_participation_icp_e8s: u64,
    },
    InvalidAllocation {
        allocated_neurons_fund_participation_icp_e8s: u64,
        intended_neurons_fund_participation_icp_e8s: u64,
        max_neurons_fund_swap_participation_icp_e8s: u64,
        total_maturity_equivalent_icp_e8s: u64,
    },
    InconsistentTotalAllocationData {
        allocated_neurons_fund_participation_icp_e8s: u64,
        neurons_fund_reserves_total_amount_icp_e8s: u64,
    },
}

impl std::fmt::Display for NeuronsFundParticipationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = "NeuronsFundParticipation is invalid: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                write!(f, "{}field `{}` is not specified.", prefix, field_name)
            }
            Self::NeuronsFundSnapshotValidationError(error) => {
                write!(f, "{}{}", prefix, error)
            }
            Self::MatchFunctionDeserializationFailed(error) => {
                write!(
                    f,
                    "{}failed to deserialize an IdealMatchingFunction instance: {}",
                    prefix, error
                )
            }
            Self::SwapParametersError(error) => {
                write!(f, "{}{}", prefix, error)
            }
            Self::NeuronsFundParticipationGreaterThanDirectParticipation {
                allocated_neurons_fund_participation_icp_e8s,
                direct_participation_icp_e8s,
            } => {
                write!(
                    f,
                    "{}invariant violated: allocated_neurons_fund_participation_icp_e8s ({}) \
                    must be <= direct_participation_icp_e8s ({}).",
                    prefix,
                    allocated_neurons_fund_participation_icp_e8s,
                    direct_participation_icp_e8s,
                )
            }
            Self::InvalidAllocation {
                allocated_neurons_fund_participation_icp_e8s,
                intended_neurons_fund_participation_icp_e8s,
                max_neurons_fund_swap_participation_icp_e8s,
                total_maturity_equivalent_icp_e8s,
            } => {
                write!(
                    f,
                    "{}invariant violated: allocated_neurons_fund_participation_icp_e8s ({}) \
                    must be <= intended_neurons_fund_participation_icp_e8s ({}) \
                    must be <= max_neurons_fund_swap_participation_icp_e8s ({}) \
                    must be <= 10% of (total_maturity_equivalent_icp_e8s ({})).",
                    prefix,
                    allocated_neurons_fund_participation_icp_e8s,
                    intended_neurons_fund_participation_icp_e8s,
                    max_neurons_fund_swap_participation_icp_e8s,
                    total_maturity_equivalent_icp_e8s,
                )
            }
            Self::InconsistentTotalAllocationData {
                allocated_neurons_fund_participation_icp_e8s,
                neurons_fund_reserves_total_amount_icp_e8s,
            } => {
                write!(
                    f,
                    "{}inconsistent total allocation data: \
                    allocated_neurons_fund_participation_icp_e8s ({}) \
                    must be == neurons_fund_reserves.total_amount_icp_e8s ({}).",
                    prefix,
                    allocated_neurons_fund_participation_icp_e8s,
                    neurons_fund_reserves_total_amount_icp_e8s,
                )
            }
        }
    }
}

impl<F> From<NeuronsFundParticipation<F>> for NeuronsFundParticipationPb
where
    F: IdealMatchingFunction,
{
    fn from(participation: NeuronsFundParticipation<F>) -> Self {
        let serialized_representation = Some(
            participation
                .ideal_matched_participation_function
                .serialize(),
        );
        let ideal_matched_participation_function = Some(IdealMatchedParticipationFunction {
            serialized_representation,
        });
        let swap_participation_limits = Some(SwapParticipationLimitsPb {
            min_direct_participation_icp_e8s: Some(
                participation
                    .swap_participation_limits
                    .min_direct_participation_icp_e8s,
            ),
            max_direct_participation_icp_e8s: Some(
                participation
                    .swap_participation_limits
                    .max_direct_participation_icp_e8s,
            ),
            min_participant_icp_e8s: Some(
                participation
                    .swap_participation_limits
                    .min_participant_icp_e8s,
            ),
            max_participant_icp_e8s: Some(
                participation
                    .swap_participation_limits
                    .max_participant_icp_e8s,
            ),
        });
        let direct_participation_icp_e8s = Some(participation.direct_participation_icp_e8s);
        let total_maturity_equivalent_icp_e8s =
            Some(participation.total_maturity_equivalent_icp_e8s);
        let max_neurons_fund_swap_participation_icp_e8s =
            Some(participation.max_neurons_fund_swap_participation_icp_e8s);
        let intended_neurons_fund_participation_icp_e8s =
            Some(participation.intended_neurons_fund_participation_icp_e8s);
        let allocated_neurons_fund_participation_icp_e8s =
            Some(participation.allocated_neurons_fund_participation_icp_e8s);
        #[allow(deprecated)] // TODO(NNS1-3198): Remove
        let neurons_fund_neuron_portions: Vec<NeuronsFundNeuronPortionPb> = participation
            .into_snapshot()
            .neurons()
            .values()
            .map(|neuron| NeuronsFundNeuronPortionPb {
                nns_neuron_id: Some(neuron.id),
                amount_icp_e8s: Some(neuron.amount_icp_e8s),
                maturity_equivalent_icp_e8s: Some(neuron.maturity_equivalent_icp_e8s),
                is_capped: Some(neuron.is_capped),
                controller: Some(neuron.controller),
                hotkeys: neuron.hotkeys.clone(),
                // TODO(NNS1-3198): remove due to the  very misleading name
                hotkey_principal: Some(neuron.controller),
            })
            .collect();
        let neurons_fund_reserves = Some(NeuronsFundSnapshotPb {
            neurons_fund_neuron_portions,
        });
        Self {
            ideal_matched_participation_function,
            neurons_fund_reserves,
            swap_participation_limits,
            direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s,
        }
    }
}

impl NeuronsFundParticipationPb {
    /// Validate that a NeuronsFundParticipationPb structure is free of defects, returning a
    /// NeuronsFundParticipation structure with validated fields.
    pub fn validate(
        &self,
    ) -> Result<PolynomialNeuronsFundParticipation, NeuronsFundParticipationValidationError> {
        self.validate_impl()
    }

    fn validate_impl<F>(
        &self,
    ) -> Result<NeuronsFundParticipation<F>, NeuronsFundParticipationValidationError>
    where
        F: IdealMatchingFunction + DeserializableFunction,
    {
        let ideal_match_function_repr = self
            .ideal_matched_participation_function
            .as_ref()
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "ideal_matched_participation_function".to_string(),
                )
            })?
            .serialized_representation
            .as_ref()
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "ideal_matched_participation_function.serialized_representation".to_string(),
                )
            })?;
        let ideal_matched_participation_function = F::from_repr(ideal_match_function_repr)
            .map_err(NeuronsFundParticipationValidationError::MatchFunctionDeserializationFailed)?;
        let neurons_fund_reserves = self
            .neurons_fund_reserves
            .as_ref()
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "neurons_fund_reserves".to_string(),
                )
            })?
            .validate()
            .map_err(NeuronsFundParticipationValidationError::NeuronsFundSnapshotValidationError)?;
        let swap_participation_limits =
            self.swap_participation_limits.as_ref().ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "swap_participation_limits".to_string(),
                )
            })?;
        let min_direct_participation_icp_e8s = swap_participation_limits
            .min_direct_participation_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "swap_participation_limits.min_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let max_direct_participation_icp_e8s = swap_participation_limits
            .max_direct_participation_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "swap_participation_limits.max_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let min_participant_icp_e8s = swap_participation_limits
            .min_participant_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "swap_participation_limits.min_participant_icp_e8s".to_string(),
                )
            })?;
        let max_participant_icp_e8s = swap_participation_limits
            .max_participant_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "swap_participation_limits.max_participant_icp_e8s".to_string(),
                )
            })?;
        let swap_participation_limits = SwapParticipationLimits {
            min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s,
            min_participant_icp_e8s,
            max_participant_icp_e8s,
        };
        swap_participation_limits
            .validate()
            .map_err(NeuronsFundParticipationValidationError::SwapParametersError)?;
        let direct_participation_icp_e8s = self.direct_participation_icp_e8s.ok_or_else(|| {
            NeuronsFundParticipationValidationError::UnspecifiedField(
                "direct_participation_icp_e8s".to_string(),
            )
        })?;
        let total_maturity_equivalent_icp_e8s =
            self.total_maturity_equivalent_icp_e8s.ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "total_maturity_equivalent_icp_e8s".to_string(),
                )
            })?;
        let max_neurons_fund_swap_participation_icp_e8s = self
            .max_neurons_fund_swap_participation_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "max_neurons_fund_swap_participation_icp_e8s".to_string(),
                )
            })?;
        let intended_neurons_fund_participation_icp_e8s = self
            .intended_neurons_fund_participation_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "intended_neurons_fund_participation_icp_e8s".to_string(),
                )
            })?;
        let allocated_neurons_fund_participation_icp_e8s = self
            .allocated_neurons_fund_participation_icp_e8s
            .ok_or_else(|| {
                NeuronsFundParticipationValidationError::UnspecifiedField(
                    "allocated_neurons_fund_participation_icp_e8s".to_string(),
                )
            })?;
        if allocated_neurons_fund_participation_icp_e8s > direct_participation_icp_e8s {
            return Err(
                NeuronsFundParticipationValidationError::NeuronsFundParticipationGreaterThanDirectParticipation {
                    allocated_neurons_fund_participation_icp_e8s,
                    direct_participation_icp_e8s,
                },
            );
        }
        if !(allocated_neurons_fund_participation_icp_e8s
            <= intended_neurons_fund_participation_icp_e8s
            && intended_neurons_fund_participation_icp_e8s
                <= max_neurons_fund_swap_participation_icp_e8s
            && max_neurons_fund_swap_participation_icp_e8s
                <= take_max_initial_neurons_fund_participation_percentage(
                    total_maturity_equivalent_icp_e8s,
                ))
        {
            return Err(NeuronsFundParticipationValidationError::InvalidAllocation {
                allocated_neurons_fund_participation_icp_e8s,
                intended_neurons_fund_participation_icp_e8s,
                max_neurons_fund_swap_participation_icp_e8s,
                total_maturity_equivalent_icp_e8s,
            });
        }
        let neurons_fund_reserves_total_amount_icp_e8s = neurons_fund_reserves
            .total_amount_icp_e8s()
            .unwrap_or(u64::MAX);
        let tolerance_icp_e8s = (neurons_fund_reserves.num_neurons() as u64).saturating_add(1);
        if allocated_neurons_fund_participation_icp_e8s
            .abs_diff(neurons_fund_reserves_total_amount_icp_e8s)
            > tolerance_icp_e8s
        {
            return Err(
                NeuronsFundParticipationValidationError::InconsistentTotalAllocationData {
                    allocated_neurons_fund_participation_icp_e8s,
                    neurons_fund_reserves_total_amount_icp_e8s,
                },
            );
        }
        Ok(NeuronsFundParticipation {
            swap_participation_limits,
            ideal_matched_participation_function,
            neurons_fund_reserves,
            direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s,
        })
    }

    /// Returns a clone of `self` without sensitive data, specifically, `nns_neuron_id`.
    pub fn anonymized(&self) -> Self {
        let neurons_fund_reserves = self
            .neurons_fund_reserves
            .as_ref()
            .map(NeuronsFundSnapshotPb::anonymized);
        Self {
            neurons_fund_reserves,
            ..self.clone()
        }
    }
}

// -------------------------------------------------------------------------------------------------
// ------------------- NeuronsFundAction -----------------------------------------------------------
// -------------------------------------------------------------------------------------------------

pub enum NeuronsFundAction {
    DrawMaturity,
    RefundMaturity,
}

impl NeuronsFundAction {
    pub fn checked_apply(&self, left: u64, right: u64) -> Result<u64, String> {
        match self {
            Self::DrawMaturity => left.checked_sub(right).ok_or_else(|| "drawing".to_string()),
            Self::RefundMaturity => left
                .checked_add(right)
                .ok_or_else(|| "refunding".to_string()),
        }
    }
}

/// Apply the Neurons' Fund snapshot, i.e., either (depending on `action`) add or subtract maturity
/// to Neurons' Fund neurons stored in `neuron_store`.
///
/// Potential refund errors (e.g., u64 overflows) are collected, serialized, and returned as
/// the Err result. Note that the maturity of neurons for which thean error occured does not
/// need to be adjusted, as the function will retain their original maturity in case of errors.
fn apply_neurons_fund_snapshot(
    neuron_store: &mut NeuronStore,
    snapshot: &NeuronsFundSnapshot,
    action: NeuronsFundAction,
) -> Result<(), String> {
    let mut neurons_fund_action_error = vec![];
    for (neuron_id, neuron_delta) in snapshot.neurons().iter() {
        let refund_result = neuron_store.with_neuron_mut(neuron_id, |nns_neuron| {
            let old_nns_neuron_maturity_e8s = nns_neuron.maturity_e8s_equivalent;
            let maturity_delta_e8s = neuron_delta.amount_icp_e8s;
            nns_neuron.maturity_e8s_equivalent = action
                .checked_apply(old_nns_neuron_maturity_e8s, maturity_delta_e8s)
                .unwrap_or_else(|verb| {
                    neurons_fund_action_error.push(format!(
                        "u64 overflow while {verb} maturity from {neuron_id:?} \
                            (*kept* original maturity e8s = {old_nns_neuron_maturity_e8s}; \
                            requested maturity delta e8s = {maturity_delta_e8s})."
                    ));
                    old_nns_neuron_maturity_e8s
                });
        });
        if let Err(with_neuron_mut_error) = refund_result {
            neurons_fund_action_error.push(with_neuron_mut_error.to_string());
        }
    }
    if neurons_fund_action_error.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Errors while mutating the Neurons' Fund:\n  - {}",
            neurons_fund_action_error.join("\n  - ")
        ))
    }
}

pub mod neurons_fund_neuron {
    use ic_base_types::PrincipalId;
    use std::collections::HashSet;

    /// The number of hotkeys for each Neurons' Fund neuron must be limited due to SNS constraints,
    /// i.e., an SNS cannot represent arbitrarily-big sets of hotkeys using SNS neuron permissions.
    /// Concretely, this value should be less than or equal
    /// `MAX_NUMBER_OF_PRINCIPALS_PER_NEURON_FLOOR` - 2
    /// because two permissions will be used for the NNS Governance and the NNS neuron controller.
    pub const MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON: usize = 3;

    /// Returns up to `MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON` elements out of `hotkeys`.
    ///
    /// Priority is given to *self-authenticating* principals; if there are too few such principals,
    /// the function picks the remaining elements in the order in which they appear in the original
    /// vector.
    pub fn pick_most_important_hotkeys(hotkeys: &Vec<PrincipalId>) -> Vec<PrincipalId> {
        // Remove duplicates while preserving the order.
        let mut unique_hotkeys = vec![];
        let mut non_self_auth_hotkeys = vec![];
        let mut observed = HashSet::new();
        for hotkey in hotkeys {
            if !observed.contains(hotkey) {
                observed.insert(*hotkey);
                // Collect hotkeys that are self-authenticating; save non_self_auth_hotkeys for
                // later, in case there is still space for some of them.
                if hotkey.is_self_authenticating() {
                    unique_hotkeys.push(*hotkey);
                } else {
                    non_self_auth_hotkeys.push(*hotkey);
                }
            }
            // Limit how many hotkeys may be collected.
            if unique_hotkeys.len() == MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON {
                break;
            }
        }

        // If there is space in `unique_hotkeys`, fill it up using `non_self_auth_hotkeys`.
        while unique_hotkeys.len() < MAX_HOTKEYS_FROM_NEURONS_FUND_NEURON
            && !non_self_auth_hotkeys.is_empty()
        {
            let non_self_authenticating_hotkey = non_self_auth_hotkeys.remove(0);
            unique_hotkeys.push(non_self_authenticating_hotkey);
        }

        unique_hotkeys
    }
}

#[cfg(test)]
mod pick_most_important_hotkeys_tests {
    use super::neurons_fund_neuron::pick_most_important_hotkeys;
    use ic_types::PrincipalId;

    fn new_non_self_authenticating_principal_id(id: u64) -> PrincipalId {
        let res = PrincipalId::new_user_test_id(id);
        assert!(!res.is_self_authenticating());
        res
    }

    fn new_self_authenticating_principal_id(id: u64) -> PrincipalId {
        let res = PrincipalId::new_self_authenticating(&id.to_be_bytes());
        assert!(res.is_self_authenticating());
        res
    }

    #[test]
    fn trivial() {
        assert_eq!(pick_most_important_hotkeys(&vec![]), vec![]);
    }

    #[test]
    fn ordering_preserved_for_self_auth() {
        let hot_keys = vec![
            new_self_authenticating_principal_id(1),
            new_self_authenticating_principal_id(2),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_self_authenticating_principal_id(1),
                new_self_authenticating_principal_id(2),
            ],
        );
    }

    #[test]
    fn ordering_preserved_for_non_self_auth() {
        let hot_keys = vec![
            new_non_self_authenticating_principal_id(1),
            new_non_self_authenticating_principal_id(2),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_non_self_authenticating_principal_id(1),
                new_non_self_authenticating_principal_id(2),
            ],
        );
    }

    #[test]
    fn ordering_preserved_for_self_auth_followed_by_non_self_auth() {
        let hot_keys = vec![
            new_self_authenticating_principal_id(1),
            new_non_self_authenticating_principal_id(2),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_self_authenticating_principal_id(1),
                new_non_self_authenticating_principal_id(2),
            ],
        );
    }

    #[test]
    fn ordering_reversed_for_non_self_auth_followed_by_self_auth() {
        let hot_keys = vec![
            new_non_self_authenticating_principal_id(1),
            new_self_authenticating_principal_id(2),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_self_authenticating_principal_id(2),
                new_non_self_authenticating_principal_id(1),
            ],
        );
    }

    #[test]
    fn plenty_self_authenticating() {
        let hot_keys = vec![
            new_self_authenticating_principal_id(1),
            new_non_self_authenticating_principal_id(2),
            new_self_authenticating_principal_id(3),
            new_self_authenticating_principal_id(4),
            new_self_authenticating_principal_id(5),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_self_authenticating_principal_id(1),
                // #2 dropped as a non-self-authenticating principal.
                new_self_authenticating_principal_id(3),
                new_self_authenticating_principal_id(4),
                // #5 dropped as there are already sufficiently-many hotkeys.
            ],
        );
    }

    #[test]
    fn few_self_authenticating() {
        let hot_keys = vec![
            new_non_self_authenticating_principal_id(1),
            new_self_authenticating_principal_id(2),
            new_non_self_authenticating_principal_id(3),
            new_non_self_authenticating_principal_id(4),
        ];

        assert_eq!(
            pick_most_important_hotkeys(&hot_keys),
            vec![
                new_self_authenticating_principal_id(2),
                new_non_self_authenticating_principal_id(1),
                new_non_self_authenticating_principal_id(3),
            ],
        );
    }
}

#[cfg(test)]
mod test_functions_tests {
    use ic_nervous_system_common::E8;
    use ic_neurons_fund::{
        test_functions::{AnalyticallyInvertibleFunction, LinearFunction, SimpleLinearFunction},
        u64_to_dec, InvertError, InvertibleFunction, MatchedParticipationFunction,
        MatchingFunction, SerializableFunction, ValidatedNeuronsFundParticipationConstraints,
    };
    use ic_sns_swap::pb::v1::{
        IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionSwapPb,
        LinearScalingCoefficient, NeuronsFundParticipationConstraints,
    };
    use rust_decimal::Decimal;
    use rust_decimal_macros::dec;

    #[test]
    fn test_simple_linear_function() {
        let f = SimpleLinearFunction {};
        let run_test_for_a = |x_icp_e8s: u64| {
            let y_icp = f.apply(x_icp_e8s).unwrap();
            println!("({}, {})", x_icp_e8s, y_icp);
            let x1_icp_e8s = f.invert(y_icp).unwrap();
            assert_eq!(x_icp_e8s, x1_icp_e8s);
        };
        let run_test_for_b = |y_icp: Decimal| {
            let x1_icp_e8s = f.invert(y_icp).unwrap();
            println!("({}, {})", x1_icp_e8s, y_icp);
            let y1_icp = f.apply(x1_icp_e8s).unwrap();
            assert_eq!(y_icp, y1_icp);
        };
        run_test_for_a(0);
        run_test_for_a(77 * E8);
        run_test_for_a(888 * E8 + 123);
        run_test_for_a(9_999 * E8);

        run_test_for_b(dec!(0));
        run_test_for_b(dec!(77));
        run_test_for_b(dec!(888.000_001_23));
        run_test_for_b(dec!(9_999));
    }

    #[test]
    fn test_intervals() {
        let slope_denominator = 200_000;
        let max_neurons_fund_participation_icp_e8s = 95_000 * E8;
        let params = NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(50 * E8),
            max_neurons_fund_participation_icp_e8s: Some(max_neurons_fund_participation_icp_e8s),
            coefficient_intervals: vec![
                LinearScalingCoefficient {
                    // Interval A
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(100 * E8),
                    slope_numerator: Some(100_000),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(111),
                },
                LinearScalingCoefficient {
                    // Interval B
                    from_direct_participation_icp_e8s: Some(100 * E8),
                    to_direct_participation_icp_e8s: Some(1_000 * E8),
                    slope_numerator: Some(120_000),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(222),
                },
                LinearScalingCoefficient {
                    // Interval C
                    from_direct_participation_icp_e8s: Some(1_000 * E8),
                    to_direct_participation_icp_e8s: Some(10_000 * E8),
                    slope_numerator: Some(140_000),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(333),
                },
                LinearScalingCoefficient {
                    // Interval D
                    from_direct_participation_icp_e8s: Some(10_000 * E8),
                    to_direct_participation_icp_e8s: Some(100_000 * E8),
                    slope_numerator: Some(160_000),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(444),
                },
                LinearScalingCoefficient {
                    // Interval E
                    from_direct_participation_icp_e8s: Some(100_000 * E8),
                    to_direct_participation_icp_e8s: Some(1_000_000 * E8),
                    slope_numerator: Some(180_000),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(555),
                },
            ],
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunctionSwapPb {
                serialized_representation: Some((SimpleLinearFunction {}).serialize()),
            }),
        };
        let participation =
            ValidatedNeuronsFundParticipationConstraints::<SimpleLinearFunction>::try_from(&params)
                .unwrap();

        // Below min_direct_participation_threshold_icp_e8s, but falls into Interval A.
        // Thus, we expect slope(0.5) * x + intercept_icp_e8s(111)
        assert_eq!(participation.apply(0), Ok(111));
        // Falls into Interval A, thus we expect slope(0.5) * x + intercept_icp_e8s(111)
        assert_eq!(participation.apply(90 * E8), Ok(45 * E8 + 111));
        // Falls into Interval B, thus we expect slope(0.6) * x + intercept_icp_e8s(222)
        assert_eq!(participation.apply(100 * E8), Ok(60 * E8 + 222));
        // Falls into Interval C, thus we expect slope(0.7) * x + intercept_icp_e8s(333)
        assert_eq!(participation.apply(5_000 * E8), Ok(3_500 * E8 + 333));
        // Falls into Interval D, thus we expect slope(0.8) * x + intercept_icp_e8s(444)
        assert_eq!(
            participation.apply(100_000 * E8 - 1),
            Ok(80_000 * E8 - 1 + 444)
        );
        // Falls into Interval E, thus we expect slope(0.9) * x + intercept_icp_e8s(555)
        assert_eq!(participation.apply(100_000 * E8), Ok(90_000 * E8 + 555),);
        // Beyond the last interval
        assert_eq!(
            participation.apply(1_000_000 * E8),
            Ok(max_neurons_fund_participation_icp_e8s),
        );
        // Extremely high value
        assert_eq!(
            participation.apply(u64::MAX),
            Ok(max_neurons_fund_participation_icp_e8s),
        );
    }

    const POTENTIALLY_INTERESTING_TARGET_Y_VALUES: &[&std::ops::RangeInclusive<u64>] = &[
        // The first 101 values of the the u64 range.
        &(0..=100_u64),
        // The last 101 values of the first one-third of the u64 range.
        &(6_148_914_691_236_516_764..=6_148_914_691_236_516_864),
        // The last 101 values of the u64 range.
        &(18_446_744_073_709_551_515..=u64::MAX),
    ];

    fn generate_potentially_intresting_target_values() -> Vec<u64> {
        POTENTIALLY_INTERESTING_TARGET_Y_VALUES
            .iter()
            .flat_map(|rs| {
                let rs = (*rs).clone();
                rs.collect::<Vec<u64>>()
            })
            .collect()
    }

    fn run_inverse_function_test<F>(function: &F, target_y: Decimal)
    where
        F: InvertibleFunction + AnalyticallyInvertibleFunction,
    {
        let Ok(expected) = function.invert_analytically(target_y) else {
            return;
        };
        let observed = function.invert(target_y).unwrap();
        // Sometimes exact equality cannot be reached with our search strategy. We tolerate errors
        // up to 1 E8.
        assert!(
            observed.max(expected) - observed.min(expected) <= 1,
            "Deviation bigger than 1 E8.\n\
            Expected: {expected}\n\
            Observed: {observed}"
        );
    }

    #[test]
    fn test_inverse_corner_cases_with_basic_linear_function() {
        let f = SimpleLinearFunction {};
        for i in generate_potentially_intresting_target_values() {
            run_inverse_function_test(&f, u64_to_dec(i).unwrap());
        }
    }

    #[test]
    fn test_inverse_corner_cases_with_slow_linear_function() {
        let slopes = vec![
            dec!(0.0001),
            dec!(0.0003),
            dec!(0.0005),
            dec!(0.001),
            dec!(0.003),
            dec!(0.005),
            dec!(0.01),
            dec!(0.03),
            dec!(0.05),
            dec!(0.1),
            dec!(0.3),
            dec!(0.5),
            dec!(1.0),
            dec!(3.0),
            dec!(5.0),
            dec!(10.0),
        ];
        let intercepts = vec![
            dec!(0.0),
            dec!(-0.0001),
            dec!(-0.0003),
            dec!(-0.0005),
            dec!(-0.001),
            dec!(-0.003),
            dec!(-0.005),
            dec!(-0.01),
            dec!(-0.03),
            dec!(-0.05),
            dec!(-0.1),
            dec!(-0.3),
            dec!(-0.5),
            dec!(-1.0),
            dec!(-3.0),
            dec!(-5.0),
            dec!(-10.0),
            dec!(-30.0),
            dec!(-50.0),
            dec!(-100.0),
            dec!(-300.0),
            dec!(-500.0),
            dec!(-1000.0),
            dec!(-3000.0),
            dec!(-5000.0),
            dec!(-10000.0),
            dec!(-30000.0),
            dec!(-50000.0),
        ];
        for intercept in intercepts {
            for slope in slopes.iter().cloned() {
                let f = LinearFunction { slope, intercept };
                for i in generate_potentially_intresting_target_values() {
                    let target_y = u64_to_dec(i).unwrap();
                    // println!("Inverting linear function {target_y} = f(x) = {slope} * x + {intercept} ...");
                    run_inverse_function_test(&f, target_y);
                }
            }
        }
    }

    #[test]
    fn test_inverse_corner_cases_with_result_exactly_max() {
        let function = LinearFunction {
            slope: dec!(1),
            intercept: dec!(0),
        };
        let target_y = u64_to_dec(u64::MAX).unwrap();
        let observed = function.invert(target_y).unwrap();
        assert_eq!(observed, u64::MAX);
    }

    #[test]
    fn test_inverse_corner_cases_with_result_above_max() {
        let function = LinearFunction {
            slope: dec!(1),
            intercept: dec!(-1),
        };
        let target_y = u64_to_dec(u64::MAX).unwrap();
        let error = function.invert(target_y).unwrap_err();
        assert_eq!(
            error,
            InvertError::InvertValueAboveU64Range {
                target_y,
                lower: u64::MAX
            }
        );
    }

    #[test]
    fn test_inverse_corner_cases_with_result_exactly_zero() {
        let function = LinearFunction {
            slope: dec!(1),
            intercept: dec!(0),
        };
        let target_y = dec!(0);
        let observed = function.invert(target_y).unwrap();
        assert_eq!(observed, 0);
    }

    #[test]
    fn test_inverse_corner_cases_with_result_below_zero() {
        let function = LinearFunction {
            slope: dec!(1),
            intercept: dec!(1),
        };
        let target_y = dec!(0);
        let error = function.invert(target_y).unwrap_err();
        assert_eq!(
            error,
            InvertError::InvertValueBelowU64Range { target_y, upper: 0 }
        );
    }
}

#[cfg(test)]
mod neurons_fund_participation_tests;

#[cfg(test)]
mod polynomial_neurons_fund_participation_tests;

#[cfg(test)]
mod neurons_fund_anonymization_tests;

#[cfg(test)]
mod neurons_fund_participation_constraints_tests;
