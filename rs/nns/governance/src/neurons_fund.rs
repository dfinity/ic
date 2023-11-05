//! Implementation of NNS Governance-specific functions for Matched Funding.

use ic_base_types::PrincipalId;
use ic_nervous_system_governance::maturity_modulation::BASIS_POINTS_PER_UNITY;
use ic_neurons_fund::{
    dec_to_u64, u64_to_dec, DeserializableFunction, IdealMatchingFunction,
    PolynomialMatchingFunction, ValidatedLinearScalingCoefficient,
    MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_sns_swap::pb::v1::{
    IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionSwapPb,
    LinearScalingCoefficient, NeuronsFundParticipationConstraints,
};
use rust_decimal::Decimal;
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
        NeuronsFundParticipation as NeuronsFundParticipationPb,
        NeuronsFundSnapshot as NeuronsFundSnapshotPb,
        SwapParticipationLimits as SwapParticipationLimitsPb,
    },
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
// ------------------- NeuronsFundNeuronPortion ----------------------------------------------------
// -------------------------------------------------------------------------------------------------

/// This structure represents an arbitrary portion of a Neurons' Fund neuron, be that the whole
/// neuron (in which case `amount_icp_e8s` equals `maturity_equivalent_icp_e8s`) or a portion
/// thereof that may either participate in an SNS swap or be refunded.
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq)]
pub enum NeuronsFundNeuronPortionError {
    UnspecifiedField(String),
    AmountTooBig {
        amount_icp_e8s: u64,
        maturity_equivalent_icp_e8s: u64,
    },
}

impl ToString for NeuronsFundNeuronPortionError {
    fn to_string(&self) -> String {
        let prefix = "Invalid NeuronsFundNeuronPortion: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                format!("{}field `{}` is not specified.", prefix, field_name)
            }
            Self::AmountTooBig {
                amount_icp_e8s,
                maturity_equivalent_icp_e8s,
            } => {
                format!(
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
        let controller = self.hotkey_principal.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("hotkey_principal".to_string())
        })?;
        let is_capped = self.is_capped.ok_or_else(|| {
            NeuronsFundNeuronPortionError::UnspecifiedField("is_capped".to_string())
        })?;
        Ok(NeuronsFundNeuronPortion {
            id,
            amount_icp_e8s,
            maturity_equivalent_icp_e8s,
            controller,
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

#[derive(Clone, Debug, PartialEq)]
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

    pub fn total_amount_icp_e8s(&self) -> u64 {
        self.neurons
            .values()
            .fold(0_u64, |a, n| a.saturating_add(n.amount_icp_e8s))
    }

    pub fn into_vec(self) -> Vec<NeuronsFundNeuronPortion> {
        self.neurons.into_values().collect()
    }

    /// Implements the `self - other` semantics for calculating Neurons' Fund refunds.
    ///
    /// Example:
    /// self = { (N1, maturity=100), (N2, maturity=200), (N3, maturity=300) }
    /// other = { (N1, maturity=60), (N3, maturity=300) }
    /// result = Ok({ (N1, maturity=40), (N2, maturity=200), (N2, maturity=200) })
    pub fn diff(&self, other: &Self) -> Result<Self, String> {
        let mut deductible_neurons = other.neurons().clone();
        let neurons = self
            .neurons
            .iter()
            .map(|(id, left)| {
                let err_prefix =
                    || format!("Cannot compute diff of two portions of neuron {:?}: ", id);
                let controller = left.controller;
                let (amount_icp_e8s, maturity_equivalent_icp_e8s, is_capped) = if let Some(right) = deductible_neurons.remove(id)
                {
                    if right.amount_icp_e8s > left.amount_icp_e8s {
                        return Err(format!(
                            "{}left.amount_icp_e8s={:?}, right.amount_icp_e8s={:?}.",
                            err_prefix(),
                            left.amount_icp_e8s,
                            right.amount_icp_e8s,
                        ));
                    }
                    if right.maturity_equivalent_icp_e8s != left.maturity_equivalent_icp_e8s {
                        return Err(format!(
                            "{}left.maturity_equivalent_icp_e8s={:?} != right.maturity_equivalent_icp_e8s={:?}.",
                            err_prefix(),
                            left.maturity_equivalent_icp_e8s,
                            right.maturity_equivalent_icp_e8s,
                        ));
                    }
                    if right.controller != controller {
                        return Err(format!(
                            "{}left.controller={:?}, right.controller={:?}.",
                            err_prefix(),
                            controller,
                            right.controller,
                        ));
                    }
                    if right.is_capped && !left.is_capped {
                        return Err(format!(
                            "{}left.is_capped=false, right.is_capped=true.",
                            err_prefix()
                        ));
                    }
                    // Taking right.is_capped, as that corresponds to the capping of the effectively
                    // taken portion of the neuron (left.is_capped is whether the originally
                    // reserved portion has been capped).
                    (left.amount_icp_e8s - right.amount_icp_e8s, left.maturity_equivalent_icp_e8s, right.is_capped)
                } else {
                    (left.amount_icp_e8s, left.maturity_equivalent_icp_e8s, left.is_capped)
                };
                Ok((
                    *id,
                    NeuronsFundNeuronPortion {
                        id: *id,
                        controller,
                        amount_icp_e8s,
                        maturity_equivalent_icp_e8s,
                        is_capped,
                    },
                ))
            })
            .collect::<Result<BTreeMap<NeuronId, NeuronsFundNeuronPortion>, _>>()?;
        if !deductible_neurons.is_empty() {
            let extra_neuron_portions_str = deductible_neurons
                .keys()
                .map(|n| n.id.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            return Err(format!(
                "Cannot compute diff of two NeuronsFundSnapshot instances: right-hand side \
                contains {} extra neuron portions: {}",
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

#[derive(Debug, PartialEq)]
pub enum NeuronsFundSnapshotValidationError {
    NeuronsFundNeuronPortionError(usize, NeuronsFundNeuronPortionError),
}

impl ToString for NeuronsFundSnapshotValidationError {
    fn to_string(&self) -> String {
        let prefix = "Cannot validate NeuronsFundSnapshot: ";
        match self {
            Self::NeuronsFundNeuronPortionError(index, error) => {
                format!(
                    "{}neurons_fund_neuron_portions[{}]: {}",
                    prefix,
                    index,
                    error.to_string()
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
        Ok(NeuronsFundSnapshot::new(neurons_fund.into_iter()))
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
#[derive(Clone, Debug)]
pub struct SwapParticipationLimits {
    pub min_direct_participation_icp_e8s: u64,
    pub max_direct_participation_icp_e8s: u64,
    pub min_participant_icp_e8s: u64,
    pub max_participant_icp_e8s: u64,
}

#[derive(Debug)]
pub enum SwapParametersError {
    /// We expect this to never occur, and can ensure this, since the caller is Swap, and we control
    /// the code that the Swap canisters run.
    UnspecifiedField(String),
}

impl ToString for SwapParametersError {
    fn to_string(&self) -> String {
        let prefix = "Cannot extract data from SwapParameters: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                format!("{}field `{}` is not specified.", prefix, field_name,)
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
        Ok(Self {
            min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s,
            min_participant_icp_e8s,
            max_participant_icp_e8s,
        })
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
    /// of the three is the smallest value:
    /// * `ideal_matched_participation_function.apply(swap_participation_limits. )`,
    /// * `MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S`,
    /// * 10% of the total Neurons' Fund maturity ICP equivalent.
    ///
    /// Warning: This value does not take into account limiting the participation of individual
    /// Neurons' Fund neurons, i.e., capping and dropping. To compute the precise Neurons' Fund
    /// participation amount, use `neurons_fund_reserves.total_amount_icp_e8s()`.
    max_neurons_fund_swap_participation_icp_e8s: u64,
    /// How much the Neurons' Fund would ideally like to participate with in this SNS swap,
    /// given the direct participation amount (`direct_participation_icp_e8s`) and matching function
    /// (`ideal_matched_participation_function`).
    ///
    /// Warning: This value does not take into account limiting the participation of individual
    /// Neurons' Fund neurons, i.e., capping and dropping. To compute the precise Neurons' Fund
    /// participation amount, use `neurons_fund_reserves.total_amount_icp_e8s()`.
    intended_neurons_fund_participation_icp_e8s: u64,
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
        self.neurons_fund_reserves.total_amount_icp_e8s()
    }

    pub fn num_neurons(&self) -> usize {
        self.neurons_fund_reserves.num_neurons()
    }

    fn count_neurons_fund_total_maturity_equivalent_icp_e8s(
        neurons_fund: &[NeuronsFundNeuron],
    ) -> u64 {
        neurons_fund
            .iter()
            .map(|neuron| neuron.maturity_equivalent_icp_e8s)
            .fold(0_u64, |a, n| a.saturating_add(n))
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
            Self::count_neurons_fund_total_maturity_equivalent_icp_e8s(&neurons_fund);
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
    /// `ideal_matched_participation_function`.  All other parameters are taken from `self`.
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
                     ..
                 }| {
                    NeuronsFundNeuron {
                        id: *id,
                        maturity_equivalent_icp_e8s: *maturity_equivalent_icp_e8s,
                        controller: *controller,
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
        // Apply hard cap.
        let max_neurons_fund_swap_participation_icp_e8s = u64::min(
            max_neurons_fund_swap_participation_icp_e8s,
            MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
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
        let neurons_fund_reserves = if total_maturity_equivalent_icp_e8s == 0 {
            println!(
                "{}WARNING: Neurons' Fund has zero total maturity.",
                governance::LOG_PREFIX
            );
            NeuronsFundSnapshot::empty()
        } else if intended_neurons_fund_participation_icp_e8s == 0 {
            println!(
                "{}WARNING: intended_neurons_fund_participation_icp_e8s is zero, matching \
                direct_participation_icp_e8s = {}. total_maturity_equivalent_icp_e8s = {}. \
                ideal_matched_participation_function = {:?}\n \
                Plot: \n{:?}",
                governance::LOG_PREFIX,
                direct_participation_icp_e8s,
                total_maturity_equivalent_icp_e8s,
                ideal_matched_participation_function,
                ideal_matched_participation_function
                    .plot(NonZeroU64::try_from(50).unwrap())
                    .map(|plot| format!("{:?}", plot))
                    .unwrap_or_else(|e| e),
            );
            NeuronsFundSnapshot::empty()
        } else {
            // Unlike in other places, here we keep the ICP value in e8s (even after converting to
            // Decimal). This mitigates rounding errors and is safe because the only operation we
            // perform over this value is multiplication over a weight between 0 and 1, so there cannot
            // be a multiplication overflow.
            let intended_neurons_fund_participation_icp_e8s =
                u64_to_dec(intended_neurons_fund_participation_icp_e8s);
            NeuronsFundSnapshot::new(neurons_fund.into_iter().filter_map(
                |NeuronsFundNeuron {
                     id,
                     maturity_equivalent_icp_e8s,
                     controller,
                 }| {
                    let proportion_to_overall_neurons_fund: Decimal = u64_to_dec(maturity_equivalent_icp_e8s)
                        / u64_to_dec(total_maturity_equivalent_icp_e8s);
                    let ideal_participation_amount_icp_e8s: u64 =
                        match dec_to_u64(proportion_to_overall_neurons_fund * intended_neurons_fund_participation_icp_e8s) {
                            Ok(ideal_participation_amount_icp_e8s) => {
                                ideal_participation_amount_icp_e8s
                            }
                            Err(err) => {
                                // This cannot practically happen as `dec_to_u64` returns an error
                                // only in two cases: (1) the argument is negative (we've multiplied
                                // two non-negative numbers, `proportion_to_overall_neurons_fund`
                                // and `intended_neurons_fund_participation_icp_e8s`) and (2) there
                                // is a u64 overflow (`intended_neurons_fund_participation_icp_e8s`
                                // is bounded by `u64::MAX` and `proportion_to_overall_neurons_fund`
                                // is a value between 0.0 and 1.0). If these assumptions are somehow
                                // still violated, we log this situation to aid debugging.
                                println!(
                                    "{}ERROR: Cannot compute ideal participation amount for \
                                    Neurons' Fund neuron {:?}: {}",
                                    governance::LOG_PREFIX, id, err,
                                );
                                return None;
                            }
                        };
                    if ideal_participation_amount_icp_e8s < swap_participation_limits.min_participant_icp_e8s {
                        // Do not include neurons that cannot participate under any circumstances.
                        println!(
                            "{}INFO: discarding neuron {:?} ({} ICP e8s maturity equivalent) as it \
                            cannot participate in the swap with its proportional participation \
                            amount ({}) that is less than `min_participant_icp_e8s` ({}).",
                            governance::LOG_PREFIX, id, maturity_equivalent_icp_e8s,
                            ideal_participation_amount_icp_e8s,
                            swap_participation_limits.min_participant_icp_e8s,
                        );
                        None
                    } else {
                        let (amount_icp_e8s, is_capped) = if ideal_participation_amount_icp_e8s > swap_participation_limits.max_participant_icp_e8s {
                            println!(
                                "{}INFO: capping neuron {:?} ({} ICP e8s maturity equivalent) as it \
                                cannot participate in the swap with all of its proportional \
                                participation amount ({}) that exceeds `max_participant_icp_e8s` ({}).",
                                governance::LOG_PREFIX, id, maturity_equivalent_icp_e8s,
                                ideal_participation_amount_icp_e8s,
                                swap_participation_limits.max_participant_icp_e8s,
                            );
                            (swap_participation_limits.max_participant_icp_e8s, true)
                        } else {
                            (ideal_participation_amount_icp_e8s, false)
                        };
                        Some(NeuronsFundNeuronPortion {
                            id,
                            amount_icp_e8s,
                            maturity_equivalent_icp_e8s,
                            controller,
                            is_capped,
                        })
                    }
                },
            ))
        };
        Ok(Self {
            swap_participation_limits,
            ideal_matched_participation_function,
            neurons_fund_reserves,
            direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s,
        })
    }

    /// TODO[NNS1-2591]: Implement the rest of this function. Currently, it returns a mock structure
    /// that will pass validiation but does not reflect the real Neurons' Fund participation.
    /// After this TODO is addressed, the tests in rs/nns/governance/tests/governance.rs would need
    /// to be adjusted.
    pub fn compute_constraints(&self) -> Result<NeuronsFundParticipationConstraints, String> {
        let min_direct_participation_threshold_icp_e8s = Some(
            self.swap_participation_limits
                .min_direct_participation_icp_e8s,
        );
        let max_neurons_fund_participation_icp_e8s =
            Some(self.max_neurons_fund_swap_participation_icp_e8s);
        let dummy_interval = ValidatedLinearScalingCoefficient {
            from_direct_participation_icp_e8s: 0,
            to_direct_participation_icp_e8s: u64::MAX,
            slope_numerator: 1,
            slope_denominator: 1,
            intercept_icp_e8s: 0,
        };
        let dummy_interval: LinearScalingCoefficient = dummy_interval.into();
        let coefficient_intervals = vec![dummy_interval];
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
}

pub type PolynomialNeuronsFundParticipation = NeuronsFundParticipation<PolynomialMatchingFunction>;

impl PolynomialNeuronsFundParticipation {
    /// Create a new Neurons' Fund participation for the given `swap_participation_limits`.
    pub fn new(
        swap_participation_limits: SwapParticipationLimits,
        neurons_fund: Vec<NeuronsFundNeuron>,
    ) -> Result<Self, String> {
        let total_maturity_equivalent_icp_e8s =
            Self::count_neurons_fund_total_maturity_equivalent_icp_e8s(&neurons_fund);
        let ideal_matched_participation_function =
            Box::from(PolynomialMatchingFunction::new(total_maturity_equivalent_icp_e8s).unwrap());
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
                     ..
                 }| {
                    NeuronsFundNeuron {
                        id: *id,
                        maturity_equivalent_icp_e8s: *maturity_equivalent_icp_e8s,
                        controller: *controller,
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

#[derive(Debug, PartialEq)]
pub enum NeuronsFundParticipationValidationError {
    UnspecifiedField(String),
    NeuronsFundSnapshotValidationError(NeuronsFundSnapshotValidationError),
    MatchFunctionDeserializationFailed(String),
    NeuronsFundParticipationCreationFailed(String),
}

impl ToString for NeuronsFundParticipationValidationError {
    fn to_string(&self) -> String {
        let prefix = "Cannot validate NeuronsFundParticipation: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                format!("{}field `{}` is not specified.", prefix, field_name)
            }
            Self::NeuronsFundSnapshotValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
            Self::MatchFunctionDeserializationFailed(error) => {
                format!(
                    "{}failed to deserialize an IdealMatchingFunction instance: {}",
                    prefix, error
                )
            }
            Self::NeuronsFundParticipationCreationFailed(error) => {
                format!(
                    "{}failed to create NeuronsFundParticipation: {}",
                    prefix, error
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
        let neurons_fund_neuron_portions: Vec<NeuronsFundNeuronPortionPb> = participation
            .into_snapshot()
            .neurons()
            .values()
            .map(|neuron| NeuronsFundNeuronPortionPb {
                nns_neuron_id: Some(neuron.id),
                amount_icp_e8s: Some(neuron.amount_icp_e8s),
                maturity_equivalent_icp_e8s: Some(neuron.maturity_equivalent_icp_e8s),
                hotkey_principal: Some(neuron.controller),
                is_capped: Some(neuron.is_capped),
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
        Ok(NeuronsFundParticipation {
            swap_participation_limits,
            ideal_matched_participation_function,
            neurons_fund_reserves,
            direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s,
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

#[cfg(test)]
mod test_functions_tests {
    use ic_nervous_system_common::E8;
    use ic_neurons_fund::{
        test_functions::{AnalyticallyInvertibleFunction, LinearFunction, SimpleLinearFunction},
        u64_to_dec, InvertibleFunction, MatchedParticipationFunction, NonDecreasingFunction,
        SerializableFunction, ValidatedNeuronsFundParticipationConstraints,
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
            let y_icp = f.apply_unchecked(x_icp_e8s);
            println!("({}, {})", x_icp_e8s, y_icp);
            let x1_icp_e8s = f.invert(y_icp).unwrap();
            assert_eq!(x_icp_e8s, x1_icp_e8s);
        };
        let run_test_for_b = |y_icp: Decimal| {
            let x1_icp_e8s = f.invert(y_icp).unwrap();
            println!("({}, {})", x1_icp_e8s, y_icp);
            let y1_icp = f.apply_unchecked(x1_icp_e8s);
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

        // Below min_direct_participation_threshold_icp_e8s
        assert_eq!(participation.apply_unchecked(0), 0);
        // Falls into Interval A, thus we expect slope(0.5) * x + intercept_icp_e8s(111)
        assert_eq!(participation.apply_unchecked(90 * E8), 45 * E8 + 111);
        // Falls into Interval B, thus we expect slope(0.6) * x + intercept_icp_e8s(222)
        assert_eq!(participation.apply_unchecked(100 * E8), 60 * E8 + 222);
        // Falls into Interval C, thus we expect slope(0.7) * x + intercept_icp_e8s(333)
        assert_eq!(participation.apply_unchecked(5_000 * E8), 3_500 * E8 + 333);
        // Falls into Interval D, thus we expect slope(0.8) * x + intercept_icp_e8s(444)
        assert_eq!(
            participation.apply_unchecked(100_000 * E8 - 1),
            80_000 * E8 - 1 + 444
        );
        // Falls into Interval E, thus we expect slope(0.9) * x + intercept_icp_e8s(555)
        assert_eq!(
            participation.apply_unchecked(100_000 * E8),
            90_000 * E8 + 555
        );
        // Beyond the last interval
        assert_eq!(
            participation.apply_unchecked(1_000_000 * E8),
            max_neurons_fund_participation_icp_e8s
        );
        // Extremely high value
        assert_eq!(
            participation.apply_unchecked(u64::MAX),
            max_neurons_fund_participation_icp_e8s
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
            println!(
                "Cannot run inverse test as a u64 analytical inverse does not exist for {}.",
                target_y,
            );
            return;
        };
        let observed = function.invert(target_y).unwrap();
        println!("{}, target_y = {target_y}", std::any::type_name::<F>(),);

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
            run_inverse_function_test(&f, u64_to_dec(i));
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
                    let target_y = u64_to_dec(i);
                    println!("Inverting linear function {target_y} = f(x) = {slope} * x + {intercept} ...");
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
        let target_y = u64_to_dec(u64::MAX);
        let observed = function.invert(target_y).unwrap();
        assert_eq!(observed, u64::MAX);
    }

    #[test]
    fn test_inverse_corner_cases_with_result_above_max() {
        let function = LinearFunction {
            slope: dec!(1),
            intercept: dec!(-1),
        };
        let target_y = u64_to_dec(u64::MAX);
        let error = function.invert(target_y).unwrap_err();
        assert_eq!(
            error,
            format!(
                "inverse of function appears to be greater than {}",
                u64::MAX
            )
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
        assert_eq!(error, "inverse of function appears to be lower than 0");
    }
}

#[cfg(test)]
mod neurons_fund_anonymization_tests {

    use crate::neurons_fund::*;
    use crate::pb::v1::{
        neurons_fund_snapshot::NeuronsFundNeuronPortion as NeuronsFundNeuronPortionPb,
        IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionPb,
        NeuronsFundParticipation as NeuronsFundParticipationPb,
        NeuronsFundSnapshot as NeuronsFundSnapshotPb,
        SwapParticipationLimits as SwapParticipationLimitsPb,
    };
    use ic_base_types::PrincipalId;
    use ic_neurons_fund::{PolynomialMatchingFunction, SerializableFunction};
    use ic_nns_common::pb::v1::NeuronId;

    #[test]
    fn test_neurons_fund_participation_anonymization() {
        let id1 = NeuronId { id: 123 };
        let id2 = NeuronId { id: 456 };
        let amount_icp_e8s = 100_000_000_000;
        let maturity_equivalent_icp_e8s = 100_000_000_000;
        let controller = PrincipalId::default();
        let is_capped = false;
        let n1: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
            nns_neuron_id: Some(id1),
            amount_icp_e8s: Some(amount_icp_e8s),
            maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
            hotkey_principal: Some(controller),
            is_capped: Some(is_capped),
        };
        let n2 = NeuronsFundNeuronPortionPb {
            nns_neuron_id: Some(id2),
            ..n1
        };
        let neurons = vec![n1, n2];
        let snapshot = NeuronsFundSnapshotPb {
            neurons_fund_neuron_portions: neurons,
        };
        let participation = NeuronsFundParticipationPb {
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunctionPb {
                serialized_representation: Some(
                    PolynomialMatchingFunction::new(1_000_000_000_000_000)
                        .unwrap()
                        .serialize(),
                ),
            }),
            neurons_fund_reserves: Some(snapshot.clone()),
            swap_participation_limits: Some(SwapParticipationLimitsPb {
                min_direct_participation_icp_e8s: Some(0),
                max_direct_participation_icp_e8s: Some(u64::MAX),
                min_participant_icp_e8s: Some(1_000_000_000),
                max_participant_icp_e8s: Some(10_000_000_000),
            }),
            direct_participation_icp_e8s: Some(1_000_000_000_000),
            total_maturity_equivalent_icp_e8s: Some(1_000_000_000_000_000),
            max_neurons_fund_swap_participation_icp_e8s: Some(1_000_000_000_000),
            intended_neurons_fund_participation_icp_e8s: Some(1_000_000_000_000),
        };
        let participation_validation_result = participation.validate();
        assert!(
            participation_validation_result.is_ok(),
            "expected Ok result, got {:#?}",
            participation_validation_result
        );
        let anonymized_participation = participation.anonymized();
        assert_eq!(
            anonymized_participation.validate().map(|_| ()),
            Err(
                NeuronsFundParticipationValidationError::NeuronsFundSnapshotValidationError(
                    NeuronsFundSnapshotValidationError::NeuronsFundNeuronPortionError(
                        0,
                        NeuronsFundNeuronPortionError::UnspecifiedField(
                            "nns_neuron_id".to_string()
                        )
                    )
                )
            )
        );
        assert_eq!(
            anonymized_participation,
            NeuronsFundParticipationPb {
                neurons_fund_reserves: Some(snapshot.anonymized()),
                ..participation
            }
        );
    }

    #[test]
    fn test_neurons_fund_snapshot_anonymization() {
        let id1 = NeuronId { id: 123 };
        let id2 = NeuronId { id: 456 };
        let amount_icp_e8s = 100_000_000_000;
        let maturity_equivalent_icp_e8s = 100_000_000_000;
        let controller = PrincipalId::default();
        let is_capped = false;
        let n1: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
            nns_neuron_id: Some(id1),
            amount_icp_e8s: Some(amount_icp_e8s),
            maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
            hotkey_principal: Some(controller),
            is_capped: Some(is_capped),
        };
        let n2 = NeuronsFundNeuronPortionPb {
            nns_neuron_id: Some(id2),
            ..n1
        };
        let neurons = vec![n1, n2];
        let snapshot = NeuronsFundSnapshotPb {
            neurons_fund_neuron_portions: neurons.clone(),
        };
        assert_eq!(
            snapshot.validate(),
            Ok(NeuronsFundSnapshot {
                neurons: neurons
                    .iter()
                    .map(|n| { (n.nns_neuron_id.unwrap(), n.validate().unwrap()) })
                    .collect()
            })
        );
        let anonymized_snapshot = snapshot.anonymized();
        assert_eq!(
            anonymized_snapshot.validate(),
            Err(
                NeuronsFundSnapshotValidationError::NeuronsFundNeuronPortionError(
                    0,
                    NeuronsFundNeuronPortionError::UnspecifiedField("nns_neuron_id".to_string())
                )
            )
        );
        assert_eq!(
            anonymized_snapshot,
            NeuronsFundSnapshotPb {
                neurons_fund_neuron_portions: neurons
                    .into_iter()
                    .map(|n| { n.anonymized() })
                    .collect()
            }
        );
    }

    #[test]
    fn test_neurons_fund_neuron_portion_anonymization() {
        let id = NeuronId { id: 123 };
        let amount_icp_e8s = 100_000_000_000;
        let maturity_equivalent_icp_e8s = 100_000_000_000;
        let controller = PrincipalId::default();
        let is_capped = false;
        let neuron: NeuronsFundNeuronPortionPb = NeuronsFundNeuronPortionPb {
            nns_neuron_id: Some(id),
            amount_icp_e8s: Some(amount_icp_e8s),
            maturity_equivalent_icp_e8s: Some(maturity_equivalent_icp_e8s),
            hotkey_principal: Some(controller),
            is_capped: Some(is_capped),
        };
        assert_eq!(
            neuron.validate(),
            Ok(NeuronsFundNeuronPortion {
                id,
                amount_icp_e8s,
                maturity_equivalent_icp_e8s,
                controller,
                is_capped,
            })
        );
        let anonymized_neuron = neuron.anonymized();
        assert_eq!(
            anonymized_neuron.validate(),
            Err(NeuronsFundNeuronPortionError::UnspecifiedField(
                "nns_neuron_id".to_string()
            ))
        );
        assert_eq!(
            anonymized_neuron,
            NeuronsFundNeuronPortionPb {
                nns_neuron_id: None,
                ..neuron
            }
        );
    }
}
