//! Implementation of SNS Swap-specific functions for Matched Funding.

use crate::pb::v1::{
    IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionSwapPb,
    LinearScalingCoefficient as LinearScalingCoefficientPb,
    NeuronsFundParticipationConstraints as NeuronsFundParticipationConstraintsPb,
};
use ic_neurons_fund::{
    DeserializableFunction, IdealMatchingFunction, ValidatedLinearScalingCoefficient,
    ValidatedNeuronsFundParticipationConstraints, MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN,
    MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES,
};

#[derive(Debug)]
pub enum LinearScalingCoefficientValidationError {
    // All fields are mandatory.
    UnspecifiedField(String),
    EmptyInterval {
        from_direct_participation_icp_e8s: u64,
        to_direct_participation_icp_e8s: u64,
    },
    DenominatorIsZero,
    // The slope should be between 0.0 and 1.0.
    NumeratorGreaterThanDenominator {
        slope_numerator: u64,
        slope_denominator: u64,
    },
}

impl ToString for LinearScalingCoefficientValidationError {
    fn to_string(&self) -> String {
        let prefix = "LinearScalingCoefficientValidationError: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                format!("{prefix}Field `{}` must be specified.", field_name)
            }
            Self::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            } => {
                format!(
                    "{prefix}from_direct_participation_icp_e8s ({}) must be strictly less that \
                    to_direct_participation_icp_e8s ({})).",
                    from_direct_participation_icp_e8s, to_direct_participation_icp_e8s,
                )
            }
            Self::DenominatorIsZero => {
                format!("{prefix}slope_denominator must not equal zero.")
            }
            Self::NumeratorGreaterThanDenominator {
                slope_numerator,
                slope_denominator,
            } => {
                format!(
                    "{prefix}slope_numerator ({}) must be less than or equal \
                    slope_denominator ({})",
                    slope_numerator, slope_denominator,
                )
            }
        }
    }
}

impl LinearScalingCoefficientPb {
    pub fn validate(&self) -> Result<(), LinearScalingCoefficientValidationError> {
        let from_direct_participation_icp_e8s =
            self.from_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "from_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let to_direct_participation_icp_e8s =
            self.to_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "to_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let slope_numerator = self.slope_numerator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField("slope_numerator".to_string())
        })?;
        let slope_denominator = self.slope_denominator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "slope_denominator".to_string(),
            )
        })?;
        // Currently we only check that `intercept_icp_e8s` is specified, so the actual field value
        // is unused.
        let _intercept_icp_e8s = self.intercept_icp_e8s.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "intercept_icp_e8s".to_string(),
            )
        })?;
        if to_direct_participation_icp_e8s <= from_direct_participation_icp_e8s {
            return Err(LinearScalingCoefficientValidationError::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            });
        }
        if slope_denominator == 0 {
            return Err(LinearScalingCoefficientValidationError::DenominatorIsZero);
        }
        if slope_numerator > slope_denominator {
            return Err(
                LinearScalingCoefficientValidationError::NumeratorGreaterThanDenominator {
                    slope_numerator,
                    slope_denominator,
                },
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum LinearScalingCoefficientVecValidationError {
    LinearScalingCoefficientsOutOfRange(usize),
    LinearScalingCoefficientsUnordered(
        ValidatedLinearScalingCoefficient,
        ValidatedLinearScalingCoefficient,
    ),
    IrregularLinearScalingCoefficients(ValidatedLinearScalingCoefficient),
    LinearScalingCoefficientValidationError(LinearScalingCoefficientValidationError),
}

impl ToString for LinearScalingCoefficientVecValidationError {
    fn to_string(&self) -> String {
        let prefix = "LinearScalingCoefficientVecValidationError: ";
        match self {
            Self::LinearScalingCoefficientsOutOfRange(num_elements) => {
                format!(
                    "{}coefficient_intervals (len={}) must contain at least 1 and at most {} elements.",
                    prefix,
                    num_elements,
                    MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN,
                )
            }
            Self::LinearScalingCoefficientsUnordered(left, right) => {
                format!(
                    "{}The intervals {:?} and {:?} are ordered incorrectly.",
                    prefix, left, right
                )
            }
            Self::IrregularLinearScalingCoefficients(interval) => {
                format!(
                    "{}The first interval {:?} does not start from 0.",
                    prefix, interval,
                )
            }
            Self::LinearScalingCoefficientValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
        }
    }
}

impl From<LinearScalingCoefficientVecValidationError> for Result<(), String> {
    fn from(value: LinearScalingCoefficientVecValidationError) -> Self {
        Err(value.to_string())
    }
}

impl From<ValidatedLinearScalingCoefficient> for LinearScalingCoefficientPb {
    fn from(value: ValidatedLinearScalingCoefficient) -> Self {
        Self {
            from_direct_participation_icp_e8s: Some(value.from_direct_participation_icp_e8s),
            to_direct_participation_icp_e8s: Some(value.to_direct_participation_icp_e8s),
            slope_numerator: Some(value.slope_numerator),
            slope_denominator: Some(value.slope_denominator),
            intercept_icp_e8s: Some(value.intercept_icp_e8s),
        }
    }
}

impl TryFrom<&LinearScalingCoefficientPb> for ValidatedLinearScalingCoefficient {
    type Error = LinearScalingCoefficientValidationError;

    fn try_from(value: &LinearScalingCoefficientPb) -> Result<Self, Self::Error> {
        let from_direct_participation_icp_e8s =
            value.from_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "from_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let to_direct_participation_icp_e8s =
            value.to_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "to_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let slope_numerator = value.slope_numerator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField("slope_numerator".to_string())
        })?;
        let slope_denominator = value.slope_denominator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "slope_denominator".to_string(),
            )
        })?;
        // Currently we only check that `intercept_icp_e8s` is specified, so the actual field value
        // is unchecked.
        let intercept_icp_e8s = value.intercept_icp_e8s.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "intercept_icp_e8s".to_string(),
            )
        })?;
        if to_direct_participation_icp_e8s <= from_direct_participation_icp_e8s {
            return Err(LinearScalingCoefficientValidationError::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            });
        }
        if slope_denominator == 0 {
            return Err(LinearScalingCoefficientValidationError::DenominatorIsZero);
        }
        if slope_numerator > slope_denominator {
            return Err(
                LinearScalingCoefficientValidationError::NumeratorGreaterThanDenominator {
                    slope_numerator,
                    slope_denominator,
                },
            );
        }
        Ok(Self {
            from_direct_participation_icp_e8s,
            to_direct_participation_icp_e8s,
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
        })
    }
}

#[derive(Debug)]
pub enum IdealMatchedParticipationFunctionValidationError {
    TooManyBytes(usize),
    DeserializationError(String),
}

impl ToString for IdealMatchedParticipationFunctionValidationError {
    fn to_string(&self) -> String {
        let prefix = "IdealMatchedParticipationFunctionValidationError: ";
        match self {
            Self::TooManyBytes(num_bytes) => {
                format!(
                    "{prefix} serialized representation has {} bytes; the maximum is {} bytes.",
                    num_bytes, MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES,
                )
            }
            Self::DeserializationError(error) => {
                format!("{prefix} cannot deserialize: {}", error)
            }
        }
    }
}

#[derive(Debug)]
pub enum NeuronsFundParticipationConstraintsValidationError {
    RelatedFieldUnspecified(String),
    LinearScalingCoefficientVecValidationError(LinearScalingCoefficientVecValidationError),
    IdealMatchedParticipationFunctionValidationError(
        IdealMatchedParticipationFunctionValidationError,
    ),
}

impl ToString for NeuronsFundParticipationConstraintsValidationError {
    fn to_string(&self) -> String {
        let prefix = "NeuronsFundParticipationConstraintsValidationError: ";
        match self {
            Self::RelatedFieldUnspecified(related_field_name) => {
                format!("{}{} must be specified.", prefix, related_field_name,)
            }
            Self::LinearScalingCoefficientVecValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
            Self::IdealMatchedParticipationFunctionValidationError(error) => {
                format!("{prefix}{}", error.to_string())
            }
        }
    }
}

impl From<NeuronsFundParticipationConstraintsValidationError> for Result<(), String> {
    fn from(value: NeuronsFundParticipationConstraintsValidationError) -> Self {
        Err(value.to_string())
    }
}

impl<F> TryFrom<&NeuronsFundParticipationConstraintsPb>
    for ValidatedNeuronsFundParticipationConstraints<F>
where
    F: DeserializableFunction,
{
    type Error = NeuronsFundParticipationConstraintsValidationError;

    fn try_from(value: &NeuronsFundParticipationConstraintsPb) -> Result<Self, Self::Error> {
        // Validate min_direct_participation_threshold_icp_e8s
        let min_direct_participation_threshold_icp_e8s = value
            .min_direct_participation_threshold_icp_e8s
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "min_direct_participation_threshold_icp_e8s".to_string(),
                )
            })?;

        // Validate max_neurons_fund_participation_icp_e8s
        let max_neurons_fund_participation_icp_e8s = value
            .max_neurons_fund_participation_icp_e8s
            .ok_or_else(|| {
            Self::Error::RelatedFieldUnspecified(
                "max_neurons_fund_participation_icp_e8s".to_string(),
            )
        })?;

        // Validate coefficient_intervals length.
        if !(1..MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN + 1)
            .contains(&value.coefficient_intervals.len())
        {
            return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsOutOfRange(
                    value.coefficient_intervals.len(),
                ),
            ));
        }

        // Validate individual coefficient_intervals elements, consuming value.
        let coefficient_intervals: Vec<ValidatedLinearScalingCoefficient> = value
            .coefficient_intervals
            .iter()
            .map(ValidatedLinearScalingCoefficient::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                Self::Error::LinearScalingCoefficientVecValidationError(
                LinearScalingCoefficientVecValidationError::LinearScalingCoefficientValidationError(err)
            )
            })?;

        // Validate that coefficient_intervals forms a partitioning.
        let intervals = &coefficient_intervals;
        intervals
            .iter()
            .zip(intervals.iter().skip(1))
            .find(|(prev, this)| {
                prev.to_direct_participation_icp_e8s != this.from_direct_participation_icp_e8s
            })
            .map_or(Ok(()), |(prev, this)| {
                Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsUnordered(
                        prev.clone(),
                        this.clone(),
                    ),
                ))
            })?;

        // Validate that coefficient_intervals starts from 0.
        if let Some(first_interval) = intervals.first() {
            if first_interval.from_direct_participation_icp_e8s != 0 {
                return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::IrregularLinearScalingCoefficients(
                        first_interval.clone(),
                    ),
                ));
            }
        }

        let matching_function_serialized_representation = value
            .ideal_matched_participation_function
            .as_ref()
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "ideal_matched_participation_function".to_string(),
                )
            })?
            .serialized_representation
            .as_ref()
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "ideal_matched_participation_function.serialized_representation".to_string(),
                )
            })?;
        if matching_function_serialized_representation.len()
            > MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES
        {
            return Err(
                Self::Error::IdealMatchedParticipationFunctionValidationError(
                    IdealMatchedParticipationFunctionValidationError::TooManyBytes(
                        matching_function_serialized_representation.len(),
                    ),
                ),
            );
        }

        let ideal_matched_participation_function =
            F::from_repr(matching_function_serialized_representation).map_err(|e| {
                Self::Error::IdealMatchedParticipationFunctionValidationError(
                    IdealMatchedParticipationFunctionValidationError::DeserializationError(e),
                )
            })?;

        Ok(Self {
            min_direct_participation_threshold_icp_e8s,
            max_neurons_fund_participation_icp_e8s,
            coefficient_intervals,
            ideal_matched_participation_function,
        })
    }
}

/// This function can be imported in crates other than ic_sns_swap.
pub fn validate_neurons_fund_participation_constraints<F>(
    value: &NeuronsFundParticipationConstraintsPb,
) -> Result<
    ValidatedNeuronsFundParticipationConstraints<F>,
    NeuronsFundParticipationConstraintsValidationError,
>
where
    F: DeserializableFunction,
{
    value.try_into()
}

impl TryFrom<LinearScalingCoefficientPb> for ValidatedLinearScalingCoefficient {
    type Error = LinearScalingCoefficientValidationError;

    fn try_from(value: LinearScalingCoefficientPb) -> Result<Self, Self::Error> {
        let from_direct_participation_icp_e8s =
            value.from_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "from_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let to_direct_participation_icp_e8s =
            value.to_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "to_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let slope_numerator = value.slope_numerator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField("slope_numerator".to_string())
        })?;
        let slope_denominator = value.slope_denominator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "slope_denominator".to_string(),
            )
        })?;
        // Currently we only check that `intercept_icp_e8s` is specified, so the actual field value
        // is unchecked.
        let intercept_icp_e8s = value.intercept_icp_e8s.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "intercept_icp_e8s".to_string(),
            )
        })?;
        if to_direct_participation_icp_e8s <= from_direct_participation_icp_e8s {
            return Err(LinearScalingCoefficientValidationError::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            });
        }
        if slope_denominator == 0 {
            return Err(LinearScalingCoefficientValidationError::DenominatorIsZero);
        }
        if slope_numerator > slope_denominator {
            return Err(
                LinearScalingCoefficientValidationError::NumeratorGreaterThanDenominator {
                    slope_numerator,
                    slope_denominator,
                },
            );
        }
        Ok(Self {
            from_direct_participation_icp_e8s,
            to_direct_participation_icp_e8s,
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
        })
    }
}

impl<F> From<ValidatedNeuronsFundParticipationConstraints<F>>
    for NeuronsFundParticipationConstraintsPb
where
    F: IdealMatchingFunction,
{
    fn from(value: ValidatedNeuronsFundParticipationConstraints<F>) -> Self {
        Self {
            min_direct_participation_threshold_icp_e8s: Some(
                value.min_direct_participation_threshold_icp_e8s,
            ),
            max_neurons_fund_participation_icp_e8s: Some(
                value.min_direct_participation_threshold_icp_e8s,
            ),
            coefficient_intervals: value
                .coefficient_intervals
                .into_iter()
                .map(LinearScalingCoefficientPb::from)
                .collect(),
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunctionSwapPb {
                serialized_representation: Some(
                    value.ideal_matched_participation_function.serialize(),
                ),
            }),
        }
    }
}

impl<F> TryFrom<NeuronsFundParticipationConstraintsPb>
    for ValidatedNeuronsFundParticipationConstraints<F>
where
    F: IdealMatchingFunction + DeserializableFunction,
{
    type Error = NeuronsFundParticipationConstraintsValidationError;

    fn try_from(value: NeuronsFundParticipationConstraintsPb) -> Result<Self, Self::Error> {
        // Validate min_direct_participation_threshold_icp_e8s
        let min_direct_participation_threshold_icp_e8s = value
            .min_direct_participation_threshold_icp_e8s
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "min_direct_participation_threshold_icp_e8s".to_string(),
                )
            })?;

        // Validate max_neurons_fund_participation_icp_e8s
        let max_neurons_fund_participation_icp_e8s = value
            .max_neurons_fund_participation_icp_e8s
            .ok_or_else(|| {
            Self::Error::RelatedFieldUnspecified(
                "max_neurons_fund_participation_icp_e8s".to_string(),
            )
        })?;

        // Validate coefficient_intervals length.
        if !(1..MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN + 1)
            .contains(&value.coefficient_intervals.len())
        {
            return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsOutOfRange(
                    value.coefficient_intervals.len(),
                ),
            ));
        }

        // Validate individual coefficient_intervals elements, consuming value.
        let coefficient_intervals: Vec<ValidatedLinearScalingCoefficient> = value
            .coefficient_intervals
            .into_iter()
            .map(ValidatedLinearScalingCoefficient::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                Self::Error::LinearScalingCoefficientVecValidationError(
                LinearScalingCoefficientVecValidationError::LinearScalingCoefficientValidationError(err)
            )
            })?;

        // Validate that coefficient_intervals forms a partitioning.
        let intervals = &coefficient_intervals;
        intervals
            .iter()
            .zip(intervals.iter().skip(1))
            .find(|(prev, this)| {
                prev.to_direct_participation_icp_e8s != this.from_direct_participation_icp_e8s
            })
            .map_or(Ok(()), |(prev, this)| {
                Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsUnordered(
                        prev.clone(),
                        this.clone(),
                    ),
                ))
            })?;

        // Validate that coefficient_intervals starts from 0.
        if let Some(first_interval) = intervals.first() {
            if first_interval.from_direct_participation_icp_e8s != 0 {
                return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::IrregularLinearScalingCoefficients(
                        first_interval.clone(),
                    ),
                ));
            }
        }

        let matching_function_serialized_representation = value
            .ideal_matched_participation_function
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "ideal_matched_participation_function".to_string(),
                )
            })?
            .serialized_representation
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "ideal_matched_participation_function.serialized_representation".to_string(),
                )
            })?;
        if matching_function_serialized_representation.len()
            > MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES
        {
            return Err(
                Self::Error::IdealMatchedParticipationFunctionValidationError(
                    IdealMatchedParticipationFunctionValidationError::TooManyBytes(
                        matching_function_serialized_representation.len(),
                    ),
                ),
            );
        }

        let ideal_matched_participation_function =
            F::from_repr(&matching_function_serialized_representation).map_err(|e| {
                Self::Error::IdealMatchedParticipationFunctionValidationError(
                    IdealMatchedParticipationFunctionValidationError::DeserializationError(e),
                )
            })?;

        Ok(Self {
            min_direct_participation_threshold_icp_e8s,
            max_neurons_fund_participation_icp_e8s,
            coefficient_intervals,
            ideal_matched_participation_function,
        })
    }
}
