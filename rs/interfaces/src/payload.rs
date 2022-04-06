//! This module defines traits related to payloads and payload building.

use crate::validation::ValidationError;
use ic_base_types::NumBytes;
use ic_types::{batch::ValidationContext, consensus::Payload, Height, Time};

/// A marker trait, indicating, that some struct is a section of the [`BatchPayload`].
pub trait BatchPayloadSectionType: Default {
    /// The type of error that is returned, when the validation failed permanently.
    type PermanentValidationError;

    /// The type of error that is returned, when the validation does not pass transitively,
    /// i.e. the payload may pass validation at a later state.
    type TransientValidationError;
}

/// A [`BatchPayloadSectionBuilder`] is implemented by any artifact, that can be
/// included into a [`BatchPayload`](ic_types::batch::BatchPayload).
///
/// # Invariants:
/// It is **crucial** that any payload returned by
/// [`build_payload`](BatchPayloadSectionBuilder::build_payload)
/// succeeds when passed into
/// [`validate_payload`](BatchPayloadSectionBuilder::validate_payload),
/// given the same arguments for [`ValidationContext`] and `past_payloads`,
/// and that the following monotony holds:
///
/// - Payload size returned by [`build_payload`](BatchPayloadSectionBuilder::build_payload)
///     `<=` `max_size` passed into [`build_payload`](BatchPayloadSectionBuilder::build_payload)
/// - Payload size returned by [`validate_payload`](BatchPayloadSectionBuilder::validate_payload)
///     `<=` payload size returned by [`build_payload`](BatchPayloadSectionBuilder::build_payload)
///
/// It is advised to call the validation function after building the payload to be 100% sure.
// [build_payload]: (BatchPayloadSectionBuilder::build_payload)
// [validate_payload]: (BatchPayloadSectionBuilder::validate_payload)
pub trait BatchPayloadSectionBuilder<T>
where
    T: BatchPayloadSectionType,
{
    /// Called to build the payload.
    ///
    /// # Arguments:
    /// - `validation_context`: The [`ValidationContext`], under which the payload must be valid.
    /// - `max_size`: The maximum size in [`NumBytes`], that the payload section has available in the current batch.
    /// - `priority`: The order in which the individual [`BatchPayloadSectionBuilder`] have been called.
    /// - `past_payloads`: All [`BatchPayload`]s from the certified height to the tip.
    ///
    /// # Returns:
    /// The [`BatchPayloadSectionType`]. If there is no suitable payload, return [`Default`].
    /// The size of the payload in [`NumBytes`].
    fn build_payload(
        &self,
        validation_context: &ValidationContext,
        max_size: NumBytes,
        priority: usize,
        past_payloads: &[(Height, Time, Payload)],
    ) -> (T, NumBytes);

    /// Called to validate the payload.
    ///
    /// # Argument:
    /// - `payload`: The payload to verify.
    /// - `validation_context`: The [`ValidationContext`], under which to validate the payload.
    /// - `past_payloads`: All [`Payload`]s from the certified height to the tip.
    ///
    /// # Returns:
    /// **On success:** The size of the section as [`NumBytes`].
    /// **On error:**: Either a transient or permantent error.
    fn validate_payload(
        &self,
        payload: &T,
        validation_context: &ValidationContext,
        past_payloads: &[(Height, Time, Payload)],
    ) -> Result<NumBytes, ValidationError<T::PermanentValidationError, T::TransientValidationError>>;
}
