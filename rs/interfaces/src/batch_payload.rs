use crate::{consensus::PayloadValidationError, validation::ValidationResult};
use ic_base_types::NumBytes;
use ic_types::{
    batch::ValidationContext, consensus::BlockPayload, crypto::CryptoHashOf, Height, NodeId, Time,
};
use prost::{bytes::BufMut, DecodeError, Message};

/// A list of [`PastPayload`] will be passed to invocation of
///  [`BatchPayloadBuilder::build_payload`].
///
/// The purpose is to allow the payload builders to deduplicate
/// messages that they have already included in prior.
#[derive(Debug, Clone)]
pub struct PastPayload<'a> {
    /// Height of the payload
    pub height: Height,
    /// Timestamp of the past payload
    pub time: Time,
    /// The hash of the block, in which this payload is included.
    ///
    /// This can be used to differentiate between multiple blocks of the same
    /// height, e.g. when the payload builder wants to maintain an internal cache
    /// of past payloads.
    pub block_hash: CryptoHashOf<BlockPayload>,
    /// Payload bytes of the past payload
    ///
    /// Note that this is only the specific payload that
    /// belongs to the payload builder.
    pub payload: &'a [u8],
}

/// Context of the proposal
///
/// This struct passes additional information about the block proposal to the
/// payload validator. Some payload validators need this information to check the
/// validity of the payload.
pub struct ProposalContext<'a> {
    pub proposer: NodeId,
    pub validation_context: &'a ValidationContext,
}

/// Indicates that this component can build batch payloads.
///
/// A batch payload has the following properties:
/// - Variable and possibly unbounded size
/// - Content of the payload is opaque to consensus and only relevant for upper layers
/// - Payload is not bound to a particular block height
/// - Internally composed of a number of similarly shaped messages
///
/// # Ordering
/// The `past_payloads` in [`BatchPayloadBuilder::build_payload`] and
/// [`BatchPayloadBuilder::validate_payload`] MUST be in descending `height` order.
pub trait BatchPayloadBuilder: Send + Sync {
    /// Builds a payload and returns it in serialized form.
    ///
    /// # Arguments
    /// - `max_size`: The maximum size the payload is supposed to have
    /// - `past_payloads`: A collection of past payloads. Allows the payload builder
    ///     to deduplicate messages.
    /// - `context`: [`ValidationContext`] under which the payload is supposed to be validated
    ///
    /// # Returns
    ///
    /// The payload in its serialized form
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8>;

    /// Checks whether a payload is valid.
    ///
    /// # Arguments
    /// - `payload`: The payload to validate
    /// - `past_payloads`: A collection of past payloads. Allows the payload builder
    ///     to deduplicate messages
    /// - `context`: [`ValidationContext`] under which to validate the payload
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - A [`BatchPayloadValidationError`] describing the problem otherwise
    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> ValidationResult<PayloadValidationError>;
}

/// Indicates that a payload can be transformed into a set of messages, which
/// can be passed to message routing as part of the batch delivery.
pub trait IntoMessages<M> {
    /// Parse the payload into the message type to be included in the batch.
    ///
    /// # Guarantees
    ///
    /// This function must be infallible if the corresponding [`BatchPayloadBuilder::validate_payload`]
    /// returns `Ok(())` on the same payload.
    fn into_messages(payload: &[u8]) -> M;
}

/// Given an iterator of [`Message`]s, this function will deserialize the messages
/// into a byte vector.
///
/// The function is given a `max_size` limit, and guarantees that the buffer will be
/// smaller or equal than the byte limit.
/// It may drop messages from the iterator, if they don't fit.
pub fn iterator_to_bytes<I, M>(iter: I, max_size: NumBytes) -> Vec<u8>
where
    M: Message,
    I: Iterator<Item = M>,
{
    let mut buffer = vec![].limit(max_size.get() as usize);

    for val in iter {
        // NOTE: This call may fail due to the encoding hitting the
        // byte limit. We continue trying the rest of the messages
        // nonetheless, to give smaller messages a chance as well
        let _ = val.encode_length_delimited(&mut buffer);
    }

    buffer.into_inner()
}

/// Parse a slice filled with protobuf encoded [`Message`]s into a vector
pub fn slice_to_messages<M>(mut data: &[u8]) -> Result<Vec<M>, DecodeError>
where
    M: Message + Default,
{
    let mut msgs = vec![];

    while !data.is_empty() {
        let msg = M::decode_length_delimited(&mut data)?;
        msgs.push(msg)
    }

    Ok(msgs)
}
