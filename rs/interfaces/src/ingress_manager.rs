//! The ingress manager public interface.
use crate::{
    execution_environment::{CanisterOutOfCyclesError, IngressHistoryError},
    ingress_pool::{ChangeSet, IngressPool, IngressPoolSelect},
    state_manager::StateManagerError,
    validation::{ValidationError, ValidationResult},
};
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, IngressPayloadError, ValidationContext},
    crypto::CryptoError,
    messages::MessageId,
    time::{Time, UNIX_EPOCH},
    CanisterId, NumBytes,
};
use std::collections::HashSet;

/// An generic interface that allows checking ingress existence.
pub trait IngressSetQuery {
    /// Return True if the given msg_id exists in the set.
    fn contains(&self, msg_id: &IngressMessageId) -> bool;

    /// Return the lower bound of expiry time that this set covers.
    ///
    /// Note that this is not necessarily the minimum of the expiry
    /// of all IngressMessageIds in the set.
    fn get_expiry_lower_bound(&self) -> Time;
}

/// HashSet<MessageId> implements IngressSetQuery.
impl IngressSetQuery for HashSet<IngressMessageId> {
    fn contains(&self, msg_id: &IngressMessageId) -> bool {
        HashSet::contains(self, msg_id)
    }
    fn get_expiry_lower_bound(&self) -> Time {
        self.iter()
            .map(|ingress_id| ingress_id.expiry())
            .min()
            .unwrap_or(UNIX_EPOCH)
    }
}

/// Permanent errors returned by the Ingress Selector.
#[derive(Debug)]
pub enum IngressPermanentError {
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    IngressValidationError(MessageId, String),
    IngressBucketError(MessageId),
    IngressHistoryError(IngressHistoryError),
    IngressPayloadError(IngressPayloadError),
    IngressExpired(MessageId, String),
    IngressMessageTooBig(usize, usize),
    IngressPayloadTooBig(usize, usize),
    IngressPayloadTooManyMessages(usize, usize),
    DuplicatedIngressMessage(MessageId),
    InsufficientCycles(CanisterOutOfCyclesError),
    CanisterNotFound(CanisterId),
    InvalidManagementMessage,
}

/// Transient errors returned by the Ingress Selector.
#[derive(Debug)]
pub enum IngressTransientError {
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
}

pub type IngressPayloadValidationError =
    ValidationError<IngressPermanentError, IngressTransientError>;

impl From<CryptoError> for IngressTransientError {
    fn from(err: CryptoError) -> IngressTransientError {
        IngressTransientError::CryptoError(err)
    }
}

impl From<CryptoError> for IngressPermanentError {
    fn from(err: CryptoError) -> IngressPermanentError {
        IngressPermanentError::CryptoError(err)
    }
}

impl<T> From<IngressPermanentError> for ValidationError<IngressPermanentError, T> {
    fn from(err: IngressPermanentError) -> ValidationError<IngressPermanentError, T> {
        ValidationError::Permanent(err)
    }
}

impl<P> From<IngressTransientError> for ValidationError<P, IngressTransientError> {
    fn from(err: IngressTransientError) -> ValidationError<P, IngressTransientError> {
        ValidationError::Transient(err)
    }
}

/// Processes Ingress messages received from peers or HttpHandler.
///
/// Its main role is to determine whether the message should be relayed to other
/// nodes or not and to remove expired messages. This interface is used by
/// ArtifactManager when a new ingress message is inserted in the unvalidated
/// pool.
pub trait IngressHandler {
    /// Inspect the input [IngressPool] to build a [ChangeSet] of
    /// actions to be executed. The caller is then expected to apply the
    /// returned [ChangeSet] to the input of this call, namely
    /// [IngressPool].
    ///
    /// #Input
    /// [IngressPool] which is passed as a read-only reference.
    ///
    /// #Returns
    /// [ChangeSet] that describes which Ingress Messages are added, moved or
    /// removed from their current part of the artifact pool
    fn on_state_change(&self, pool: &dyn IngressPool) -> ChangeSet;
}

/// A component used by Consensus to build and validate a payload.
pub trait IngressSelector: Send + Sync {
    /// Returns a new ingress payload containing valid Signed Ingress Messages
    /// to Consensus.
    ///
    /// #Input
    /// [IngressPool] passed as a read-only reference. It's the trait object to
    /// read validated messages from the IngressPool.
    /// [past_ingress] allows querying if an ingress message exists in past
    /// blocks. It is used for deduplication purpose.
    /// [ValidationContext] contains registry_version that allows to validate
    /// messages against the correct registry entries, execution_height which is
    /// used as parameter for the valid set rule check run to select a valid
    /// set of messages.
    ///
    /// The following invariant is placed on this function by consensus:
    /// get_ingress_payload(..., byte_limit).count_bytes() <= byte_limit
    ///
    /// #Returns
    /// [IngressPayload] which is a collection of valid ingress messages
    fn get_ingress_payload(
        &self,
        ingress_pool: &dyn IngressPoolSelect,
        past_ingress: &dyn IngressSetQuery,
        context: &ValidationContext,
        byte_limit: NumBytes,
    ) -> IngressPayload;

    /// Validates an IngressPayload against the past payloads and
    /// ValidationContext. The size of the payload is derived from registry.
    ///
    /// #Input
    /// [IngressPayload] is the payload to be validated.
    /// [past_ingress] allows querying if an ingress message exists in past
    /// blocks. It is used for deduplication purpose.
    /// [ValidationContext] Refers to the validation context which contains
    /// registry_version, execution_height to be used as a parameter for the
    /// valid set rule check run to select a valid set of messages
    ///
    /// #Returns
    /// `ValidationResult::Valid`: if the payload is valid
    /// `ValidationResult::Invalid`: if the payload is invalid
    /// `ValidationResult::Error`: a transient error occured during the
    /// validation.
    fn validate_ingress_payload(
        &self,
        payload: &IngressPayload,
        past_ingress: &dyn IngressSetQuery,
        context: &ValidationContext,
    ) -> ValidationResult<IngressPayloadValidationError>;

    /// Request purge of the given ingress messages from the pool when
    /// they have already been included in finalized blocks.
    ///
    /// The actual purge is not required to happen immediately.
    fn request_purge_finalized_messages(&self, message_ids: Vec<IngressMessageId>);
}

/*
A past ingress set contains past messages, and can be used for
deduplication purposes.  The following property of past ingress
set and its lowerbound must hold:

  A past ingress set contains (but may not only contain) ALL
  past messages whose expiry is greater than or equal to its
  lowerbound + MAX_INGRESS_TTL.

Explanation:

We assume each block's payload covers a certain expiry interval:

 P1 |---------|
    P2 |---------|
       P3 |---------|
          P4 |---------|
             P5 |---------|

In this diagram we know that we don't have to look into P1
when deduplicating ingress messages to be included in P5 because
their expiry domains do not overlap.

Suppose we accumulate past ingress into a set S, and use S(n) to
deduplicate messages to be included in P(n+1).

 P1 |---------|               S1 = P1
    P2 |---------|            S2 = S1 + P2 = P1 + P2
       P3 |---------|         S3 = S2 + P3 = P1 + P2 + P3
          P4 |---------|      S4 = S3 + P4 = P1 + P2 + P3 + P4
             P5 |---------|   ...

This works fine if P1 is the block after genesis. However, for a
replica joining the network from a CUP block (say P3), the situation
may look like this:

 P1 |---------|
    P2 |---------|
       P3 |---------|         S3 = P3
          P4 |---------|      S4 = S3 + P4 = P3 + P4
             P5 |---------|   ...

It has no knowledge of P1 and P2 because such blocks do not exist
locally. Apparently, checking only S4 when making P5 is insufficient.
To fix this problem, we need to look into the executed set E, i.e.
the IngressHistoryReader at P3.

Therefore, when making P5, we need to deduplicate against E + S4.
The question is, when can we safely stop looking into E?

 P1 |---------|
    P2 |---------|
       P3 |---------|             S3 = P3
          P4 |---------|          S4 = S3 + P4 = P3 + P4
             P5 |---------|       S5 = S4 + P5 = P3 + P4 + P5
                P6 |---------|    S6 = S5 + P6 = P3 + P4 + P5 + P6
                   P7 |---------|

When we make P7, We know for sure that payloads <= P3 no longer
have to be consulted, because the P3 and P7 do not overlap in
their expiry domain. So if we just look at the domain of S:

       S3 |---------|             S3 = P3
       S4 |------------|          S4 = S3 + P4 = P3 + P4
       S5 |---------------|       S5 = S4 + P5 = P3 + P4 + P5
       S6 |---------+--------|    S6 = S5 + P6 = P3 + P4 + P5 + P6

We can conclude that S6 includes ALL messages whose expiry are
greater than or equal to (lowerbound of S6 + MAX_INGRESS_TTL).
In fact this property holds true for every set we compute.

We can also start purging these sets to keep their size bounded.
If we look at just S6, P6 and P7:

       S6 |---------+--------|    S6 = S5 + P6 = P3 + P4 + P5 + P6
                P6 |---------|
                   P7 |---------|

Anything older than P6's start expiry can be safely purged from
S6, because P7 can only have a start expiry >= P6's.

       S6 |        -+--------|    S6 = S5 + P6 = P3 + P4 + P5 + P6
                P6 |---------|

However it is important to keep the original lowerbound, or set it
as follows in order to maintain our property:

  lowerbound := max(lowerbound, purge point - MAX_INGRESS_TTL)
*/
