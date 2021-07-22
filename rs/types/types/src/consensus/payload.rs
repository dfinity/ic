//! Defines consensus payload types.
use crate::{
    batch::BatchPayload,
    consensus::{dkg, hashed::Hashed, thunk::Thunk},
    crypto::CryptoHashOf,
    *,
};
use serde::{Deserialize, Serialize};
use std::cmp::PartialOrd;
use std::hash::Hash;
use std::sync::Arc;

/// Block payload is either DKG summary or (BatchPayload, DKG Dealings).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum BlockPayload {
    /// A BlockPayload::Summary contains only a DKG Summary
    Summary(dkg::Summary),
    /// A BlockPayload::BatchAndDealings contains batch payload (ingress and
    /// xnet messages) and DKG dealings
    BatchAndDealings(BatchPayload, dkg::Dealings),
}

impl BlockPayload {
    /// Return true if it is a normal block and empty
    pub fn is_empty(&self) -> bool {
        match self {
            BlockPayload::BatchAndDealings(batch, dealings) => {
                batch.is_empty() && dealings.messages.is_empty()
            }
            _ => false,
        }
    }

    /// Return true if the given payload is a summary block.
    pub fn is_summary(&self) -> bool {
        matches!(self, BlockPayload::Summary(_))
    }

    /// Returns a reference to DKG summary. Panics if called on a dealings
    /// payload.
    pub fn as_summary(&self) -> &dkg::Summary {
        match self {
            BlockPayload::Summary(summary) => summary,
            _ => panic!("No DKG summary available on a block with dealings."),
        }
    }

    /// Returns the DKG summary. Panics if called on a normal payload.
    pub fn into_summary(self) -> dkg::Summary {
        match self {
            BlockPayload::Summary(summary) => summary,
            _ => panic!("No DKG summary available on a block with dealings."),
        }
    }

    /// Returns a reference to DKG dealings. Panics if called on a summary
    /// payload.
    pub fn as_dealings(&self) -> &dkg::Dealings {
        match self {
            BlockPayload::BatchAndDealings(_, payload) => &payload,
            _ => panic!("No DKG dealings available on a summary block."),
        }
    }

    /// Returns DKG dealings. Panics if called on a summary payload.
    pub fn into_dealings(self) -> dkg::Dealings {
        match self {
            BlockPayload::BatchAndDealings(_, payload) => payload,
            _ => panic!("No DKG dealings available on a summary block."),
        }
    }

    /// Return a reference to batch payload. Panics if called on a summary
    /// payload.
    pub fn as_batch_payload(&self) -> &BatchPayload {
        match self {
            BlockPayload::BatchAndDealings(batch, _) => batch,
            _ => panic!("No batch payload available on a summary block."),
        }
    }

    /// Return the batch payload. Panics if called on a summary payload.
    pub fn into_batch_payload(self) -> BatchPayload {
        match self {
            BlockPayload::BatchAndDealings(batch, _) => batch,
            _ => panic!("No batch payload available on a summary block."),
        }
    }

    /// Return the payload type.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            BlockPayload::Summary(_) => PayloadType::Summary,
            BlockPayload::BatchAndDealings(_, _) => PayloadType::BatchAndDealings,
        }
    }

    /// Return start height of the DKG interval that this payload is in.
    pub fn dkg_interval_start_height(&self) -> Height {
        match self {
            BlockPayload::Summary(summary) => summary.height,
            BlockPayload::BatchAndDealings(_, payload) => payload.start_height,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum PayloadType {
    Summary,
    BatchAndDealings,
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PayloadType::Summary => "summary",
                PayloadType::BatchAndDealings => "batch_and_dealings",
            }
        )
    }
}

/// A lazily loaded `BlockPayload` that is also internally shared via an `Arc`
/// pointer so that it is cheap to clone.
///
/// It serializes to both the crypto hash and value of a `BlockPayload`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Payload {
    payload_type: PayloadType,
    payload: Arc<Hashed<CryptoHashOf<BlockPayload>, Thunk<BlockPayload>>>,
}

impl Payload {
    /// Return a Payload using the given hash function and a `BlockPayload`.
    pub fn new<F: FnOnce(&BlockPayload) -> CryptoHashOf<BlockPayload> + Send + 'static>(
        hash_func: F,
        payload: BlockPayload,
    ) -> Self {
        Self {
            payload_type: payload.payload_type(),
            payload: Arc::new(Hashed::new(
                move |thunk: &Thunk<BlockPayload>| hash_func(thunk.as_ref()),
                Thunk::from(payload),
            )),
        }
    }

    /// Return a Payload with the given hash, and an intialization function that
    /// will be use for lazily loading the actual `BlockPayload` matching
    /// the given hash. This function does not check if the eventually loaded
    /// `BlockPayload` with match the given hash, so it must be used with care.
    pub fn new_with(
        hash: CryptoHashOf<BlockPayload>,
        payload_type: PayloadType,
        init: Box<dyn FnOnce() -> BlockPayload + Send>,
    ) -> Self {
        Self {
            payload_type,
            payload: Arc::new(Hashed {
                hash,
                value: Thunk::new(init),
            }),
        }
    }

    pub(crate) fn new_from_hash_and_value(
        hash: CryptoHashOf<BlockPayload>,
        payload: BlockPayload,
    ) -> Self {
        Self {
            payload_type: payload.payload_type(),
            payload: Arc::new(Hashed::recompose(hash, Thunk::from(payload))),
        }
    }

    /// Return the crypto hash of the enclosed `BlockPayload`.
    pub fn get_hash(&self) -> &CryptoHashOf<BlockPayload> {
        self.payload.get_hash()
    }

    /// Return true if the given payload is a summary block.
    pub fn is_summary(&self) -> bool {
        self.payload_type == PayloadType::Summary
    }

    /// Return the payload type of the block.
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }
}

impl AsRef<BlockPayload> for Payload {
    fn as_ref(&self) -> &BlockPayload {
        self.payload.get_value().as_ref()
    }
}

impl From<Payload> for BlockPayload {
    fn from(payload: Payload) -> BlockPayload {
        match Arc::try_unwrap(payload.payload) {
            Ok(payload) => payload.into_inner().into_inner(),
            Err(payload) => payload.get_value().as_ref().clone(),
        }
    }
}

impl From<dkg::Summary> for BlockPayload {
    fn from(summary: dkg::Summary) -> BlockPayload {
        BlockPayload::Summary(summary)
    }
}

impl From<(BatchPayload, dkg::Dealings)> for BlockPayload {
    fn from((batch, dealings): (BatchPayload, dkg::Dealings)) -> BlockPayload {
        BlockPayload::BatchAndDealings(batch, dealings)
    }
}

impl From<dkg::Payload> for BlockPayload {
    fn from(payload: dkg::Payload) -> BlockPayload {
        match payload {
            dkg::Payload::Summary(summary) => summary.into(),
            dkg::Payload::Dealings(dealings) => {
                BlockPayload::BatchAndDealings(BatchPayload::default(), dealings)
            }
        }
    }
}
