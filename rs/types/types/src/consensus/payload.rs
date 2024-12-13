//! Defines consensus payload types.
use crate::{
    batch::BatchPayload,
    consensus::{dkg, hashed::Hashed, idkg, thunk::Thunk, vetkd},
    crypto::CryptoHashOf,
    *,
};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use std::{cmp::PartialOrd, hash::Hasher};

/// A payload, that contains information needed during a regular round.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DataPayload {
    pub batch: BatchPayload,
    pub dkg: dkg::DkgDataPayload,
    pub idkg: idkg::Payload,
    pub vetkd: vetkd::Payload,
}

/// The payload of a summary block.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SummaryPayload {
    pub dkg: dkg::Summary,
    pub idkg: idkg::Summary,
    pub vetkd: vetkd::Summary,
    pub supports_vetkd_payload: bool,
}

impl Hash for SummaryPayload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let SummaryPayload {
            dkg,
            idkg,
            vetkd,
            supports_vetkd_payload,
        } = self;

        dkg.hash(state);
        idkg.hash(state);
        // supports_vetkd_payload purposefully ignored
        if *supports_vetkd_payload {
            vetkd.hash(state);
        }
    }
}

impl SummaryPayload {
    /// Return the oldest registry version that is still referenced by
    /// parts of the summary block.
    ///
    /// P2P should keep up connections to all nodes registered in any registry
    /// between the one returned from this function and the current
    /// `RegistryVersion`.
    ///
    /// Note that this function should generally be called on the CUP instead.
    pub(crate) fn get_oldest_registry_version_in_use(&self) -> RegistryVersion {
        let dkg_version = self.dkg.get_oldest_registry_version_in_use();
        if let Some(idkg_version) = self
            .idkg
            .as_ref()
            .and_then(|payload| payload.get_oldest_registry_version_in_use())
        {
            dkg_version.min(idkg_version)
        } else {
            dkg_version
        }
    }

    pub fn new(dkg: dkg::Summary, idkg: idkg::Summary) -> Self {
        Self {
            dkg,
            idkg,
            vetkd: None,
            supports_vetkd_payload: false,
        }
    }
}

/// Block payload is either summary or a data payload).
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum BlockPayload {
    /// A BlockPayload::Summary contains only a DKG Summary
    Summary(SummaryPayload),
    /// A BlockPayload::Data contains data that is needed during a regular
    /// round, such as XNet or Ingress messages and DKG dealings.
    Data(DataPayload),
}

impl BlockPayload {
    /// Return true if it is a normal block and empty
    pub fn is_empty(&self) -> bool {
        match self {
            BlockPayload::Data(data) => {
                data.batch.is_empty()
                    && data.dkg.messages.is_empty()
                    && data.idkg.is_none()
                    && data.vetkd.is_none()
            }
            _ => false,
        }
    }

    /// Return true if the given payload is a summary block.
    pub fn is_summary(&self) -> bool {
        matches!(self, BlockPayload::Summary(_))
    }

    /// Returns a reference to summary. Panics if called on a data
    /// payload.
    pub fn as_summary(&self) -> &SummaryPayload {
        match self {
            BlockPayload::Summary(summary) => summary,
            _ => panic!("No DKG summary available on a block with dealings."),
        }
    }

    /// Returns the summary. Panics if called on a normal payload.
    pub fn into_summary(self) -> SummaryPayload {
        match self {
            BlockPayload::Summary(summary) => summary,
            _ => panic!("No DKG summary available on a block with dealings."),
        }
    }

    /// Returns a reference to DKG data. Panics if called on a summary
    /// payload.
    pub fn as_data(&self) -> &DataPayload {
        match self {
            BlockPayload::Data(data) => data,
            _ => panic!("No data payload available on a summary block."),
        }
    }

    /// Returns DKG data. Panics if called on a summary payload.
    pub fn into_data(self) -> DataPayload {
        match self {
            BlockPayload::Data(data) => data,
            _ => panic!("No data payload available on a summary block."),
        }
    }

    /// Returns a reference to IDkgPayload if it exists.
    pub fn as_idkg(&self) -> Option<&idkg::IDkgPayload> {
        match self {
            BlockPayload::Data(data) => data.idkg.as_ref(),
            BlockPayload::Summary(data) => data.idkg.as_ref(),
        }
    }

    /// Returns a reference to VetKdPayload if it exists.
    pub fn as_vetkd(&self) -> Option<&vetkd::VetKdPayload> {
        match self {
            BlockPayload::Data(data) => data.vetkd.as_ref(),
            BlockPayload::Summary(data) => data.vetkd.as_ref(),
        }
    }

    /// Return the payload type.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            BlockPayload::Summary(_) => PayloadType::Summary,
            BlockPayload::Data(_) => PayloadType::Data,
        }
    }

    /// Return start height of the DKG interval that this payload is in.
    pub fn dkg_interval_start_height(&self) -> Height {
        match self {
            BlockPayload::Summary(summary) => summary.dkg.height,
            BlockPayload::Data(data) => data.dkg.start_height,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum PayloadType {
    Summary,
    Data,
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PayloadType::Summary => "summary",
                PayloadType::Data => "batch_and_dealings",
            }
        )
    }
}

/// A lazily loaded `BlockPayload` that is also internally shared via an `Arc`
/// pointer so that it is cheap to clone.
///
/// It serializes to both the crypto hash and value of a `BlockPayload`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct Payload {
    payload_type: PayloadType,
    // It is not crucial that Arc used here is unique, because the data referenced remains
    // immutable. We use Arc only to optimize cloning cost.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
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

    /// Return a Payload with the given hash, and an initialization function that
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
