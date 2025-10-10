use crate::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{Storable, storable::Bound};
use num_traits::bounds::{LowerBounded, UpperBounded};
use std::borrow::Cow;

pub mod access_control;
pub mod init;
pub mod pb;
pub mod registry;
pub mod types;

impl NeuronId {
    pub const MIN: Self = Self { id: u64::MIN };
    pub const MAX: Self = Self { id: u64::MAX };

    pub fn next(&self) -> Option<NeuronId> {
        self.id.checked_add(1).map(|id| NeuronId { id })
    }
}

impl From<NeuronId> for u64 {
    fn from(id: NeuronId) -> Self {
        id.id
    }
}

impl Storable for NeuronId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.id.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            id: u64::from_bytes(bytes),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: std::mem::size_of::<u64>() as u32,
        is_fixed_size: true,
    };
}

impl LowerBounded for NeuronId {
    fn min_value() -> Self {
        Self::MIN
    }
}

impl UpperBounded for NeuronId {
    fn max_value() -> Self {
        Self::MAX
    }
}

impl ProposalId {
    pub const MIN: Self = Self { id: u64::MIN };
    pub const MAX: Self = Self { id: u64::MAX };
}

impl Storable for ProposalId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.id.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            id: u64::from_bytes(bytes),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: std::mem::size_of::<u64>() as u32,
        is_fixed_size: true,
    };
}
