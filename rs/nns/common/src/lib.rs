use crate::pb::v1::{NeuronId, ProposalId};
use ic_crypto_sha2::Sha256;
use ic_stable_structures::{storable::Bound, Storable};
use num_traits::bounds::{LowerBounded, UpperBounded};
use std::{borrow::Cow, convert::TryInto};

pub mod access_control;
pub mod init;
pub mod pb;
pub mod registry;
pub mod types;

impl NeuronId {
    pub const MIN: Self = Self { id: u64::MIN };
    pub const MAX: Self = Self { id: u64::MAX };

    pub fn from_subaccount(subaccount: &[u8; 32]) -> Self {
        Self {
            id: {
                let mut state = Sha256::new();
                state.write(subaccount);
                // TODO(NNS1-192) We should just store the Sha256, but for now
                // we convert it to a number
                u64::from_ne_bytes(state.finish()[0..8].try_into().unwrap())
            },
        }
    }

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
    fn to_bytes(&self) -> Cow<[u8]> {
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

impl Storable for ProposalId {
    fn to_bytes(&self) -> Cow<[u8]> {
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
