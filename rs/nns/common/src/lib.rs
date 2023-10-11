use crate::pb::v1::NeuronId;
use ic_crypto_sha2::Sha256;
use ic_stable_structures::{BoundedStorable, Storable};
use num_traits::bounds::{LowerBounded, UpperBounded};
use std::{borrow::Cow, convert::TryInto};

pub mod access_control;
pub mod init;
pub mod pb;
pub mod registry;
pub mod types;

impl NeuronId {
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
        NeuronId {
            id: u64::from_bytes(bytes),
        }
    }
}

impl BoundedStorable for NeuronId {
    const MAX_SIZE: u32 = std::mem::size_of::<u64>() as u32;
    const IS_FIXED_SIZE: bool = true;
}

impl LowerBounded for NeuronId {
    fn min_value() -> Self {
        NeuronId {
            id: u64::min_value(),
        }
    }
}

impl UpperBounded for NeuronId {
    fn max_value() -> Self {
        NeuronId {
            id: u64::max_value(),
        }
    }
}
