pub mod access_control;
pub mod init;
pub mod pb;
pub mod registry;
pub mod types;

use ic_crypto_sha256::Sha256;
use std::convert::TryInto;

impl pb::v1::NeuronId {
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
