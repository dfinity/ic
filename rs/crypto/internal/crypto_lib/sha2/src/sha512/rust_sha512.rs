use sha2::{Digest, Sha512};
use std::convert::TryInto;

#[derive(Default)]
pub struct InternalSha512 {
    state: Sha512,
}

pub fn hash(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.as_slice()
        .try_into()
        .expect("infallable as length is 64")
}

impl InternalSha512 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 64] {
        let hash = self.state.finalize();
        hash.as_slice()
            .try_into()
            .expect("infallable as length is 64")
    }
}
