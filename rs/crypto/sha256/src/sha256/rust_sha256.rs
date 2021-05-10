use sha2::{Digest, Sha256};

#[derive(Default)]
pub struct InternalSha256 {
    state: Sha256,
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

impl InternalSha256 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        self.state.finalize().into()
    }
}
