use sha2::{Digest, Sha224};

#[derive(Default)]
pub struct InternalSha224 {
    state: Sha224,
}

pub fn hash(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(data);
    hasher.finalize().into()
}

impl InternalSha224 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 28] {
        self.state.finalize().into()
    }
}
