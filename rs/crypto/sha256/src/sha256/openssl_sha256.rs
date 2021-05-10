use openssl::sha::Sha256;

pub struct InternalSha256 {
    state: Sha256,
}

impl Default for InternalSha256 {
    fn default() -> Self {
        Self {
            state: openssl::sha::Sha256::new(),
        }
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(data)
}

impl InternalSha256 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        self.state.finish()
    }
}
