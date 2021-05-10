use openssl::sha::Sha224;

pub struct InternalSha224 {
    state: Sha224,
}

impl Default for InternalSha224 {
    fn default() -> Self {
        Self {
            state: openssl::sha::Sha224::new(),
        }
    }
}

pub fn hash(data: &[u8]) -> [u8; 28] {
    openssl::sha::sha224(data)
}

impl InternalSha224 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 28] {
        self.state.finish()
    }
}
