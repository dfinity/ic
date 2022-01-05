use openssl::sha::Sha512;

pub struct InternalSha512 {
    state: Sha512,
}

impl Default for InternalSha512 {
    fn default() -> Self {
        Self {
            state: openssl::sha::Sha512::new(),
        }
    }
}

pub fn hash(data: &[u8]) -> [u8; 64] {
    openssl::sha::sha512(data)
}

impl InternalSha512 {
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn finish(self) -> [u8; 64] {
        self.state.finish()
    }
}
