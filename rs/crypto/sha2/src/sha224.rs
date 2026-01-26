use sha2::Digest;

/// Hasher with fixed algorithm that is guaranteed not to change in the future
/// or across registry versions. The algorithm used to generate the hash is
/// SHA224 and therefore has constant output size of 28 bytes.
///
/// This hasher can be used, e.g., for creating fingerprints of files that are
/// persisted on disk.

#[derive(Default)]
pub struct Sha224 {
    sha224: sha2::Sha224,
}

impl Sha224 {
    /// Return a new Sha224 object
    pub fn new() -> Self {
        Self::default()
    }

    /// Hashes some data and returns the digest
    pub fn hash(data: &[u8]) -> [u8; 28] {
        let mut hash = Self::new();
        hash.write(data);
        hash.finish()
    }

    /// Incrementally update the current hash
    pub fn write(&mut self, data: &[u8]) {
        self.sha224.update(data);
    }

    /// Finishes computing a hash, returning the digest
    pub fn finish(self) -> [u8; 28] {
        self.sha224.finalize().into()
    }
}

impl std::io::Write for Sha224 {
    /// Update an incremental hash
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write(buf);
        Ok(buf.len())
    }

    /// This is a no-op
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::hash::Hasher for Sha224 {
    /// This function will panic; use finish() -> [u8; 28] instead
    fn finish(&self) -> u64 {
        panic!(
            "not supported because the hash values produced by this hasher \
             contain more than just the 64 bits returned by this method"
        )
    }

    /// Update an incremental hash
    fn write(&mut self, bytes: &[u8]) {
        self.write(bytes)
    }
}
