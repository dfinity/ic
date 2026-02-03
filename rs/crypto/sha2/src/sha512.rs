use crate::DomainSeparationContext;
use sha2::Digest;

/// Hasher with fixed algorithm that is guaranteed not to change in the future
/// or across registry versions. The algorithm used to generate the hash is
/// SHA512 and therefore has constant output size of 64 bytes.
///
/// This hasher can be used, e.g., for creating fingerprints of files that are
/// persisted on disk.

#[derive(Default)]
pub struct Sha512 {
    sha512: sha2::Sha512,
}

impl Sha512 {
    /// Return a new Sha512 object
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a new Sha512 object, with the specified domain/context.
    pub fn new_with_context(context: &DomainSeparationContext) -> Self {
        let mut hash = Self::new();
        hash.write(context.as_bytes());
        hash
    }

    /// Hashes some data and returns the digest
    pub fn hash(data: &[u8]) -> [u8; 64] {
        let mut hash = Self::new();
        hash.write(data);
        hash.finish()
    }

    /// Incrementally update the current hash
    pub fn write(&mut self, data: &[u8]) {
        self.sha512.update(data);
    }

    /// Finishes computing a hash, returning the digest
    pub fn finish(self) -> [u8; 64] {
        let hash = self.sha512.finalize();
        hash.as_slice()
            .try_into()
            .expect("infallible as length is 64")
    }
}

impl std::io::Write for Sha512 {
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

impl std::hash::Hasher for Sha512 {
    /// This function will panic; use finish() -> [u8; 64] instead
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
