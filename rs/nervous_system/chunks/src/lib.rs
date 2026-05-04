use ic_crypto_sha2::Sha256;
use ic_stable_structures::{Memory, StableBTreeMap};

pub mod test_data;

const CHUNK_SIZE_BYTES: usize = 1_800_000;

/// Splits "monolithic" blobs into chunks, and stores the chunks. Chunks are
/// keyed by their SHA256.
///
/// Deleting is not supported (because there seems to be no need, but could be
/// added later).
///
/// Since chunks are keyed by their SHA256, modifying elements does not make sense.
///
/// This is backed by ic_stable_structures::Memory; thus, making it suitable for
/// use with stable memory.
pub struct Chunks<MyMemory: Memory> {
    chunk_sha256_to_content: StableBTreeMap<Vec<u8>, Vec<u8>, MyMemory>,
}

impl<MyMemory: Memory> Chunks<MyMemory> {
    /// Like StableBTreeMap::init.
    pub fn init(memory: MyMemory) -> Self {
        Self {
            chunk_sha256_to_content: StableBTreeMap::init(memory),
        }
    }

    /// Returns the SHA256s of the chunks, which are the keys of the chunks.
    ///
    /// The chunks can be fetched via the `get` method. (Ofc, when you
    /// concatenate the chunks, you get back the original monolithic blob.)
    pub fn upsert_monolithic_blob(&mut self, mut monolithic_blob: Vec<u8>) -> Vec<Vec<u8>> {
        let mut result = vec![];

        // Split monolithic blob into chunks, and insert them into self.chunk_sha256_to_content.
        while !monolithic_blob.is_empty() {
            let next_chunk_size = std::cmp::min(CHUNK_SIZE_BYTES, monolithic_blob.len());
            let chunk = monolithic_blob
                .drain(..next_chunk_size)
                .collect::<Vec<u8>>();
            let sha256 = Sha256::hash(&chunk).to_vec();

            let _old_content = self.chunk_sha256_to_content.insert(sha256.clone(), chunk);

            result.push(sha256);
        }

        result
    }

    /// Returns the chunk whose SHA256 is key.
    ///
    /// By "chunk", we here mean a slice of a monolithic blob that was
    /// previously stored via upsert_monolithic_blob.
    pub fn get_chunk(&self, key: &Vec<u8>) -> Option<Vec<u8>> {
        self.chunk_sha256_to_content.get(key)
    }
}

#[cfg(test)]
mod tests;
