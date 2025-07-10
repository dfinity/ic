use std::collections::BTreeMap;

use ic_crypto_sha2::Sha256;

/// The length of a environment variables hash in bytes.
pub const HASH_LENGTH: usize = 32;

/// Represents a set of environment variables for a canister
/// mapping environment variable names to their values.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct EnvironmentVariables {
    map: BTreeMap<String, String>,
}

impl EnvironmentVariables {
    pub fn new(environment_variables: BTreeMap<String, String>) -> Self {
        Self {
            map: environment_variables,
        }
    }

    /// Calculates the hash of environment variables as
    /// described in `hash_of_map` as specified in the public spec.
    pub fn hash(&self) -> [u8; HASH_LENGTH] {
        // Create a vector to store the hashes of key-value pairs
        let mut hashes: Vec<Vec<u8>> = Vec::new();

        // 1. For each key-value pair, hash the key and value, and concatenate the hashes.
        for (key, value) in &self.map {
            let mut key_hash = Sha256::hash(key.as_bytes()).to_vec();
            let mut value_hash = Sha256::hash(value.as_bytes()).to_vec();
            key_hash.append(&mut value_hash);
            hashes.push(key_hash);
        }
        // 2. Sort the concatenated hashes.
        hashes.sort();

        // 3. Concatenate the sorted hashes, and hash the result.
        let mut hasher = Sha256::new();
        for hash in hashes {
            hasher.write(&hash);
        }

        hasher.finish()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.map.iter()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

impl From<EnvironmentVariables> for BTreeMap<String, String> {
    fn from(environment_variables: EnvironmentVariables) -> Self {
        environment_variables.map
    }
}
