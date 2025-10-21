use crate::{HASH_LENGTH, hash_of_map};
use ic_crypto_sha2::Sha256;
use std::collections::BTreeMap;

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
        hash_of_map(&self.map, |key, value| {
            let mut key_hash = Sha256::hash(key.as_bytes()).to_vec();
            let mut value_hash = Sha256::hash(value.as_bytes()).to_vec();
            key_hash.append(&mut value_hash);
            key_hash
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.map.iter()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl From<EnvironmentVariables> for BTreeMap<String, String> {
    fn from(environment_variables: EnvironmentVariables) -> Self {
        environment_variables.map
    }
}
