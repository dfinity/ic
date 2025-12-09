#[allow(clippy::all)]
#[path = "../gen/ic_registry_transport.pb.v1.rs"]
mod generated_by_prost;
mod non_high_capacity_legacy_types;

pub mod v1 {
    pub use super::generated_by_prost::*;
    pub use super::non_high_capacity_legacy_types::*;
}

use ic_base_types::PrincipalId;
use std::fmt;
use v1::registry_mutation::Type;

impl v1::RegistryMutation {
    /// Returns a string representation of the key, lossily.
    ///
    /// Despite the API specifying keys to be &[u8], many parts of the IC
    /// assume that they are strings, so the "lossy" should never actually
    /// kick in.
    pub fn key_as_string(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.key.as_slice())
    }
}

impl fmt::Display for v1::RegistryMutation {
    /// Produces a string that shows the key being mutated and the type of
    /// mutation, but not the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_opt = Type::try_from(self.mutation_type).ok();
        let type_str = match type_opt {
            None => "unknown",
            Some(type_enum) => match type_enum {
                Type::Insert => "insert",
                Type::Update => "update",
                Type::Delete => "delete",
                Type::Upsert => "upsert",
            },
        };

        write!(
            f,
            "RegistryMutation {{ mutation_type: {}, key: {}, value: {} }}",
            type_str,
            match String::from_utf8(self.key.clone()) {
                Ok(key) => key,
                Err(_) => format!("{:?}", self.key),
            },
            match String::from_utf8(self.value.clone()) {
                Ok(value) => value,
                Err(_) => {
                    // Any sequence of up to 29 bytes can be converted into a PrincipalId, so we also print raw bytes
                    match PrincipalId::try_from(&self.value) {
                        Ok(principal) => {
                            format!("{:?} (possibly PrincipalId: {})", self.value, principal)
                        }
                        Err(_) => format!("{:?}", self.value),
                    }
                }
            },
        )
    }
}

impl fmt::Display for v1::RegistryAtomicMutateRequest {
    /// Produces a string that shows the keys being mutated and the type of
    /// mutations, but not the values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegistryAtomicMutateRequest{{ mutations: [{}], preconditions on keys: [{}] }}",
            self.mutations
                .iter()
                .map(v1::RegistryMutation::to_string)
                .collect::<Vec::<String>>()
                .join(", "),
            self.preconditions
                .iter()
                .map(|p| String::from_utf8_lossy(&p.key).to_string())
                .collect::<Vec::<String>>()
                .join(", ")
        )
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
