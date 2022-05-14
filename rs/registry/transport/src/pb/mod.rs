#[rustfmt::skip]
#[allow(clippy::all)]
#[path = "../../gen/ic_registry_transport.pb.v1.rs"]
pub mod v1;

use std::fmt;
use v1::registry_mutation::Type;

impl v1::RegistryMutation {
    /// Returns a string representation of the key, lossily.
    ///
    /// Despite the API specifiying keys to be &[u8], many parts of the IC
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
        let type_opt = Type::from_i32(self.mutation_type);
        let type_str = match type_opt {
            None => "unknown",
            Some(type_enum) => match type_enum {
                Type::Insert => "insert",
                Type::Update => "update",
                Type::Delete => "delete",
                Type::Upsert => "upsert",
            },
        };

        write!(f, "{}({})", type_str, self.key_as_string())
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
