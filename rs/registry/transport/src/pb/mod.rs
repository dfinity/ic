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
mod tests {
    use super::*;
    use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
    use ic_registry_keys::make_node_operator_record_key;

    fn principal(i: u64) -> PrincipalId {
        PrincipalId::try_from(format!("SID{i}").as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn registry_mutation_display() {
        assert_eq!(
            format!("{}", v1::RegistryMutation::default()),
            "RegistryMutation { mutation_type: insert, key: , value:  }"
        );

        assert_eq!(
            format!(
                "{}",
                v1::RegistryMutation {
                    mutation_type: Type::Delete as i32,
                    key: make_node_operator_record_key(principal(1)).into_bytes(),
                    value: vec![],
                }
            ),
            "RegistryMutation { mutation_type: delete, key: node_operator_record_ij6eg-jctjf-cdc, value:  }"
        );

        assert_eq!(
            format!(
                "{}",
                v1::RegistryMutation {
                    mutation_type: Type::Update as i32,
                    key: make_node_operator_record_key(principal(1)).into_bytes(),
                    value: (*TEST_USER1_PRINCIPAL).to_vec(),
                }
            ),
            "RegistryMutation { mutation_type: update, key: node_operator_record_ij6eg-jctjf-cdc, value: [178, 106, 186, 245, 220, 132, 246, 155, 74, 29, 140, 79, 172, 68, 231, 10, 94, 93, 81, 204, 109, 25, 21, 213, 213, 75, 120, 108, 2] (possibly PrincipalId: vpysv-v5snk-5plxe-e62nu-uhmmj-6wejz-yklzo-vdtdn-dek5l-vklpb-wae) }"
        );

        assert_eq!(
            format!(
                "{}",
                v1::RegistryMutation {
                    mutation_type: Type::Upsert as i32,
                    key: (200..205).collect::<Vec<u8>>(),
                    value: (205..210).collect::<Vec<u8>>(), // Short sequences of bytes can be converted into a PrincipalId
                }
            ),
            "RegistryMutation { mutation_type: upsert, key: [200, 201, 202, 203, 204], value: [205, 206, 207, 208, 209] (possibly PrincipalId: vmvli-ywnz3-h5bui) }"
        );
    }
}
