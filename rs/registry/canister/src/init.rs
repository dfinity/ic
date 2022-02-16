use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use std::fmt;

#[derive(candid::CandidType, candid::Deserialize, Clone, Debug, Default)]
pub struct RegistryCanisterInitPayload {
    pub mutations: Vec<RegistryAtomicMutateRequest>,
}

impl fmt::Display for RegistryCanisterInitPayload {
    /// Produces a string that partly represent the content of this init
    /// payload.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mutations: [{}]",
            self.mutations
                .iter()
                .map(RegistryAtomicMutateRequest::to_string)
                .collect::<Vec::<String>>()
                .join(", ")
        )
    }
}

pub struct RegistryCanisterInitPayloadBuilder {
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
}

#[allow(clippy::new_without_default)]
impl RegistryCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            initial_mutations: Vec::new(),
        }
    }

    pub fn push_init_mutate_request(
        &mut self,
        mutate_req: RegistryAtomicMutateRequest,
    ) -> &mut Self {
        self.initial_mutations.push(mutate_req);
        self
    }

    pub fn build(&self) -> RegistryCanisterInitPayload {
        RegistryCanisterInitPayload {
            mutations: self.initial_mutations.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default_payload_has_no_mutations() {
        let default = RegistryCanisterInitPayloadBuilder::new().build();
        assert_eq!(default.mutations, vec![]);
    }
}
