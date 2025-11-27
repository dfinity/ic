use crate::pb::v1::{
    Governance, NervousSystemParameters, Neuron,
    governance::{Mode, SnsMetadata},
};
use ic_base_types::PrincipalId;
use std::collections::BTreeMap;

pub struct GovernanceCanisterInitPayloadBuilder {
    pub proto: Governance,
}

#[allow(clippy::new_without_default)]
impl GovernanceCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            proto: Governance {
                parameters: Some(NervousSystemParameters::with_default_values()),
                mode: Mode::PreInitializationSwap as i32,
                sns_metadata: Some(SnsMetadata {
                    logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
                    name: Some("ServiceNervousSystemTest".to_string()),
                    url: Some("https://internetcomputer.org".to_string()),
                    description: Some("Launch an SNS Project".to_string()),
                }),
                ..Default::default()
            },
        }
    }

    pub fn get_balance(&self) -> u64 {
        self.proto
            .neurons
            .values()
            .map(|n| n.cached_neuron_stake_e8s)
            .sum()
    }

    pub fn with_ledger_canister_id(&mut self, ledger_canister_id: PrincipalId) -> &mut Self {
        self.proto.ledger_canister_id = Some(ledger_canister_id);
        self
    }

    pub fn with_root_canister_id(&mut self, root_canister_id: PrincipalId) -> &mut Self {
        self.proto.root_canister_id = Some(root_canister_id);
        self
    }

    pub fn with_swap_canister_id(&mut self, swap_canister_id: PrincipalId) -> &mut Self {
        self.proto.swap_canister_id = Some(swap_canister_id);
        self
    }

    pub fn with_mode(&mut self, mode: Mode) -> &mut Self {
        self.proto.set_mode(mode);
        self
    }

    pub fn with_parameters(&mut self, parameters: NervousSystemParameters) -> &mut Self {
        self.proto.parameters = Some(parameters);
        self
    }

    pub fn with_neurons(&mut self, neurons: BTreeMap<String, Neuron>) -> &mut Self {
        self.proto.neurons = neurons;
        self
    }

    pub fn with_sns_metadata(&mut self, sns_metadata: SnsMetadata) -> &mut Self {
        self.proto.sns_metadata = Some(sns_metadata);
        self
    }

    pub fn with_genesis_timestamp_seconds(&mut self, genesis_timestamp_seconds: u64) -> &mut Self {
        self.proto.genesis_timestamp_seconds = genesis_timestamp_seconds;
        self
    }

    pub fn build(&mut self) -> Governance {
        self.proto.clone()
    }
}
