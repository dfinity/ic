#[cfg(target_arch = "x86_64")]
use rand::rngs::StdRng;
#[cfg(target_arch = "x86_64")]
use rand_core::SeedableRng;

use crate::pb::v1::{Governance, NervousSystemParameters};
use ic_base_types::{CanisterId, PrincipalId};

#[allow(dead_code)]
pub struct GovernanceCanisterInitPayloadBuilder {
    pub proto: Governance,
    voters_to_add_to_all_neurons: Vec<PrincipalId>,
    #[cfg(target_arch = "x86_64")]
    rng: StdRng,
}

#[allow(clippy::new_without_default)]
impl GovernanceCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            proto: Governance {
                parameters: Some(NervousSystemParameters::with_default_values()),
                ..Default::default()
            },
            voters_to_add_to_all_neurons: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            rng: StdRng::seed_from_u64(0),
        }
    }

    pub fn get_balance(&self) -> u64 {
        self.proto
            .neurons
            .values()
            .map(|n| n.cached_neuron_stake_e8s)
            .sum()
    }

    pub fn with_governance_proto(&mut self, proto: Governance) -> &mut Self {
        // Save the neurons from the current proto, to account for the neurons
        // possibly already crated.
        let neurons = self.proto.neurons.clone();
        self.proto = proto;
        self.proto.neurons.extend(neurons);
        self
    }

    pub fn with_ledger_canister_id(&mut self, ledger_canister_id: CanisterId) -> &mut Self {
        self.proto.ledger_canister_id = Some(ledger_canister_id.get());
        self
    }
    pub fn build(&mut self) -> Governance {
        self.proto.clone()
    }
}
