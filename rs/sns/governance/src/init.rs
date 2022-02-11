#[cfg(target_arch = "x86_64")]
use crate::pb::v1::neuron::DissolveState;
#[cfg(target_arch = "x86_64")]
use ledger_canister::Subaccount;
#[cfg(target_arch = "x86_64")]
use rand::rngs::StdRng;
#[cfg(target_arch = "x86_64")]
use rand_core::{RngCore, SeedableRng};

use crate::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronId, NeuronPermission, NeuronPermissionType,
};
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

    #[cfg(not(target_arch = "x86_64"))]
    pub fn new_neuron_id(&mut self) -> NeuronId {
        unimplemented!("Not implemented for non-x86_64");
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

    #[cfg(target_arch = "x86_64")]
    pub fn make_subaccount(&mut self) -> Subaccount {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    }

    /// Initializes the governance canister with a few neurons to be used
    /// in tests.
    #[cfg(target_arch = "x86_64")]
    pub fn with_test_neurons(&mut self) -> &mut Self {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;
        use ic_nns_constants::ids::{
            TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
            TEST_NEURON_3_OWNER_PRINCIPAL,
        };
        let subaccount: Subaccount = self.make_subaccount();
        let neuron_id = NeuronId::from(subaccount);
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    permissions: vec![NeuronPermission {
                        principal: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                        permission_type: vec![
                            NeuronPermissionType::ManagePrincipals as i32,
                            NeuronPermissionType::Disburse as i32,
                            NeuronPermissionType::ManageMaturity as i32,
                        ]
                    }],
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 1_000_000_000, /* invariant: part of
                                                             * TEST_NEURON_TOTAL_STAKE_E8S */
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let subaccount: Subaccount = self.make_subaccount();
        let neuron_id = NeuronId::from(subaccount);
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    permissions: vec![NeuronPermission {
                        principal: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                        permission_type: vec![NeuronPermissionType::ManagePrincipals as i32]
                    }],
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 100_000_000, /* invariant: part of
                                                           * TEST_NEURON_TOTAL_STAKE_E8S */
                    created_timestamp_seconds: 1,
                    aging_since_timestamp_seconds: 1,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let subaccount: Subaccount = self.make_subaccount();
        let neuron_id = NeuronId::from(subaccount);
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    permissions: vec![NeuronPermission {
                        principal: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
                        permission_type: vec![NeuronPermissionType::ManagePrincipals as i32]
                    }],
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 10_000_000, /* invariant: part of
                                                          * TEST_NEURON_TOTAL_STAKE_E8S */
                    created_timestamp_seconds: 10,
                    aging_since_timestamp_seconds: 10,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        self
    }

    pub fn build(&mut self) -> Governance {
        self.proto.clone()
    }
}
