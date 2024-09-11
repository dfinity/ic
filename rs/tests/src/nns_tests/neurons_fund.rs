use candid::Principal;
use ic_agent::{agent::EnvelopeContent, Identity, Signature};
use ic_base_types::PrincipalId;
use ic_canister_client_sender::ed25519_public_key_to_der;
use ic_icrc1_test_utils::KeyPairGenerator;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::pb::v1::{neuron::DissolveState, Neuron};
use ic_rosetta_test_utils::EdKeypair;
use ic_system_test_driver::{
    canister_agent::HasCanisterAgentCapability,
    canister_api::{CallMode, NnsRequestProvider},
};
use icp_ledger::Subaccount;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rosetta_core::models::RosettaSupportedKeyPair;

/// Deterministically generates NNS neurons that have joined the Neurons' Fund (NF).
/// As long as at least one neuron is in the NF, the NF will contribute to the SNS.
///
/// These neurons are suitable to inject into the NNS at NNS creation time, to test
/// that the NF works properly
pub fn initial_nns_neurons(maturity_e8s: u64, amount: u64) -> Vec<NnsNfNeuron> {
    let mut rng = ChaChaRng::seed_from_u64(2000_u64);
    (0..amount)
        .map(|_| initial_nns_neuron(maturity_e8s, &mut rng))
        .collect()
}

fn initial_nns_neuron(maturity_e8s: u64, rng: &mut ChaChaRng) -> NnsNfNeuron {
    const TWELVE_MONTHS_SECONDS: u64 = 12 * 30 * 24 * 60 * 60;

    let (key_pair, principal, id, account) = nns_neuron_info(rng);

    let id = Some(id);

    NnsNfNeuron {
        neuron: Neuron {
            id,
            account: account.into(),
            maturity_e8s_equivalent: maturity_e8s,
            cached_neuron_stake_e8s: 0,
            controller: Some(principal),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
            not_for_profit: false,
            // Join the neurons' fund some time in the past.
            // (It's unclear what the semantics should be if the neuron joins in the
            // future.)
            joined_community_fund_timestamp_seconds: Some(1000),
            ..Default::default()
        },
        controller_identity: key_pair,
    }
}

fn nns_neuron_info(rng: &mut ChaChaRng) -> (EdKeypair, PrincipalId, NeuronId, Subaccount) {
    let seed = rng.next_u64();
    let key_pair: EdKeypair = EdKeypair::generate(seed);
    let principal_id = key_pair.generate_principal_id().unwrap();

    let id = NeuronId { id: rng.next_u64() };
    let account = {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    };
    (key_pair, principal_id, id, account)
}

#[derive(Clone, PartialEq, Debug)]
pub struct NnsNfNeuron {
    pub neuron: Neuron,
    pub controller_identity: EdKeypair,
}

impl Identity for NnsNfNeuron {
    fn sender(&self) -> Result<Principal, String> {
        let principal = Principal::from(self.controller_identity.generate_principal_id().unwrap());
        Ok(principal)
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        let pk = self.controller_identity.get_pb_key();
        Some(ed25519_public_key_to_der(pk))
    }
    fn sign(&self, msg: &EnvelopeContent) -> Result<Signature, String> {
        self.sign_arbitrary(&msg.to_request_id().signable())
    }
    fn sign_arbitrary(&self, msg: &[u8]) -> Result<Signature, String> {
        let signature = self.controller_identity.sign(msg.as_ref());
        Ok(Signature {
            signature: Some(signature),
            public_key: self.public_key(),
            delegations: None,
        })
    }
}

impl NnsNfNeuron {
    pub async fn get_current_info(
        &self,
        nns_node: &ic_system_test_driver::driver::test_env_api::IcNodeSnapshot,
        nns_request_provider: &NnsRequestProvider,
    ) -> Result<Neuron, String> {
        let neuron_id = self.neuron.id.as_ref().unwrap().id;
        let nns_agent = nns_node
            .build_canister_agent_with_identity(self.clone())
            .await;
        let request = nns_request_provider.list_neurons(vec![neuron_id], false, CallMode::Query);
        let neuron = nns_agent
            .call_and_parse(&request)
            .await
            .result()
            .map_err(|err| err.to_string())?
            .full_neurons
            .into_iter()
            .next()
            .ok_or_else(|| format!("no neurons owned by {neuron_id}"))?;
        Ok(neuron)
    }
}
