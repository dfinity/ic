use candid::Principal;
use ic_agent::{Identity, Signature};
use ic_base_types::PrincipalId;
use ic_canister_client_sender::ed25519_public_key_to_der;
use ic_nervous_system_common::E8;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::{neuron::DissolveState, Neuron};
use ic_rosetta_api::models::RosettaSupportedKeyPair;
use ic_rosetta_test_utils::EdKeypair;
use icp_ledger::Subaccount;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

use crate::{
    canister_agent::HasCanisterAgentCapability,
    canister_api::{CallMode, NnsRequestProvider},
    driver::{test_env::TestEnv, test_env_api::GetFirstHealthyNodeSnapshot},
};

/// Deterministically generates an NNS neuron that's joined the community fund (CF).
/// As long as at least one neuron is in the CF, the CF will contribute to the SNS.
///
/// This neuron is suitable to inject into the NNS at NNS creation time, to test
/// that the NF works properly
pub fn initial_nns_neuron(contribution: u64) -> NnsNfNeuron {
    const TWELVE_MONTHS_SECONDS: u64 = 12 * 30 * 24 * 60 * 60;

    let (key_pair, principal, id, account) = nns_neuron_info();

    let id = Some(id);

    NnsNfNeuron {
        neuron: Neuron {
            id,
            account: account.into(),
            maturity_e8s_equivalent: contribution,
            cached_neuron_stake_e8s: E8,
            controller: Some(principal),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
            not_for_profit: false,
            // Join the community fund some time in the past.
            // (It's unclear what the semantics should be if the neuron joins in the
            // future.)
            joined_community_fund_timestamp_seconds: Some(1000),
            ..Default::default()
        },
        controller_identity: key_pair,
    }
}

fn nns_neuron_info() -> (EdKeypair, PrincipalId, NeuronId, Subaccount) {
    let key_pair: EdKeypair = EdKeypair::generate_from_u64(2000);
    let principal_id = key_pair.generate_principal_id().unwrap();

    let mut rng = ChaChaRng::seed_from_u64(2000_u64);

    let id = NeuronId { id: rng.next_u64() };
    let account = {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    };
    (key_pair, principal_id, id, account)
}

pub async fn get_current_nns_neuron_info(env: &TestEnv) -> Result<Neuron, String> {
    let nns_neuron = initial_nns_neuron(
        0, // The contribution doesn't matter for our purposes
    );
    let neuron_id = nns_neuron.neuron.id.as_ref().unwrap().id;

    let nns_request_provider = NnsRequestProvider::default();
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let nns_agent = nns_node
        .build_canister_agent_with_identity(nns_neuron)
        .await;

    let list_neurons_response = {
        let request = nns_request_provider.list_neurons(vec![neuron_id], false, CallMode::Update);
        nns_agent.call_and_parse(&request).await.result().unwrap()
    };

    list_neurons_response
        .full_neurons
        .into_iter()
        .next()
        .ok_or("neuron not found or access denied".to_string())
}

#[derive(Clone, Debug, PartialEq)]
pub struct NnsNfNeuron {
    pub neuron: Neuron,
    pub controller_identity: EdKeypair,
}

impl Identity for NnsNfNeuron {
    fn sender(&self) -> Result<Principal, String> {
        let principal = Principal::from(self.controller_identity.generate_principal_id().unwrap());
        Ok(principal)
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let signature = self.controller_identity.sign(msg.as_ref());
        let pk = self.controller_identity.get_pb_key();
        let pk_der = ed25519_public_key_to_der(pk);
        Ok(Signature {
            signature: Some(signature.as_ref().to_vec()),
            public_key: Some(pk_der),
        })
    }
}
