use crate::rosetta_tests::lib::{create_neuron, NeuronDetails};
use ic_ledger_core::Tokens;
use ic_nns_governance_api::pb::v1::Neuron;
use ic_rosetta_test_utils::EdKeypair;
use icp_ledger::AccountIdentifier;
use std::collections::{BTreeMap, HashMap};

use super::lib::create_custom_neuron;

pub(crate) struct TestNeurons<'a> {
    neurons: BTreeMap<u64, Neuron>,
    seed: u64,
    ledger_balances: &'a mut HashMap<AccountIdentifier, Tokens>,
}

impl TestNeurons<'_> {
    pub(crate) fn new(
        seed: u64,
        ledger_balances: &mut HashMap<AccountIdentifier, Tokens>,
    ) -> TestNeurons {
        TestNeurons {
            neurons: BTreeMap::default(),
            seed: seed * 100_000,
            ledger_balances,
        }
    }

    /// Add a new test neuron and return the details about created neuron.
    pub(crate) fn create(&mut self, neuron_setup: impl FnOnce(&mut Neuron)) -> NeuronDetails {
        let details = create_neuron(self.seed, neuron_setup, self.ledger_balances);
        self.neurons
            .insert(details.neuron.id.unwrap().id, details.neuron.clone());
        self.seed += 1;
        details
    }
    pub(crate) fn create_custom(
        &mut self,
        neuron_setup: impl FnOnce(&mut Neuron),
        id: u64,
        kp: &EdKeypair,
    ) -> NeuronDetails {
        let details = create_custom_neuron(id, neuron_setup, self.ledger_balances, kp);
        self.neurons
            .insert(details.neuron.id.unwrap().id, details.neuron.clone());
        self.seed += 1;
        details
    }

    /// Return the map of neurons indexed by their id.
    pub(crate) fn get_neurons(&self) -> BTreeMap<u64, Neuron> {
        self.neurons.clone()
    }
}
