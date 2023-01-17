use crate::rosetta_tests::lib::{create_neuron, NeuronDetails};
use ic_ledger_core::Tokens;
use ic_nns_governance::pb::v1::Neuron;
use icp_ledger::AccountIdentifier;
use std::collections::HashMap;

pub(crate) struct TestNeurons<'a> {
    neurons: HashMap<u64, Neuron>,
    seed: u64,
    ledger_balances: &'a mut HashMap<AccountIdentifier, Tokens>,
}

impl TestNeurons<'_> {
    pub(crate) fn new(
        seed: u64,
        ledger_balances: &mut HashMap<AccountIdentifier, Tokens>,
    ) -> TestNeurons {
        TestNeurons {
            neurons: HashMap::default(),
            seed: seed * 100_000,
            ledger_balances,
        }
    }

    /// Add a new test neuron and return the details about created neuron.
    pub(crate) fn create(&mut self, neuron_setup: impl FnOnce(&mut Neuron)) -> NeuronDetails {
        let details = create_neuron(self.seed, neuron_setup, self.ledger_balances);
        self.neurons.insert(
            details.neuron.id.clone().unwrap().id,
            details.neuron.clone(),
        );
        self.seed += 1;
        details
    }

    /// Return the map of neurons indexed by their id.
    pub(crate) fn get_neurons(&self) -> HashMap<u64, Neuron> {
        self.neurons.clone()
    }
}
