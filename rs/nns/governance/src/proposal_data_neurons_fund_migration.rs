use crate::pb::v1::{
    neurons_fund_snapshot::{self, NeuronsFundNeuronPortion},
    NeuronsFundAuditInfo, NeuronsFundData, NeuronsFundParticipation, NeuronsFundSnapshot,
    ProposalData,
};

impl ProposalData {
    pub fn migrate(self) -> ProposalData {
        ProposalData {
            neurons_fund_data: self
                .neurons_fund_data
                .map(|neurons_fund_data| neurons_fund_data.migrate()),
            ..self
        }
    }
}

impl NeuronsFundData {
    pub fn migrate(self) -> NeuronsFundData {
        NeuronsFundData {
            initial_neurons_fund_participation: self
                .initial_neurons_fund_participation
                .map(NeuronsFundParticipation::migrate),
            final_neurons_fund_participation: self
                .final_neurons_fund_participation
                .map(NeuronsFundParticipation::migrate),
            neurons_fund_refunds: self.neurons_fund_refunds.map(NeuronsFundSnapshot::migrate),
        }
    }
}

impl NeuronsFundAuditInfo {
    pub fn migrate(self) -> NeuronsFundAuditInfo {
        NeuronsFundAuditInfo {
            initial_neurons_fund_participation: self
                .initial_neurons_fund_participation
                .map(NeuronsFundParticipation::migrate),
            final_neurons_fund_participation: self
                .final_neurons_fund_participation
                .map(NeuronsFundParticipation::migrate),
            neurons_fund_refunds: self.neurons_fund_refunds.map(NeuronsFundSnapshot::migrate),
        }
    }
}

impl NeuronsFundParticipation {
    pub fn migrate(self) -> NeuronsFundParticipation {
        NeuronsFundParticipation {
            ideal_matched_participation_function: self.ideal_matched_participation_function,
            neurons_fund_reserves: self.neurons_fund_reserves.map(NeuronsFundSnapshot::migrate),
            ..self
        }
    }
}

impl NeuronsFundSnapshot {
    pub fn migrate(self) -> NeuronsFundSnapshot {
        NeuronsFundSnapshot {
            neurons_fund_neuron_portions: self
                .neurons_fund_neuron_portions
                .into_iter()
                .map(NeuronsFundNeuronPortion::migrate)
                .collect(),
        }
    }
}

impl neurons_fund_snapshot::NeuronsFundNeuronPortion {
    #[allow(deprecated)] // hotkey_principal is deprecated to make sure we don't accidentally use it.
    pub fn migrate(self) -> NeuronsFundNeuronPortion {
        NeuronsFundNeuronPortion {
            controller: self.controller.or(self.hotkey_principal), // <- Actual meat of the migration.
            ..self
        }
    }
}
