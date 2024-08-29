use crate::{
    neuron_store::NeuronStore,
    pb::v1::{
        governance::{migration::MigrationStatus, Migration, Migrations},
        neurons_fund_snapshot::{self, NeuronsFundNeuronPortion},
        NeuronsFundAuditInfo, NeuronsFundData, NeuronsFundParticipation, NeuronsFundSnapshot,
        ProposalData,
    },
};

impl MigrationStatus {
    pub fn is_terminal(self) -> bool {
        match self {
            Self::Unspecified | Self::InProgress => false,
            Self::Succeeded | Self::Failed => true,
        }
    }
}

impl Migration {
    pub fn migration_status(&self) -> MigrationStatus {
        self.status
            .and_then(|v| MigrationStatus::try_from(v).ok())
            .unwrap_or_default()
    }
}

pub(crate) fn maybe_run_migrations(
    migrations: Migrations,
    _neuron_store: &mut NeuronStore,
) -> Migrations {
    // TODO: move inactive neuron migration here.
    migrations
}

impl NeuronsFundData {
    pub fn into_current(self) -> NeuronsFundData {
        NeuronsFundData {
            initial_neurons_fund_participation: self
                .initial_neurons_fund_participation
                .map(|participation| participation.into_current()),
            final_neurons_fund_participation: self
                .final_neurons_fund_participation
                .map(|participation| participation.into_current()),
            neurons_fund_refunds: self
                .neurons_fund_refunds
                .map(|snapshot| snapshot.into_current()),
        }
    }
}

impl ProposalData {
    pub fn into_current(self) -> ProposalData {
        ProposalData {
            neurons_fund_data: self
                .neurons_fund_data
                .map(|neurons_fund_data| neurons_fund_data.into_current()),
            ..self
        }
    }
}

impl NeuronsFundAuditInfo {
    pub fn into_current(self) -> NeuronsFundAuditInfo {
        NeuronsFundAuditInfo {
            initial_neurons_fund_participation: self
                .initial_neurons_fund_participation
                .map(|participation| participation.into_current()),
            final_neurons_fund_participation: self
                .final_neurons_fund_participation
                .map(|participation| participation.into_current()),
            neurons_fund_refunds: self
                .neurons_fund_refunds
                .map(|snapshot| snapshot.into_current()),
        }
    }
}

impl NeuronsFundParticipation {
    pub fn into_current(self) -> NeuronsFundParticipation {
        NeuronsFundParticipation {
            ideal_matched_participation_function: self.ideal_matched_participation_function,
            neurons_fund_reserves: self
                .neurons_fund_reserves
                .map(|snapshot| snapshot.into_current()),
            swap_participation_limits: self.swap_participation_limits,
            direct_participation_icp_e8s: self.direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s: self.total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s: self
                .max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s: self
                .intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s: self
                .allocated_neurons_fund_participation_icp_e8s,
        }
    }
}

impl NeuronsFundSnapshot {
    pub fn into_current(self) -> NeuronsFundSnapshot {
        NeuronsFundSnapshot {
            neurons_fund_neuron_portions: self
                .neurons_fund_neuron_portions
                .into_iter()
                .map(|portion| portion.into_current())
                .collect(),
        }
    }
}

impl neurons_fund_snapshot::NeuronsFundNeuronPortion {
    #[allow(deprecated)] // hotkey_principal is deprecated to make sure we don't accidentally use it.
    pub fn into_current(self) -> NeuronsFundNeuronPortion {
        NeuronsFundNeuronPortion {
            nns_neuron_id: self.nns_neuron_id,
            amount_icp_e8s: self.amount_icp_e8s,
            maturity_equivalent_icp_e8s: self.maturity_equivalent_icp_e8s,
            is_capped: self.is_capped,
            controller: self.controller.or(self.hotkey_principal),
            hotkeys: self.hotkeys,
            hotkey_principal: self.hotkey_principal,
        }
    }
}
