use crate::{
    neuron_store::NeuronStore,
    pb::v1::governance::{migration::MigrationStatus, Migration, Migrations},
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
