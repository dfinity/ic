use crate::governance::Governance;

use async_trait::async_trait;
use ic_nervous_system_recurring_task::PeriodicAsyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};
#[cfg(not(feature = "tla"))]
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;
#[cfg(feature = "tla")]
mod tla_ledger;
#[cfg(feature = "tla")]
use tla_ledger::LoggingIcpLedgerCanister as IcpLedgerCanister;


#[derive(Clone)]
pub(super) struct SpawnNeuronsTask {
    governance: &'static LocalKey<RefCell<Governance>>,

}

impl SpawnNeuronsTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

#[async_trait]
impl PeriodicAsyncTask for SpawnNeuronsTask {
    async fn execute(self) {
        Governance::maybe_spawn_neurons(self.governance, ledger)
        self.governance
            .with_borrow_mut(|governance| governance.maybe_spawn_neurons())
            .await
    }

    const NAME: &'static str = "SpawnNeurons";
    const INTERVAL: Duration = Duration::from_secs(60);
}
