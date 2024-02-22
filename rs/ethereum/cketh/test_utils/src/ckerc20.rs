use crate::{new_state_machine, CkEthSetup};
use ic_ledger_suite_orchestrator::candid::InitArg as LedgerSuiteOrchestratorInitArg;
use ic_ledger_suite_orchestrator_test_utils::LedgerSuiteOrchestrator;
use ic_state_machine_tests::StateMachine;
use std::sync::Arc;

pub struct CkErc20Setup {
    pub env: Arc<StateMachine>,
    pub cketh: CkEthSetup,
    pub orchestrator: LedgerSuiteOrchestrator,
}

impl Default for CkErc20Setup {
    fn default() -> Self {
        Self::new(Arc::new(new_state_machine()))
    }
}

impl CkErc20Setup {
    pub fn new(env: Arc<StateMachine>) -> Self {
        let mut cketh = CkEthSetup::new(env.clone());
        let orchestrator = LedgerSuiteOrchestrator::new(
            env.clone(),
            LedgerSuiteOrchestratorInitArg {
                more_controller_ids: vec![],
                minter_id: Some(cketh.minter_id.get_ref().0),
            },
        );
        cketh = cketh.upgrade_minter_to_add_orchestrator_id(
            orchestrator.ledger_suite_orchestrator_id.get_ref().0,
        );
        Self {
            env,
            cketh,
            orchestrator,
        }
    }
}
