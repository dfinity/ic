use crate::external_interfaces::management::{get_canister_info, set_controllers};
use crate::processing::ProcessingResult;
use async_trait::async_trait;
use candid::Principal;
use ic_cdk::api::canister_self;
use ic_cdk::management_canister::CanisterInfoResult;
use serde::{Deserialize, Serialize};

#[async_trait]
trait InternetComputer: Send + Sync {
    fn canister_self(&self) -> Principal;

    async fn get_canister_info(
        &mut self,
        canister_id: Principal,
    ) -> ProcessingResult<CanisterInfoResult, ()>;

    async fn set_controllers(
        &mut self,
        canister_id: Principal,
        controllers: Vec<Principal>,
    ) -> ProcessingResult<(), ()>;
}

struct ProductionInternetComputer;

#[async_trait]
impl InternetComputer for ProductionInternetComputer {
    fn canister_self(&self) -> Principal {
        canister_self()
    }

    async fn get_canister_info(
        &mut self,
        canister_id: Principal,
    ) -> ProcessingResult<CanisterInfoResult, ()> {
        get_canister_info(canister_id).await
    }

    async fn set_controllers(
        &mut self,
        canister_id: Principal,
        controllers: Vec<Principal>,
    ) -> ProcessingResult<(), ()> {
        set_controllers(canister_id, controllers, Principal::management_canister()).await
    }
}

/// Represents the recovery state for controllers of either migrated or replaced.
/// Such a recovery is needed for a failed request in order to restore
/// the original controllers of migrated or replaced, respectively.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControllerRecoveryState {
    /// Controller recovery is pending and no progress has been made so far.
    NoProgress,
    /// Controller recovery has been confirmed to be necessary (the migration canister
    /// is the only controller) and the canister history has the specified
    /// number of changes in total (used to derive if controller recovery
    /// succeeded).
    TotalNumChangesBefore(u64),
    /// Controller recovery has completed (or it was not needed to be performed at all).
    Done,
}

pub async fn controller_recovery(
    state: ControllerRecoveryState,
    canister_id: Principal,
    controllers: Vec<Principal>,
) -> ControllerRecoveryState {
    controller_recovery_internal(
        &mut ProductionInternetComputer,
        state,
        canister_id,
        controllers,
    )
    .await
}

async fn controller_recovery_internal<IC: InternetComputer>(
    ic00: &mut IC,
    state: ControllerRecoveryState,
    canister_id: Principal,
    controllers: Vec<Principal>,
) -> ControllerRecoveryState {
    match state {
        ControllerRecoveryState::NoProgress => match ic00.get_canister_info(canister_id).await {
            ProcessingResult::Success(canister_info) => {
                if canister_info.controllers == vec![ic00.canister_self()] {
                    ControllerRecoveryState::TotalNumChangesBefore(canister_info.total_num_changes)
                } else {
                    // We only recover controllers if the migration canister is the exclusive controller.
                    ControllerRecoveryState::Done
                }
            }
            ProcessingResult::NoProgress => state,
            // `ProcessingResult::FatalFailure` means that the canister does not exist, and thus
            // we are (trivially) done because there is nothing to recover at this point.
            ProcessingResult::FatalFailure(()) => ControllerRecoveryState::Done,
        },
        ControllerRecoveryState::TotalNumChangesBefore(total_num_changes) => {
            match ic00.get_canister_info(canister_id).await {
                ProcessingResult::Success(canister_info) => {
                    if canister_info.total_num_changes > total_num_changes {
                        // Because the migration canister is the exclusive controller and
                        // the number of changes in canister history increased since last time,
                        // a past update call to restore controllers must have succeeded.
                        ControllerRecoveryState::Done
                    } else {
                        let res = ic00.set_controllers(canister_id, controllers.clone()).await;
                        match res {
                            ProcessingResult::Success(_) => ControllerRecoveryState::Done,
                            ProcessingResult::NoProgress => state,
                            // `ProcessingResult::FatalFailure` means that the canister does not exist, and thus
                            // we are (trivially) done because there is nothing to recover at this point.
                            ProcessingResult::FatalFailure(()) => ControllerRecoveryState::Done,
                        }
                    }
                }
                ProcessingResult::NoProgress => state,
                // `ProcessingResult::FatalFailure` means that the canister does not exist, and thus
                // we are (trivially) done because there is nothing to recover at this point.
                ProcessingResult::FatalFailure(()) => ControllerRecoveryState::Done,
            }
        }
        ControllerRecoveryState::Done => ControllerRecoveryState::Done,
    }
}

#[cfg(test)]
mod test {
    use crate::ControllerRecoveryState;
    use crate::controller_recovery::{
        InternetComputer, ProcessingResult, controller_recovery_internal,
    };
    use async_trait::async_trait;
    use candid::Principal;
    use ic_cdk::management_canister::CanisterInfoResult;
    use ic_nns_constants::MIGRATION_CANISTER_ID;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::BTreeMap;

    /// The canister ID to test recovery of.
    const CANISTER_ID: Principal =
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01]);

    struct MockInternetComputer {
        rng: StdRng,
        controllers: BTreeMap<Principal, Vec<Principal>>,
        total_num_changes: BTreeMap<Principal, u64>,
    }

    impl MockInternetComputer {
        /// If some controllers are provided, then
        /// this function creates a mock with a single `CANISTER_ID`
        /// and the given (initial) controllers.
        /// Otherwise, this function creates a mock
        /// with no canisters.
        fn new(seed: u64, controllers: Option<Vec<Principal>>) -> Self {
            let rng = StdRng::seed_from_u64(seed);
            let canister_id = CANISTER_ID;
            match controllers {
                Some(initial_controllers) => {
                    let mut controllers = BTreeMap::new();
                    controllers.insert(canister_id, initial_controllers);
                    let mut total_num_changes = BTreeMap::new();
                    total_num_changes.insert(canister_id, 0);
                    Self {
                        rng,
                        controllers,
                        total_num_changes,
                    }
                }
                None => Self {
                    rng,
                    controllers: BTreeMap::new(),
                    total_num_changes: BTreeMap::new(),
                },
            }
        }
    }

    #[async_trait]
    impl InternetComputer for MockInternetComputer {
        fn canister_self(&self) -> Principal {
            MIGRATION_CANISTER_ID.get().0
        }

        async fn get_canister_info(
            &mut self,
            canister_id: Principal,
        ) -> ProcessingResult<CanisterInfoResult, ()> {
            if self.rng.r#gen() {
                return ProcessingResult::NoProgress;
            }
            match self.controllers.get(&canister_id) {
                Some(controllers) => {
                    let canister_info = CanisterInfoResult {
                        total_num_changes: *self.total_num_changes.get(&canister_id).unwrap(),
                        recent_changes: vec![],
                        module_hash: None,
                        controllers: controllers.clone(),
                    };
                    ProcessingResult::Success(canister_info)
                }
                None => ProcessingResult::FatalFailure(()),
            }
        }

        async fn set_controllers(
            &mut self,
            canister_id: Principal,
            new_controllers: Vec<Principal>,
        ) -> ProcessingResult<(), ()> {
            if self.rng.r#gen() {
                return ProcessingResult::NoProgress;
            }
            match self.controllers.get_mut(&canister_id) {
                Some(controllers) => {
                    *controllers = new_controllers;
                    *self.total_num_changes.get_mut(&canister_id).unwrap() += 1;
                    if self.rng.r#gen() {
                        return ProcessingResult::NoProgress;
                    }
                    ProcessingResult::Success(())
                }
                None => ProcessingResult::FatalFailure(()),
            }
        }
    }

    #[tokio::test]
    async fn controller_recovery_happy_path() {
        for seed in 0..1_000_000 {
            let mut state = ControllerRecoveryState::NoProgress;
            let canister_id = CANISTER_ID;
            let new_controllers = vec![Principal::anonymous()];

            let mut ic00 =
                MockInternetComputer::new(seed, Some(vec![MIGRATION_CANISTER_ID.get().0]));

            while state != ControllerRecoveryState::Done {
                state = controller_recovery_internal(
                    &mut ic00,
                    state,
                    canister_id,
                    new_controllers.clone(),
                )
                .await;
            }

            assert_eq!(
                *ic00.controllers.get(&canister_id).unwrap(),
                new_controllers
            );
        }
    }

    #[tokio::test]
    async fn controller_recovery_not_controller() {
        for seed in 0..1_000_000 {
            let mut state = ControllerRecoveryState::NoProgress;
            let canister_id = CANISTER_ID;
            let new_controllers = vec![Principal::anonymous()];

            let mut ic00 = MockInternetComputer::new(seed, Some(vec![CANISTER_ID]));

            while state != ControllerRecoveryState::Done {
                state = controller_recovery_internal(
                    &mut ic00,
                    state,
                    canister_id,
                    new_controllers.clone(),
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn controller_recovery_canister_deleted() {
        for seed in 0..1_000_000 {
            let mut state = ControllerRecoveryState::NoProgress;
            let canister_id = CANISTER_ID;
            let new_controllers = vec![Principal::anonymous()];

            let mut ic00 = MockInternetComputer::new(seed, None);

            while state != ControllerRecoveryState::Done {
                state = controller_recovery_internal(
                    &mut ic00,
                    state,
                    canister_id,
                    new_controllers.clone(),
                )
                .await;
            }
        }
    }
}
