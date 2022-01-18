use ic_base_types::{CanisterId, PrincipalId};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterStatus, SystemState};
use ic_types::{messages::CallbackId, methods::Callback};
use serde::{Deserialize, Serialize};

use crate::CERTIFIED_DATA_MAX_LENGTH;

/// The information that canisters can see about their own status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CanisterStatusView {
    Running,
    Stopping,
    Stopped,
}

impl CanisterStatusView {
    pub fn from_full_status(full_status: &CanisterStatus) -> Self {
        match full_status {
            CanisterStatus::Running { .. } => Self::Running,
            CanisterStatus::Stopping { .. } => Self::Stopping,
            CanisterStatus::Stopped => Self::Stopped,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallbackUpdate {
    Register(CallbackId, Callback),
    Unregister(CallbackId),
}

/// Tracks changes to the system state that the canister has requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStateChanges {
    pub(super) new_certified_data: Option<Vec<u8>>,
    pub(super) callback_updates: Vec<CallbackUpdate>,
}

impl Default for SystemStateChanges {
    fn default() -> Self {
        Self {
            new_certified_data: None,
            callback_updates: vec![],
        }
    }
}

impl SystemStateChanges {
    /// Verify that the changes to the system state are sound and apply them to
    /// the system state if they are.
    ///
    /// # Panic
    ///
    /// This will panic if the changes are invalid. That could indicate that a
    /// canister has broken out of wasmtime.
    pub fn apply_changes(self, system_state: &mut SystemState) {
        if let Some(certified_data) = self.new_certified_data.as_ref() {
            assert!(certified_data.len() <= CERTIFIED_DATA_MAX_LENGTH as usize);
            system_state.certified_data = certified_data.clone();
        }
        for update in self.callback_updates {
            match update {
                CallbackUpdate::Register(expected_id, callback) => {
                    let id = system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .register_callback(callback);
                    assert_eq!(id, expected_id);
                }
                CallbackUpdate::Unregister(callback_id) => {
                    let _callback = system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .unregister_callback(callback_id)
                        .expect("Tried to unregister callback with an id that isn't in use");
                }
            }
        }
    }
}

/// A version of the `SystemState` that can be used in a sandboxed process.
/// Changes are separately tracked so that we can verify the changes are valid
/// before applying them to the actual system state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSafeSystemState {
    pub(super) canister_id: CanisterId,
    pub(super) controller: PrincipalId,
    pub(super) status: CanisterStatusView,
    pub(super) subnet_type: SubnetType,
    pub(super) system_state_changes: SystemStateChanges,
    // None indicates that we are in a context where the canister cannot
    // register callbacks (e.g. running the `start` method when installing a
    // canister.)
    next_callback_id: Option<u64>,
}

impl SandboxSafeSystemState {
    /// Only public for use in tests.
    pub fn new_internal(
        canister_id: CanisterId,
        controller: PrincipalId,
        status: CanisterStatusView,
        subnet_type: SubnetType,
        next_callback_id: Option<u64>,
    ) -> Self {
        Self {
            canister_id,
            controller,
            status,
            subnet_type,
            system_state_changes: SystemStateChanges::default(),
            next_callback_id,
        }
    }

    pub fn new(system_state: &SystemState, subnet_type: SubnetType) -> Self {
        Self::new_internal(
            system_state.canister_id,
            *system_state.controller(),
            CanisterStatusView::from_full_status(&system_state.status),
            subnet_type,
            system_state
                .call_context_manager()
                .map(|c| c.next_callback_id()),
        )
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn changes(self) -> SystemStateChanges {
        self.system_state_changes
    }

    pub fn take_changes(&mut self) -> SystemStateChanges {
        std::mem::take(&mut self.system_state_changes)
    }

    pub(super) fn register_callback(&mut self, callback: Callback) -> HypervisorResult<CallbackId> {
        match &mut self.next_callback_id {
            Some(next_callback_id) => {
                *next_callback_id += 1;
                let id = CallbackId::from(*next_callback_id);
                self.system_state_changes
                    .callback_updates
                    .push(CallbackUpdate::Register(id, callback));
                Ok(id)
            }
            None => Err(HypervisorError::ContractViolation(
                "Tried to register a callback in a context where it isn't allowed.".to_string(),
            )),
        }
    }

    pub(super) fn unregister_callback(&mut self, id: CallbackId) {
        self.system_state_changes
            .callback_updates
            .push(CallbackUpdate::Unregister(id))
    }
}
