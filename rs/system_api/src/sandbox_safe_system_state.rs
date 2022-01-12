use ic_base_types::{CanisterId, PrincipalId};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterStatus, SystemState};
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

/// Tracks changes to the system state that the canister has requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStateChanges {
    pub(super) new_certified_data: Option<Vec<u8>>,
}

impl Default for SystemStateChanges {
    fn default() -> Self {
        Self {
            new_certified_data: None,
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
    pub fn apply_changes(&self, system_state: &mut SystemState) {
        if let Some(certified_data) = self.new_certified_data.as_ref() {
            assert!(certified_data.len() <= CERTIFIED_DATA_MAX_LENGTH as usize);
            system_state.certified_data = certified_data.clone();
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
}

impl SandboxSafeSystemState {
    /// Only public for use in tests.
    pub fn new_internal(
        canister_id: CanisterId,
        controller: PrincipalId,
        status: CanisterStatusView,
        subnet_type: SubnetType,
    ) -> Self {
        Self {
            canister_id,
            controller,
            status,
            subnet_type,
            system_state_changes: SystemStateChanges::default(),
        }
    }

    pub fn new(system_state: &SystemState, subnet_type: SubnetType) -> Self {
        Self::new_internal(
            system_state.canister_id,
            *system_state.controller(),
            CanisterStatusView::from_full_status(&system_state.status),
            subnet_type,
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
}
