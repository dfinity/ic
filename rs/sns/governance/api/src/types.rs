use crate::pb::v1::{
    governance_error::ErrorType, manage_neuron_response, GovernanceError, ManageNeuronResponse,
    NeuronId, NeuronPermission, NeuronPermissionType, VotingRewardsParameters,
};
use ic_base_types::PrincipalId;
use strum::IntoEnumIterator;

use std::fmt;

impl fmt::Display for crate::pb::v1::GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_type, self.error_message)
    }
}

impl std::error::Error for crate::pb::v1::GovernanceError {}

impl fmt::Display for NeuronId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.id))
    }
}

pub(crate) type Subaccount = [u8; 32];
impl NeuronId {
    pub fn subaccount(&self) -> Result<Subaccount, GovernanceError> {
        match Subaccount::try_from(self.id.as_slice()) {
            Ok(subaccount) => Ok(subaccount),
            Err(e) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidNeuronId,
                format!("Could not convert NeuronId to Subaccount {}", e),
            )),
        }
    }
}
impl From<Subaccount> for NeuronId {
    fn from(subaccount: Subaccount) -> Self {
        NeuronId {
            id: subaccount.to_vec(),
        }
    }
}

impl GovernanceError {
    pub fn new_with_message(error_type: ErrorType, message: impl ToString) -> Self {
        GovernanceError {
            error_type: error_type as i32,
            error_message: message.to_string(),
        }
    }
}

impl VotingRewardsParameters {
    pub fn with_default_values() -> Self {
        Self {
            round_duration_seconds: Some(ic_nervous_system_common::ONE_DAY_SECONDS),
            reward_rate_transition_duration_seconds: Some(0),
            initial_reward_rate_basis_points: Some(0),
            final_reward_rate_basis_points: Some(0),
        }
    }
}

impl NeuronPermissionType {
    /// Returns all the different types of neuron permissions as a vector.
    pub fn all() -> Vec<i32> {
        NeuronPermissionType::iter()
            .map(|permission| permission as i32)
            .collect()
    }
}

impl ManageNeuronResponse {
    pub fn expect(self, msg: &str) -> Self {
        if let Some(manage_neuron_response::Command::Error(err)) = &self.command {
            panic!("{}: {}", msg, err);
        }
        self
    }
}

impl NeuronPermission {
    pub fn new(principal: &PrincipalId, permissions: Vec<i32>) -> NeuronPermission {
        NeuronPermission {
            principal: Some(*principal),
            permission_type: permissions,
        }
    }
}

impl From<icrc_ledger_types::icrc1::account::Account> for crate::pb::v1::Account {
    fn from(account: icrc_ledger_types::icrc1::account::Account) -> Self {
        let maybe_subaccount_pb = account
            .subaccount
            .map(|subaccount| crate::pb::v1::Subaccount {
                subaccount: subaccount.into(),
            });
        crate::pb::v1::Account {
            owner: Some(account.owner.into()),
            subaccount: maybe_subaccount_pb,
        }
    }
}
