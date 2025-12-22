use crate::{
    pb::v1::{
        AddOrRemoveNodeProvider, GovernanceError, NodeProvider, SelfDescribingValue,
        add_or_remove_node_provider::Change, governance_error::ErrorType,
    },
    proposals::self_describing::LocallyDescribableProposalAction,
};

use ic_base_types::PrincipalId;
use ic_nns_governance_derive_self_describing::SelfDescribing;
use icp_ledger::{AccountIdentifier, protobuf::AccountIdentifier as AccountIdentifierPb};

/// A validated AddOrRemoveNodeProvider proposal action.
#[derive(Debug, Clone, PartialEq, SelfDescribing)]
pub(crate) enum ValidAddOrRemoveNodeProvider {
    ToAdd(ValidAddNodeProvider),
    ToRemove(ValidRemoveNodeProvider),
}

/// A validated node provider to be added.
#[derive(Debug, Clone, PartialEq, SelfDescribing)]
pub(crate) struct ValidAddNodeProvider {
    id: PrincipalId,
    reward_account: Option<ValidAccountIdentifier>,
}

/// A validated node provider to be removed.
#[derive(Debug, Clone, PartialEq, SelfDescribing)]
pub(crate) struct ValidRemoveNodeProvider {
    id: PrincipalId,
}

/// A validated account identifier that is guaranteed to be 32 bytes (including checksum).
// It can also be used other places where we prefer 32-byte account identifiers for consistency.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ValidAccountIdentifier(AccountIdentifier);

impl TryFrom<AccountIdentifierPb> for ValidAccountIdentifier {
    type Error = String;

    fn try_from(value: AccountIdentifierPb) -> Result<Self, Self::Error> {
        if value.hash.len() != 32 {
            return Err(format!(
                "The account identifier must be 32 bytes long (so that it includes the checksum) but, this account identifier is: {} bytes",
                value.hash.len()
            ));
        }

        let account_identifier = AccountIdentifier::try_from(&value)
            .map_err(|e| format!("The account identifier is not valid: {e}"))?;

        Ok(ValidAccountIdentifier(account_identifier))
    }
}

impl TryFrom<AddOrRemoveNodeProvider> for ValidAddOrRemoveNodeProvider {
    type Error = GovernanceError;

    fn try_from(value: AddOrRemoveNodeProvider) -> Result<Self, Self::Error> {
        let Some(change) = value.change else {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "AddOrRemoveNodeProvider proposal must have a change field",
            ));
        };

        match change {
            Change::ToAdd(to_add) => Ok(ValidAddOrRemoveNodeProvider::ToAdd(
                ValidAddNodeProvider::try_from(to_add)?,
            )),
            Change::ToRemove(to_remove) => Ok(ValidAddOrRemoveNodeProvider::ToRemove(
                ValidRemoveNodeProvider::try_from(to_remove)?,
            )),
        }
    }
}

impl LocallyDescribableProposalAction for ValidAddOrRemoveNodeProvider {
    const TYPE_NAME: &'static str = "Add or Remove Node Provider";
    const TYPE_DESCRIPTION: &'static str = "Assign (or revoke) an identity to a node provider, \
    associating key information regarding the legal person associated that should provide a way \
    to uniquely identify it.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        SelfDescribingValue::from(self.clone())
    }
}

impl From<ValidAccountIdentifier> for SelfDescribingValue {
    fn from(value: ValidAccountIdentifier) -> Self {
        Self::from(value.0.to_hex())
    }
}

impl ValidAddOrRemoveNodeProvider {
    /// Validates the proposal against the current state of node providers.
    ///
    /// Preconditions:
    /// - For ToAdd: The node provider must not already exist in the `node_providers` list.
    /// - For ToRemove: The node provider must exist in the `node_providers` list.
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        match self {
            ValidAddOrRemoveNodeProvider::ToAdd(valid_add_node_provider) => {
                valid_add_node_provider.validate(node_providers)
            }
            ValidAddOrRemoveNodeProvider::ToRemove(valid_remove_node_provider) => {
                valid_remove_node_provider.validate(node_providers)
            }
        }
    }

    /// Executes the add or remove node provider action.
    ///
    /// This method adds or removes the node provider from the list of node providers.
    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        match self {
            ValidAddOrRemoveNodeProvider::ToAdd(valid_add_node_provider) => {
                valid_add_node_provider.execute(node_providers)
            }
            ValidAddOrRemoveNodeProvider::ToRemove(valid_remove_node_provider) => {
                valid_remove_node_provider.execute(node_providers)
            }
        }
    }
}

impl TryFrom<NodeProvider> for ValidAddNodeProvider {
    type Error = GovernanceError;

    fn try_from(value: NodeProvider) -> Result<Self, Self::Error> {
        let NodeProvider { id, reward_account } = value;

        let id = id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "AddOrRemoveNodeProvider proposal must have a node provider id",
            )
        })?;

        let reward_account = reward_account
            .map(ValidAccountIdentifier::try_from)
            .transpose()
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!("The account_identifier field is invalid: {e}"),
                )
            })?;

        Ok(ValidAddNodeProvider { id, reward_account })
    }
}

impl ValidAddNodeProvider {
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        let already_exists = node_providers
            .iter()
            .any(|node_provider| node_provider.id == Some(self.id));
        if already_exists {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("NodeProvider with id {} already exists", self.id),
            ));
        }

        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        // Validate again at execution time, since the state may have changed since validation.
        self.validate(node_providers)?;

        let reward_account = self
            .reward_account
            .as_ref()
            .map(|valid_account| valid_account.0.into_proto_with_checksum());

        node_providers.push(NodeProvider {
            id: Some(self.id),
            reward_account,
        });
        Ok(())
    }
}

impl TryFrom<NodeProvider> for ValidRemoveNodeProvider {
    type Error = GovernanceError;

    fn try_from(value: NodeProvider) -> Result<Self, Self::Error> {
        let NodeProvider {
            id,
            // The reward_account is not used for a removal.
            reward_account: _,
        } = value;

        let id = id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "AddOrRemoveNodeProvider proposal must have a node provider id",
            )
        })?;

        Ok(ValidRemoveNodeProvider { id })
    }
}

impl ValidRemoveNodeProvider {
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        self.find_existing_node_provider_position(node_providers)?;
        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        let existing_node_provider_position =
            self.find_existing_node_provider_position(node_providers)?;
        node_providers.remove(existing_node_provider_position);
        Ok(())
    }

    fn find_existing_node_provider_position(
        &self,
        node_providers: &[NodeProvider],
    ) -> Result<usize, GovernanceError> {
        node_providers
            .iter()
            .position(|node_provider| node_provider.id == Some(self.id))
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "AddOrRemoveNodeProvider ToRemove must target an existing Node Provider but targeted {}",
                        self.id
                    ),
                )
            })
    }
}

#[cfg(test)]
#[path = "add_or_remove_node_provider_tests.rs"]
mod tests;
