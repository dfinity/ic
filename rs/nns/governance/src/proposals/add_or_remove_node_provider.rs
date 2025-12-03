use crate::pb::v1::{
    AddOrRemoveNodeProvider, GovernanceError, NodeProvider, add_or_remove_node_provider::Change,
    governance_error::ErrorType,
};
use ic_base_types::PrincipalId;
use icp_ledger::{AccountIdentifier, protobuf::AccountIdentifier as AccountIdentifierPb};

/// A validated AddOrRemoveNodeProvider proposal.
/// This enum ensures that invalid states cannot be represented.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidAddOrRemoveNodeProvider {
    ToAdd(ValidAddNodeProvider),
    ToRemove(ValidRemoveNodeProvider),
}

/// A validated node provider to be added.
/// All fields are guaranteed to be valid at construction time.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidAddNodeProvider {
    id: PrincipalId,
    reward_account: Option<ValidAccountIdentifier>,
}

/// A validated node provider to be removed.
/// The ID is guaranteed to be valid at construction time.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidRemoveNodeProvider {
    id: PrincipalId,
}

/// A validated account identifier that is guaranteed to be 32 bytes (including checksum).
#[derive(Debug, Clone, PartialEq)]
pub struct ValidAccountIdentifier(AccountIdentifier);

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
        match value.change {
            None => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "AddOrRemoveNodeProvider proposal must have a change field",
            )),
            Some(Change::ToAdd(node_provider)) => {
                let NodeProvider { id, reward_account } = node_provider;
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
                Ok(ValidAddOrRemoveNodeProvider::ToAdd(ValidAddNodeProvider {
                    id,
                    reward_account,
                }))
            }
            Some(Change::ToRemove(node_provider)) => {
                let NodeProvider {
                    id,
                    reward_account: _,
                } = node_provider;
                let id = id.ok_or_else(|| {
                    GovernanceError::new_with_message(
                        ErrorType::InvalidProposal,
                        "AddOrRemoveNodeProvider proposal must have a node provider id",
                    )
                })?;
                Ok(ValidAddOrRemoveNodeProvider::ToRemove(
                    ValidRemoveNodeProvider { id },
                ))
            }
        }
    }
}

impl ValidAddOrRemoveNodeProvider {
    /// Validates the proposal against the current state of node providers.
    ///
    /// Preconditions:
    /// - For ToAdd: The node provider must not already exist in the registry.
    /// - For ToRemove: The node provider must exist in the registry.
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

impl ValidAddNodeProvider {
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        if node_providers
            .iter()
            .any(|node_provider| node_provider.id == Some(self.id))
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "AddOrRemoveNodeProvider cannot add already existing Node Provider: {}",
                    self.id
                ),
            ));
        }
        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        // Double-check that the node provider doesn't already exist
        if node_providers
            .iter()
            .any(|node_provider| node_provider.id == Some(self.id))
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "A node provider with the same principal already exists.",
            ));
        }

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

impl ValidRemoveNodeProvider {
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        if !node_providers
            .iter()
            .any(|node_provider| node_provider.id == Some(self.id))
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "AddOrRemoveNodeProvider ToRemove must target an existing Node Provider \
                      but targeted {}",
                    self.id
                ),
            ));
        }
        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        // Find and remove the node provider
        if let Some(pos) = node_providers
            .iter()
            .position(|node_provider| node_provider.id == Some(self.id))
        {
            node_providers.remove(pos);
            Ok(())
        } else {
            Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "Can't find a NodeProvider with the same principal id.",
            ))
        }
    }
}

#[cfg(test)]
#[path = "add_or_remove_node_provider_tests.rs"]
mod tests;
