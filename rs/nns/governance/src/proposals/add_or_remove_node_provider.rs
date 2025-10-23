use crate::{
    pb::v1::{
        AddOrRemoveNodeProvider, GovernanceError, NodeProvider,
        add_or_remove_node_provider::Change, governance_error::ErrorType,
    },
    proposals::generic::LocalProposalType,
};

use ic_base_types::PrincipalId;
use ic_nns_governance_api::GenericValue;
use icp_ledger::{AccountIdentifier, protobuf::AccountIdentifier as AccountIdentiferPb};
use maplit::hashmap;

#[derive(Debug, Clone, PartialEq)]
pub enum ValidAddOrRemoveNodeProvider {
    ToAdd(ValidAddNodeProvider),
    ToRemove(ValidRemoveNodeProvider),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidAddNodeProvider {
    id: PrincipalId,
    reward_account: Option<ValidAccountIdentifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidRemoveNodeProvider {
    id: PrincipalId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidAccountIdentifier(AccountIdentifier);

impl TryFrom<AccountIdentiferPb> for ValidAccountIdentifier {
    type Error = String;

    fn try_from(value: AccountIdentiferPb) -> Result<Self, Self::Error> {
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
    type Error = String;

    fn try_from(value: AddOrRemoveNodeProvider) -> Result<Self, Self::Error> {
        match value.change {
            None => Err("AddOrRemoveNodeProvider proposal must have a change field".to_string()),
            Some(Change::ToAdd(node_provider)) => {
                let NodeProvider { id, reward_account } = node_provider;
                let id = id.ok_or_else(|| {
                    "AddOrRemoveNodeProvider proposal must have a node provider id".to_string()
                })?;
                let reward_account = reward_account
                    .map(ValidAccountIdentifier::try_from)
                    .transpose()?;
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
                    "AddOrRemoveNodeProvider proposal must have a node provider id".to_string()
                })?;
                Ok(ValidAddOrRemoveNodeProvider::ToRemove(
                    ValidRemoveNodeProvider { id },
                ))
            }
        }
    }
}

impl LocalProposalType for ValidAddOrRemoveNodeProvider {
    const TYPE_NAME: &'static str = "Add or Remove Node Provider";
    const TYPE_DESCRIPTION: &'static str = "Assign (or revoke) an identity to a node provider, associating key information regarding \
        the legal person associated that should provide a way to uniquely identify it.";

    fn to_generic_value(&self) -> GenericValue {
        match self {
            ValidAddOrRemoveNodeProvider::ToAdd(valid_add_node_provider) => {
                let mut values = hashmap! {
                    "id".to_string() => GenericValue::Text(valid_add_node_provider.id.to_string()),
                };
                if let Some(reward_account) = &valid_add_node_provider.reward_account {
                    values.insert(
                        "reward_account".to_string(),
                        GenericValue::Text(reward_account.0.to_string()),
                    );
                }
                GenericValue::Map(values)
            }
            ValidAddOrRemoveNodeProvider::ToRemove(valid_remove_node_provider) => {
                GenericValue::Map(hashmap! {
                    "id".to_string() => GenericValue::Text(valid_remove_node_provider.id.to_string()),
                })
            }
        }
    }
}

impl ValidAddOrRemoveNodeProvider {
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
        if node_providers.iter().any(|np| np.id == Some(self.id)) {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Proposal invalid because of cannot add already existing Node Provider with id: {}",
                    self.id
                ),
            ));
        }
        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        node_providers.push(NodeProvider {
            id: Some(self.id),
            reward_account: self
                .reward_account
                .as_ref()
                .map(|x| x.0.into_proto_with_checksum()),
        });
        Ok(())
    }
}

impl ValidRemoveNodeProvider {
    pub fn validate(&self, node_providers: &[NodeProvider]) -> Result<(), GovernanceError> {
        if !node_providers.iter().any(|np| np.id == Some(self.id)) {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Node provider {} does not exist", self.id),
            ));
        }
        Ok(())
    }

    pub fn execute(&self, node_providers: &mut Vec<NodeProvider>) -> Result<(), GovernanceError> {
        node_providers.retain(|np| np.id != Some(self.id));
        Ok(())
    }
}
