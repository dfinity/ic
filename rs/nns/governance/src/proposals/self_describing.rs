use crate::pb::v1::{
    ApproveGenesisKyc, Motion, SelfDescribingProposalAction, Value, ValueArray, ValueMap,
    value::Value::{Array, Map, Text},
};

use ic_base_types::PrincipalId;
use std::collections::HashMap;

/// A proposal action that can be described locally, without having to call `canister_metadata`
/// management canister method to get the candid file of an external canister. Every proposal action
/// except for `ExecuteNnsFunction` should implement this trait.
pub trait LocallyDescribableProposalAction {
    const TYPE_NAME: &'static str;
    const TYPE_DESCRIPTION: &'static str;

    fn to_value(&self) -> Value;

    fn to_self_describing(&self) -> SelfDescribingProposalAction {
        SelfDescribingProposalAction {
            type_name: Self::TYPE_NAME.to_string(),
            type_description: Self::TYPE_DESCRIPTION.to_string(),
            value: Some(self.to_value()),
        }
    }
}

impl LocallyDescribableProposalAction for Motion {
    const TYPE_NAME: &'static str = "Motion";

    const TYPE_DESCRIPTION: &'static str = "A motion is a text that can be adopted or rejected. \
    No code is executed when a motion is adopted. An adopted motion should guide the future \
    strategy of the Internet Computer ecosystem.";

    fn to_value(&self) -> Value {
        ValueBuilder::new()
            .add_field("motion_text", self.motion_text.clone())
            .build()
    }
}

impl LocallyDescribableProposalAction for ApproveGenesisKyc {
    const TYPE_NAME: &'static str = "Approve Genesis KYC";

    const TYPE_DESCRIPTION: &'static str = "When new neurons are created at Genesis, they have \
    GenesisKYC=false. This restricts what actions they can perform. Specifically, they cannot spawn \
    new neurons, and once their dissolve delays are zero, they cannot be disbursed and their balances \
    unlocked to new accounts. This proposal sets GenesisKYC=true for batches of principals. \
    (Special note: The Genesis event disburses all ICP in the form of neurons, whose principals \
    must be KYCed. Consequently, all neurons created after Genesis have GenesisKYC=true set \
    automatically since they must have been derived from balances that have already been KYCed.)";

    fn to_value(&self) -> Value {
        ValueBuilder::new()
            .add_array_field("principals", self.principals.clone())
            .build()
    }
}

/// A builder for `Value` objects.
pub(crate) struct ValueBuilder {
    fields: HashMap<String, Value>,
}

impl ValueBuilder {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    pub fn add_field(mut self, key: impl ToString, value: impl Into<Value>) -> Self {
        self.fields.insert(key.to_string(), value.into());
        self
    }

    pub fn add_array_field(
        mut self,
        key: impl ToString,
        values: impl IntoIterator<Item = impl Into<Value>>,
    ) -> Self {
        self.fields.insert(
            key.to_string(),
            Value {
                value: Some(Array(ValueArray {
                    values: values.into_iter().map(Into::into).collect(),
                })),
            },
        );
        self
    }

    pub fn build(self) -> Value {
        let Self { fields } = self;
        Value {
            value: Some(Map(ValueMap { values: fields })),
        }
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value {
            value: Some(Text(value)),
        }
    }
}

impl From<PrincipalId> for Value {
    fn from(value: PrincipalId) -> Self {
        Value {
            value: Some(Text(value.to_string())),
        }
    }
}

#[path = "self_describing_tests.rs"]
#[cfg(test)]
pub mod tests;
