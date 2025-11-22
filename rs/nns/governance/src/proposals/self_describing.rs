use std::collections::HashMap;

use crate::pb::v1::{
    Motion, SelfDescribingProposalAction, Value, ValueMap,
    value::Value::{Map, Text},
};

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
            .add_string_field("motion_text".to_string(), self.motion_text.clone())
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

    pub fn add_string_field(mut self, key: String, value: String) -> Self {
        self.fields.insert(
            key,
            Value {
                value: Some(Text(value)),
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

#[path = "self_describing_tests.rs"]
#[cfg(test)]
pub mod tests;
