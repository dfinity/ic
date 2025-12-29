use crate::pb::v1::{
    Account, ApproveGenesisKyc, Motion, SelfDescribingProposalAction, SelfDescribingValue,
    SelfDescribingValueArray, SelfDescribingValueMap,
    self_describing_value::Value::{self, Array, Blob, Map, Text},
};

use ic_base_types::PrincipalId;
use ic_cdk::println;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use icp_ledger::protobuf::AccountIdentifier;
use std::{collections::HashMap, marker::PhantomData};

/// A proposal action that can be described locally, without having to call `canister_metadata`
/// management canister method to get the candid file of an external canister. Every proposal action
/// except for `ExecuteNnsFunction` should implement this trait.
pub trait LocallyDescribableProposalAction {
    const TYPE_NAME: &'static str;
    const TYPE_DESCRIPTION: &'static str;

    fn to_self_describing_value(&self) -> SelfDescribingValue;

    fn to_self_describing_action(&self) -> SelfDescribingProposalAction {
        SelfDescribingProposalAction {
            type_name: Self::TYPE_NAME.to_string(),
            type_description: Self::TYPE_DESCRIPTION.to_string(),
            value: Some(self.to_self_describing_value()),
        }
    }
}

impl LocallyDescribableProposalAction for Motion {
    const TYPE_NAME: &'static str = "Motion";

    const TYPE_DESCRIPTION: &'static str = "A motion is a text that can be adopted or rejected. \
    No code is executed when a motion is adopted. An adopted motion should guide the future \
    strategy of the Internet Computer ecosystem.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
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

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        ValueBuilder::new()
            .add_field("principals", self.principals.clone())
            .build()
    }
}

/// A builder for `SelfDescribingValue` objects.
#[derive(Default)]
pub struct ValueBuilder {
    fields: HashMap<String, SelfDescribingValue>,
}

impl ValueBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_field(mut self, key: impl ToString, value: impl Into<SelfDescribingValue>) -> Self {
        self.fields.insert(key.to_string(), value.into());
        self
    }

    /// Adds a field with an empty array value. This is useful for fields that don't have a meaningful
    /// payload (e.g., StartDissolving, StopDissolving).
    pub fn add_empty_field(self, key: impl ToString) -> Self {
        self.add_field(key, SelfDescribingValue::EMPTY)
    }

    /// Given an `value: Option<T>`, if `value` is `Some(inner)`, add the `inner` to the builder. If
    /// `value` is `None`, add an empty array to the builder. This is useful for cases where a field
    /// is designed to be required, while we want to still add an empty field to the builder in case
    /// of a bug.
    pub fn add_field_with_empty_as_fallback(
        self,
        key: impl ToString,
        value: Option<impl Into<SelfDescribingValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.add_field(key, value)
        } else {
            println!(
                "A field {} is added with an empty value while we think it should be impossible",
                key.to_string()
            );
            self.add_empty_field(key)
        }
    }

    pub fn build(self) -> SelfDescribingValue {
        let Self { fields } = self;
        SelfDescribingValue {
            value: Some(Map(SelfDescribingValueMap { values: fields })),
        }
    }
}

impl From<String> for SelfDescribingValue {
    fn from(value: String) -> Self {
        SelfDescribingValue {
            value: Some(Text(value)),
        }
    }
}

impl From<&str> for SelfDescribingValue {
    fn from(value: &str) -> Self {
        SelfDescribingValue {
            value: Some(Text(value.to_string())),
        }
    }
}

impl From<PrincipalId> for SelfDescribingValue {
    fn from(value: PrincipalId) -> Self {
        SelfDescribingValue {
            value: Some(Text(value.to_string())),
        }
    }
}

impl From<Vec<u8>> for SelfDescribingValue {
    fn from(value: Vec<u8>) -> Self {
        SelfDescribingValue {
            value: Some(Blob(value)),
        }
    }
}

impl From<bool> for SelfDescribingValue {
    fn from(value: bool) -> Self {
        SelfDescribingValue {
            value: Some(to_self_describing_nat(if value { 1_u8 } else { 0_u8 })),
        }
    }
}

impl<T> From<Option<T>> for SelfDescribingValue
where
    SelfDescribingValue: From<T>,
{
    fn from(value: Option<T>) -> Self {
        SelfDescribingValue {
            value: Some(Array(SelfDescribingValueArray {
                values: value.into_iter().map(SelfDescribingValue::from).collect(),
            })),
        }
    }
}

impl<T> From<Vec<T>> for SelfDescribingValue
where
    SelfDescribingValue: From<T>,
{
    fn from(value: Vec<T>) -> Self {
        SelfDescribingValue {
            value: Some(Array(SelfDescribingValueArray {
                values: value.into_iter().map(SelfDescribingValue::from).collect(),
            })),
        }
    }
}
pub(crate) struct SelfDescribingProstEnum<E> {
    value: i32,
    prost_type: PhantomData<E>,
}

impl<E> SelfDescribingProstEnum<E>
where
    E: TryFrom<i32>,
{
    pub fn new(value: i32) -> Self {
        Self {
            value,
            prost_type: PhantomData,
        }
    }
}

impl<E> From<SelfDescribingProstEnum<E>> for SelfDescribingValue
where
    E: TryFrom<i32> + std::fmt::Debug,
{
    fn from(prost_enum: SelfDescribingProstEnum<E>) -> Self {
        let SelfDescribingProstEnum { value, .. } = prost_enum;
        let value = match E::try_from(value) {
            Ok(value) => format!("{value:?}"),
            Err(_) => {
                let enum_type_name = enum_type_name::<E>();
                println!("Unknown value for enum {enum_type_name}: {value}");
                format!("UNKNOWN_{}_{}", enum_type_name.to_ascii_uppercase(), value)
            }
        };
        SelfDescribingValue::from(value)
    }
}

fn enum_type_name<E>() -> &'static str
where
    E: TryFrom<i32>,
{
    std::any::type_name::<E>()
        .split("::")
        .last()
        .unwrap_or("???")
}

impl From<NeuronId> for SelfDescribingValue {
    fn from(value: NeuronId) -> Self {
        Self::from(value.id)
    }
}

impl From<ProposalId> for SelfDescribingValue {
    fn from(value: ProposalId) -> Self {
        Self::from(value.id)
    }
}

impl From<AccountIdentifier> for SelfDescribingValue {
    fn from(value: AccountIdentifier) -> Self {
        Self::from(value.hash)
    }
}

impl From<Account> for SelfDescribingValue {
    fn from(account: Account) -> Self {
        let Account { owner, subaccount } = account;
        let subaccount = subaccount.map(|subaccount| subaccount.subaccount);
        ValueBuilder::new()
            .add_field_with_empty_as_fallback("owner", owner)
            .add_field("subaccount", subaccount)
            .build()
    }
}

impl SelfDescribingValue {
    pub const EMPTY: Self = Self {
        value: Some(Array(SelfDescribingValueArray { values: vec![] })),
    };

    pub fn singleton_map(key: impl ToString, value: impl Into<SelfDescribingValue>) -> Self {
        ValueBuilder::new().add_field(key, value).build()
    }
}

/// A trait for types that can be converted to a SelfDescribingValue as an unsigned integer. This is
/// used because we can't do `impl<T: Into<candid::Nat>> From<T> for SelfDescribingValue` because of
/// potential conflicts.
pub(crate) trait ToSelfDescribingNat: Into<candid::Nat> {}

impl<T> From<T> for SelfDescribingValue
where
    T: ToSelfDescribingNat,
{
    fn from(value: T) -> Self {
        SelfDescribingValue {
            value: Some(to_self_describing_nat(value.into())),
        }
    }
}

// Types we want to be able to convert to a SelfDescribingValue as an unsigned integer.
impl ToSelfDescribingNat for u64 {}
impl ToSelfDescribingNat for u32 {}

pub(crate) fn to_self_describing_nat<N>(n: N) -> Value
where
    candid::Nat: From<N>,
{
    let n = candid::Nat::from(n);
    let mut bytes = Vec::new();
    n.encode(&mut bytes).expect("Failed to encode Nat");
    Value::Nat(bytes)
}

pub(crate) fn to_self_describing_int<I>(i: I) -> Value
where
    candid::Int: From<I>,
{
    let i = candid::Int::from(i);
    let mut bytes = Vec::new();
    i.encode(&mut bytes).expect("Failed to encode Int");
    Value::Int(bytes)
}

#[path = "self_describing_tests.rs"]
#[cfg(test)]
pub mod tests;
