use crate::pb::v1::{
    Account, ApproveGenesisKyc, Empty, Motion, NetworkEconomics, SelfDescribingProposalAction,
    SelfDescribingValue, SelfDescribingValueArray, SelfDescribingValueMap,
    self_describing_value::Value::{self, Array, Blob, Map, Text},
};

use ic_base_types::PrincipalId;
use ic_cdk::println;
use ic_nervous_system_proto::pb::v1::{
    Canister, Countries, Decimal, Duration, GlobalTimeOfDay, Image, Percentage, Tokens,
};
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

impl LocallyDescribableProposalAction for NetworkEconomics {
    const TYPE_NAME: &'static str = "Manage Network Economics";
    const TYPE_DESCRIPTION: &'static str = "Updates the network economics parameters that control various costs, rewards, and \
        thresholds in the Network Nervous System, including proposal costs, neuron staking \
        requirements, transaction fees, and voting power economics.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        SelfDescribingValue::from(self.clone())
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

impl From<Percentage> for SelfDescribingValue {
    fn from(value: Percentage) -> Self {
        let Percentage { basis_points } = value;

        let basis_points = match basis_points {
            Some(basis_points) => basis_points,
            None => {
                println!("A Percentage is added with absent basis_points");
                return Self::from("[unspecified]");
            }
        };

        Self::singleton_map("basis_points", basis_points)
    }
}

impl From<Decimal> for SelfDescribingValue {
    fn from(decimal: Decimal) -> Self {
        let Decimal { human_readable } = decimal;
        let decimal = match human_readable {
            Some(human_readable) => human_readable,
            None => {
                println!("A Decimal is added with absent human_readable");
                "[unspecified]".to_string()
            }
        };
        Self::from(decimal)
    }
}

impl<T> From<Option<T>> for SelfDescribingValue
where
    SelfDescribingValue: From<T>,
{
    fn from(value: Option<T>) -> Self {
        if let Some(value) = value {
            SelfDescribingValue::from(value)
        } else {
            SelfDescribingValue::NULL
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
            .add_field("owner", owner)
            .add_field("subaccount", subaccount)
            .build()
    }
}

impl SelfDescribingValue {
    pub const NULL: Self = Self {
        value: Some(Value::Null(Empty {})),
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

impl From<Duration> for SelfDescribingValue {
    fn from(value: Duration) -> Self {
        let Duration { seconds } = value;
        ValueBuilder::new().add_field("seconds", seconds).build()
    }
}

impl From<Tokens> for SelfDescribingValue {
    fn from(value: Tokens) -> Self {
        let Tokens { e8s } = value;
        ValueBuilder::new().add_field("e8s", e8s).build()
    }
}

impl From<Image> for SelfDescribingValue {
    fn from(value: Image) -> Self {
        let Image { base64_encoding } = value;
        ValueBuilder::new()
            .add_field("base64_encoding", base64_encoding)
            .build()
    }
}

impl From<Countries> for SelfDescribingValue {
    fn from(value: Countries) -> Self {
        let Countries { iso_codes } = value;
        ValueBuilder::new()
            .add_field("iso_codes", iso_codes)
            .build()
    }
}

impl From<GlobalTimeOfDay> for SelfDescribingValue {
    fn from(value: GlobalTimeOfDay) -> Self {
        let GlobalTimeOfDay {
            seconds_after_utc_midnight,
        } = value;
        ValueBuilder::new()
            .add_field("seconds_after_utc_midnight", seconds_after_utc_midnight)
            .build()
    }
}

impl From<Canister> for SelfDescribingValue {
    fn from(value: Canister) -> Self {
        let Canister { id } = value;
        Self::from(id)
    }
}

#[path = "self_describing_tests.rs"]
#[cfg(test)]
pub mod tests;
