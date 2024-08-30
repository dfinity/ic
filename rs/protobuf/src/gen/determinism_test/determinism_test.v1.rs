/// A message with plain and repeated scalar fields.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Scalars {
    #[prost(float, tag = "1")]
    pub v_float: f32,
    #[prost(double, tag = "2")]
    pub v_double: f64,
    #[prost(int32, tag = "3")]
    pub v_i32: i32,
    #[prost(int64, tag = "4")]
    pub v_i64: i64,
    #[prost(uint32, tag = "5")]
    pub v_u32: u32,
    #[prost(uint64, tag = "6")]
    pub v_u64: u64,
    #[prost(sint32, tag = "7")]
    pub v_s32: i32,
    #[prost(sint64, tag = "8")]
    pub v_s64: i64,
    #[prost(fixed32, tag = "9")]
    pub v_fu32: u32,
    #[prost(fixed64, tag = "10")]
    pub v_fu64: u64,
    #[prost(sfixed32, tag = "11")]
    pub v_fi32: i32,
    #[prost(sfixed64, tag = "12")]
    pub v_fi64: i64,
    #[prost(bool, tag = "13")]
    pub v_bool: bool,
    #[prost(string, tag = "14")]
    pub v_string: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "15")]
    pub v_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(float, repeated, tag = "16")]
    pub r_float: ::prost::alloc::vec::Vec<f32>,
    #[prost(double, repeated, tag = "17")]
    pub r_double: ::prost::alloc::vec::Vec<f64>,
    #[prost(int32, repeated, tag = "18")]
    pub r_i32: ::prost::alloc::vec::Vec<i32>,
    #[prost(int64, repeated, tag = "19")]
    pub r_i64: ::prost::alloc::vec::Vec<i64>,
    #[prost(uint32, repeated, tag = "20")]
    pub r_u32: ::prost::alloc::vec::Vec<u32>,
    #[prost(uint64, repeated, tag = "21")]
    pub r_u64: ::prost::alloc::vec::Vec<u64>,
    #[prost(sint32, repeated, tag = "22")]
    pub r_s32: ::prost::alloc::vec::Vec<i32>,
    #[prost(sint64, repeated, tag = "23")]
    pub r_s64: ::prost::alloc::vec::Vec<i64>,
    #[prost(fixed32, repeated, tag = "24")]
    pub r_fu32: ::prost::alloc::vec::Vec<u32>,
    #[prost(fixed64, repeated, tag = "25")]
    pub r_fu64: ::prost::alloc::vec::Vec<u64>,
    #[prost(sfixed32, repeated, tag = "26")]
    pub r_fi32: ::prost::alloc::vec::Vec<i32>,
    #[prost(sfixed64, repeated, tag = "27")]
    pub r_fi64: ::prost::alloc::vec::Vec<i64>,
    #[prost(bool, repeated, tag = "28")]
    pub r_bool: ::prost::alloc::vec::Vec<bool>,
    #[prost(string, repeated, tag = "29")]
    pub r_string: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(bytes = "vec", repeated, tag = "30")]
    pub r_bytes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Simple message to be included into a composite message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Simple {
    #[prost(int64, tag = "1")]
    pub v_i64: i64,
    #[prost(string, tag = "2")]
    pub v_string: ::prost::alloc::string::String,
}
/// A message containing other messages, enums, oneoffs.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Composite {
    #[prost(message, optional, tag = "1")]
    pub v_simple: ::core::option::Option<Simple>,
    #[prost(message, repeated, tag = "2")]
    pub r_simple: ::prost::alloc::vec::Vec<Simple>,
    #[prost(enumeration = "Enum", tag = "3")]
    pub v_enum: i32,
    #[prost(enumeration = "Enum", repeated, tag = "4")]
    pub r_enum: ::prost::alloc::vec::Vec<i32>,
    #[prost(btree_map = "string, uint64", tag = "5")]
    pub v_map: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, u64>,
    #[prost(oneof = "composite::VOneof", tags = "6, 7")]
    pub v_oneof: ::core::option::Option<composite::VOneof>,
}
/// Nested message and enum types in `Composite`.
pub mod composite {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NestedInner {
        #[prost(uint64, tag = "1")]
        pub inner_u64: u64,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum VOneof {
        #[prost(string, tag = "6")]
        OneofString(::prost::alloc::string::String),
        #[prost(message, tag = "7")]
        OneofInner(NestedInner),
    }
}
/// A message with out-of-order fields.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ordering {
    #[prost(int64, tag = "16")]
    pub v_i64: i64,
    #[prost(string, tag = "5")]
    pub v_string: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "14")]
    pub v_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, repeated, tag = "3")]
    pub r_bool: ::prost::alloc::vec::Vec<bool>,
    #[prost(message, optional, tag = "2")]
    pub v_inner: ::core::option::Option<composite::NestedInner>,
}
/// An enum type with a couple of variants with a gap between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Enum {
    Unspecified = 0,
    One = 1,
    Many = 10,
}
impl Enum {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Enum::Unspecified => "ENUM_UNSPECIFIED",
            Enum::One => "ENUM_ONE",
            Enum::Many => "ENUM_MANY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ENUM_UNSPECIFIED" => Some(Self::Unspecified),
            "ENUM_ONE" => Some(Self::One),
            "ENUM_MANY" => Some(Self::Many),
            _ => None,
        }
    }
}
