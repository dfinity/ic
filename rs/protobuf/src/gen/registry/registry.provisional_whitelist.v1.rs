#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProvisionalWhitelist {
    #[prost(enumeration = "provisional_whitelist::ListType", tag = "1")]
    pub list_type: i32,
    /// This must be empty if list_type is of variant ALL.
    #[prost(message, repeated, tag = "2")]
    pub set: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
/// Nested message and enum types in `ProvisionalWhitelist`.
pub mod provisional_whitelist {
    #[derive(
        Copy,
        Clone,
        Eq,
        PartialEq,
        Ord,
        PartialOrd,
        Hash,
        Debug,
        ::prost::Enumeration,
        serde::Deserialize,
        serde::Serialize,
    )]
    #[repr(i32)]
    pub enum ListType {
        Unspecified = 0,
        All = 1,
        Set = 2,
    }
    impl ListType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ListType::Unspecified => "LIST_TYPE_UNSPECIFIED",
                ListType::All => "LIST_TYPE_ALL",
                ListType::Set => "LIST_TYPE_SET",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "LIST_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "LIST_TYPE_ALL" => Some(Self::All),
                "LIST_TYPE_SET" => Some(Self::Set),
                _ => None,
            }
        }
    }
}
