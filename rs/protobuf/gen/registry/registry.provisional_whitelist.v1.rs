#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProvisionalWhitelist {
    #[prost(enumeration="provisional_whitelist::ListType", tag="1")]
    pub list_type: i32,
    /// This must be empty if list_type is of variant ALL.
    #[prost(message, repeated, tag="2")]
    pub set: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
/// Nested message and enum types in `ProvisionalWhitelist`.
pub mod provisional_whitelist {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ListType {
        Unspecified = 0,
        All = 1,
        Set = 2,
    }
}
