#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretKeyV1 {
    /// CBOR serialization of `CspSecretKey`
    #[prost(bytes="vec", tag="1")]
    pub csp_secret_key: ::prost::alloc::vec::Vec<u8>,
    /// Rust's `to_string()` of `Scope`
    #[prost(string, tag="2")]
    pub scope: ::prost::alloc::string::String,
}
/// SecretKeyStore stores secret keys.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretKeyStore {
    /// Mapping from KeyId to serialised CspSecretKey.
    #[prost(map="string, bytes", tag="1")]
    pub key_id_to_csp_secret_key: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::vec::Vec<u8>>,
    /// Version of SecretKeyStore
    #[prost(uint32, tag="2")]
    pub version: u32,
    /// Mapping from KeyId to SecretKeyV1.
    /// `KeyId` is represented as a hex-string (32 bytes).
    #[prost(map="string, message", tag="3")]
    pub key_id_to_secret_key_v1: ::std::collections::HashMap<::prost::alloc::string::String, SecretKeyV1>,
}
