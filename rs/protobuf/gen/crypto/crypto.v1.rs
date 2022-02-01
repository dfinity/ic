/// Public keys corresponding to the given node.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodePublicKeys {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub node_signing_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
    #[prost(message, optional, tag="3")]
    pub committee_signing_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
    #[prost(message, optional, tag="4")]
    pub tls_certificate: ::core::option::Option<super::super::registry::crypto::v1::X509PublicKeyCert>,
    #[prost(message, optional, tag="5")]
    pub dkg_dealing_encryption_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
}
