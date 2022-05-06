/// Public keys corresponding to the given node.
///
/// This struct is used for two purposes:
/// 1. As storage medium in the node's public key store. There, the `version`
///    field indicates if the I-DKG key is included, no matter if it was
///    generated together with all other keys (which is the case for new nodes)
///    or if it was generated separately afterwards (which is the case for
///    existing nodes): Version 0 means the key is *not* included. Version 1
///    means the key is included.
/// 2. As input parameter for node key validation performed by the
///    `ic-crypto-node-key-validation` crate. There, the version field indicates
///    whether the key validation shall include the I-DKG key: Version 0 means
///    the validation shall *not* include the I-DKG key. Version 1 means the
///    key validation shall include the I-DKG key.
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
    #[prost(message, optional, tag="6")]
    pub idkg_dealing_encryption_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
}
