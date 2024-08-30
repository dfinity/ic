/// Node's public keys and certificates.
///
/// This struct is used as storage medium in the node's public key store.
/// Depending on the `version` field different public keys are expected:
/// 1. `version 0`
///      * Node signing public key `node_signing_pk`
///      * Committee signing public key `committee_signing_pk`
///      * TLS certificate `tls_certificate`
///      * DKG public key `dkg_dealing_encryption_pk`
/// 2. `version 1`
///      * Contains additionally the I-DKG public key `idkg_dealing_encryption_pk`
///
/// Note that version 0 was used to transition existing nodes to version 1 by
/// generating the corresponding I-DKG public key.
/// This transition is now done and so we *always* expect the I-DKG public key to be present
/// (and `version >= 1`).
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodePublicKeys {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(message, optional, tag = "2")]
    pub node_signing_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
    #[prost(message, optional, tag = "3")]
    pub committee_signing_pk: ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
    #[prost(message, optional, tag = "4")]
    pub tls_certificate:
        ::core::option::Option<super::super::registry::crypto::v1::X509PublicKeyCert>,
    #[prost(message, optional, tag = "5")]
    pub dkg_dealing_encryption_pk:
        ::core::option::Option<super::super::registry::crypto::v1::PublicKey>,
    #[prost(message, repeated, tag = "7")]
    pub idkg_dealing_encryption_pks:
        ::prost::alloc::vec::Vec<super::super::registry::crypto::v1::PublicKey>,
}
