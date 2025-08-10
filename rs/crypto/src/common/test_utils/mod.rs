use ic_crypto_internal_csp::types::{CspPop, CspPublicKey, CspSecretKey};
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::{
    BasicSig, BasicSigOf, IndividualMultiSig, IndividualMultiSigOf, KeyPurpose, SignableMock,
};
use ic_types::{NodeId, RegistryVersion};
use strum_macros::EnumIter;

pub mod basic_sig;
pub mod crypto_component;
pub mod multi_bls12_381;

// Indirections to delete:
pub use ic_crypto_internal_test_vectors::unhex::*;

// Registry is a (key, value) store.
// The structs below define the corresponding key and the value structures
// used by the CryptoComponent.
#[derive(Clone)]
pub struct CryptoRegistryKey {
    pub node_id: NodeId,
    pub key_purpose: KeyPurpose,
}

// An auxiliary structure for preparing records that initialize
// a registry for testing purposes.
#[derive(Clone)]
pub struct CryptoRegistryRecord {
    pub key: CryptoRegistryKey,
    pub value: PublicKeyProto,
    pub registry_version: RegistryVersion,
}
