pub use crate::miscellaneous::Error;
pub use crate::objects::CurveType;
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_canister_client_sender::{ed25519_public_key_from_der, Secp256k1KeyPair};
use ic_crypto_ecdsa_secp256k1;
use ic_types::PrincipalId;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;

pub trait RosettaSupportedKeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn generate_from_u64(seed: u64) -> Self;
    fn get_pb_key(&self) -> Vec<u8>;
    fn get_curve_type(&self) -> CurveType;
    fn generate_principal_id(&self) -> Result<PrincipalId, Error>;
    fn hex_encode_pk(&self) -> String;
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, Error>;
    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, Error>;
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, Error>;
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, Error>;
}

impl RosettaSupportedKeyPair for EdKeypair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign(msg).to_vec()
    }
    fn generate_from_u64(seed: u64) -> EdKeypair {
        let mut rng = StdRng::seed_from_u64(seed);
        EdKeypair::generate(&mut rng)
    }
    fn get_pb_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }

    fn generate_principal_id(&self) -> Result<PrincipalId, Error> {
        let public_key_der =
            ic_canister_client_sender::ed25519_public_key_to_der(self.public_key.to_vec());
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key)
    }
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, Error> {
        Ok(hex::decode(pk_encoded)?)
    }

    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, Error> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ed25519_public_key_from_der(pk_encoded))
    }
}

impl RosettaSupportedKeyPair for Secp256k1KeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Secp256k1KeyPair::sign(self, msg)
    }
    fn generate_from_u64(seed: u64) -> Secp256k1KeyPair {
        let mut rng = StdRng::seed_from_u64(seed);
        Secp256k1KeyPair::generate(&mut rng)
    }
    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        self.get_public_key().serialize_sec1(false)
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Secp256K1
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, Error> {
        let public_key_der = self.get_public_key().serialize_der();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.get_public_key().serialize_sec1(false))
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> Result<Vec<u8>, Error> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> Result<PrincipalId, Error> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)?
                        .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)?.serialize_der())
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)?.serialize_sec1(false))
    }
}

impl RosettaSupportedKeyPair for Arc<EdKeypair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Arc::new((**self).sign(msg)).to_vec()
    }
    fn generate_from_u64(seed: u64) -> Arc<EdKeypair> {
        let mut rng = StdRng::seed_from_u64(seed);
        Arc::new(EdKeypair::generate(&mut rng))
    }
    fn get_pb_key(&self) -> Vec<u8> {
        Arc::new((**self).get_pb_key()).to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        (**self).get_curve_type()
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, Error> {
        (**self).generate_principal_id()
    }
    fn hex_encode_pk(&self) -> String {
        (**self).hex_encode_pk()
    }
    fn hex_decode_pk(pk_encoded: &str) -> Result<Vec<u8>, Error> {
        Ok(hex::decode(pk_encoded)?)
    }
    fn der_encode_pk(pk: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ed25519_public_key_from_der(pk_encoded))
    }
    fn get_principal_id(pk_encoded: &str) -> Result<PrincipalId, Error> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e),
        }
    }
}

impl RosettaSupportedKeyPair for Arc<Secp256k1KeyPair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Arc::new((**self).sign(msg)).to_vec()
    }
    fn generate_from_u64(seed: u64) -> Arc<Secp256k1KeyPair> {
        let mut rng = StdRng::seed_from_u64(seed);
        Arc::new(Secp256k1KeyPair::generate(&mut rng))
    }
    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        Arc::new((**self).get_pb_key()).to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        (**self).get_curve_type()
    }
    fn generate_principal_id(&self) -> Result<PrincipalId, Error> {
        (**self).generate_principal_id()
    }
    fn hex_encode_pk(&self) -> String {
        (**self).hex_encode_pk()
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> Result<Vec<u8>, Error> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> Result<PrincipalId, Error> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)?
                        .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)?.serialize_der())
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)?.serialize_sec1(false))
    }
}
