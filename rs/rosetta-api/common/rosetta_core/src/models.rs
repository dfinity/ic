pub use crate::objects::CurveType;
use anyhow::Context;
use anyhow::anyhow;
use ic_agent::identity::BasicIdentity;
use ic_agent::identity::Identity;
use ic_ed25519::{
    PrivateKey as Ed25519SecretKey, PrivateKeyDecodingError, PrivateKeyFormat,
    PublicKey as Ed25519PublicKey,
};
use ic_secp256k1::KeyDecodingError;
use ic_secp256k1::{PrivateKey as Secp256k1PrivateKey, PublicKey as Secp256k1PublicKey};
use ic_types::PrincipalId;
use std::sync::Arc;

#[derive(Clone, PartialEq, Debug)]
pub struct Ed25519KeyPair {
    secret_key: Ed25519SecretKey,
    public_key: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    pub fn to_pem(&self) -> String {
        self.secret_key
            .serialize_pkcs8_pem(PrivateKeyFormat::Pkcs8v2)
    }

    pub fn serialize_raw(&self) -> ([u8; Ed25519SecretKey::BYTES], [u8; Ed25519SecretKey::BYTES]) {
        (
            self.secret_key.serialize_raw(),
            self.public_key.serialize_raw(),
        )
    }

    pub fn deserialize_raw(bytes: &[u8]) -> Result<Self, PrivateKeyDecodingError> {
        let secret_key = Ed25519SecretKey::deserialize_raw(bytes)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, PrivateKeyDecodingError> {
        let secret_key = Ed25519SecretKey::deserialize_pkcs8_pem(pem)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }
}

pub struct Secp256k1KeyPair {
    secret_key: Secp256k1PrivateKey,
    public_key: Secp256k1PublicKey,
}

impl Secp256k1KeyPair {
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let secret_key = Secp256k1PrivateKey::deserialize_sec1(bytes)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }
}

pub trait RosettaSupportedKeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn get_pb_key(&self) -> Vec<u8>;
    fn get_curve_type(&self) -> CurveType;
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId>;
    fn hex_encode_pk(&self) -> String;
    fn hex_decode_pk(pk_encoded: &str) -> anyhow::Result<Vec<u8>>;
    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId>;
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>>;
    fn der_decode_pk(pk_encoded: Vec<u8>) -> anyhow::Result<Vec<u8>>;
}

impl RosettaSupportedKeyPair for Ed25519KeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.secret_key.sign_message(msg).to_vec()
    }

    fn get_pb_key(&self) -> Vec<u8> {
        self.public_key.serialize_raw().to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }

    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        let public_key_der = self.public_key.serialize_rfc8410_der().to_vec();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key.serialize_raw())
    }
    fn hex_decode_pk(pk_encoded: &str) -> anyhow::Result<Vec<u8>> {
        hex::decode(pk_encoded).context(format!("Could not decode public key {pk_encoded}"))
    }

    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId> {
        match Ed25519KeyPair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = Ed25519KeyPair::der_encode_pk(pk_decoded)?;
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e.context(format!("Could not decode public key {pk_encoded}"))),
        }
    }
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ed25519PublicKey::convert_raw_to_der(&pk)
            .map_err(|err| anyhow!("Could not encode public key as der: {:?}", err))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(Ed25519PublicKey::deserialize_rfc8410_der(&pk_encoded)
            .map_err(|err| anyhow!("Could not deserialize der public key: {:?}", err))?
            .serialize_raw()
            .to_vec())
    }
}

impl RosettaSupportedKeyPair for Secp256k1KeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.secret_key.sign_message_with_ecdsa(msg).to_vec()
    }

    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        self.public_key.serialize_sec1(false)
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Secp256K1
    }
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        let public_key_der = self.public_key.serialize_der();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key.serialize_sec1(false))
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> anyhow::Result<PrincipalId> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der = Secp256k1PublicKey::deserialize_sec1(&pk_decoded)
                    .with_context(|| {
                        format!("Could not deserialize sec1 public key: {pk_decoded:?}.",)
                    })?
                    .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e.context(format!("Could not decode hex public key {pk_hex_encoded}"))),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(Secp256k1PublicKey::deserialize_sec1(&pk_sec1)
            .with_context(|| format!("Could not deserialize sec1 public key: {pk_sec1:?}.",))?
            .serialize_der())
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(Secp256k1PublicKey::deserialize_der(&pk_der)
            .with_context(|| format!("Could not deserialize der public key: {pk_der:?}.",))?
            .serialize_sec1(false))
    }
}

impl RosettaSupportedKeyPair for Arc<Ed25519KeyPair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Arc::new((**self).sign(msg)).to_vec()
    }

    fn get_pb_key(&self) -> Vec<u8> {
        Arc::new((**self).get_pb_key()).to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        (**self).get_curve_type()
    }
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        (**self).generate_principal_id()
    }
    fn hex_encode_pk(&self) -> String {
        (**self).hex_encode_pk()
    }
    fn hex_decode_pk(pk_encoded: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(pk_encoded)?)
    }
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ed25519KeyPair::der_encode_pk(pk)
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ed25519KeyPair::der_decode_pk(pk_encoded)
    }
    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId> {
        Ed25519KeyPair::get_principal_id(pk_encoded)
    }
}

impl RosettaSupportedKeyPair for Arc<Secp256k1KeyPair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Arc::new((**self).sign(msg)).to_vec()
    }

    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        Arc::new((**self).get_pb_key()).to_vec()
    }
    fn get_curve_type(&self) -> CurveType {
        (**self).get_curve_type()
    }
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        (**self).generate_principal_id()
    }
    fn hex_encode_pk(&self) -> String {
        (**self).hex_encode_pk()
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> anyhow::Result<PrincipalId> {
        Secp256k1KeyPair::get_principal_id(pk_hex_encoded)
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Secp256k1KeyPair::der_encode_pk(pk_sec1)
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Secp256k1KeyPair::der_decode_pk(pk_der)
    }
}

impl RosettaSupportedKeyPair for Arc<BasicIdentity> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_arbitrary(msg).unwrap().signature.unwrap()
    }

    //The default serialization version for the Public Key is sec1
    fn get_pb_key(&self) -> Vec<u8> {
        Self::der_decode_pk(self.public_key().unwrap().to_vec()).unwrap()
    }
    fn get_curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        Ok(PrincipalId(self.sender().map_err(|err| {
            anyhow!("Could not generate principal id: {}", err)
        })?))
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.get_pb_key())
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> anyhow::Result<PrincipalId> {
        Ed25519KeyPair::get_principal_id(pk_hex_encoded)
    }
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ed25519KeyPair::der_encode_pk(pk)
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ed25519KeyPair::der_decode_pk(pk_der)
    }
}
