pub use crate::objects::CurveType;
use anyhow::anyhow;
use anyhow::Context;
use ic_agent::identity::BasicIdentity;
use ic_agent::identity::Identity;
use ic_crypto_ecdsa_secp256k1::{
    PrivateKey as Secp256k1PrivateKey, PublicKey as Secp256k1PublicKey,
};
use ic_crypto_ed25519::{
    PrivateKey as Ed25519SecretKey, PrivateKeyDecodingError, PrivateKeyFormat,
    PublicKey as Ed25519PublicKey,
};
use ic_types::PrincipalId;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{CryptoRng, Rng};
use std::io::Cursor;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub struct Ed25519KeyPair {
    secret_key: Ed25519SecretKey,
    public_key: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    pub fn generate<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let secret_key = Ed25519SecretKey::generate_using_rng(rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

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

pub trait RosettaSupportedKeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn generate_from_u64(seed: u64) -> Self;
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
    fn generate_from_u64(seed: u64) -> Ed25519KeyPair {
        let mut rng = StdRng::seed_from_u64(seed);
        Ed25519KeyPair::generate(&mut rng)
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
        hex::decode(pk_encoded).context(format!("Could not decode public key {}", pk_encoded))
    }

    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId> {
        match Ed25519KeyPair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = Ed25519KeyPair::der_encode_pk(pk_decoded)?;
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e.context(format!("Could not decode public key {}", pk_encoded))),
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
        self.secret_key.sign_message(msg).to_vec()
    }
    fn generate_from_u64(seed: u64) -> Secp256k1KeyPair {
        let mut rng = StdRng::seed_from_u64(seed);
        let secret_key = Secp256k1PrivateKey::generate_using_rng(&mut rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
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
                        format!("Could not deserialize sec1 public key: {:?}.", pk_decoded,)
                    })?
                    .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e.context(format!(
                "Could not decode hex public key {}",
                pk_hex_encoded
            ))),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(Secp256k1PublicKey::deserialize_sec1(&pk_sec1)
            .with_context(|| format!("Could not deserialize sec1 public key: {:?}.", pk_sec1,))?
            .serialize_der())
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(Secp256k1PublicKey::deserialize_der(&pk_der)
            .with_context(|| format!("Could not deserialize der public key: {:?}.", pk_der,))?
            .serialize_sec1(false))
    }
}

impl RosettaSupportedKeyPair for Arc<Ed25519KeyPair> {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        Arc::new((**self).sign(msg)).to_vec()
    }
    fn generate_from_u64(seed: u64) -> Arc<Ed25519KeyPair> {
        Arc::new(Ed25519KeyPair::generate_from_u64(seed))
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
    fn generate_from_u64(seed: u64) -> Arc<Secp256k1KeyPair> {
        Arc::new(Secp256k1KeyPair::generate_from_u64(seed))
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
    fn generate_from_u64(seed: u64) -> Arc<BasicIdentity> {
        let mut rng = StdRng::seed_from_u64(seed);
        Arc::new(
            BasicIdentity::from_pem(Cursor::new(
                Ed25519KeyPair::generate(&mut rng)
                    .secret_key
                    .serialize_pkcs8_pem(PrivateKeyFormat::Pkcs8v2)
                    .into_bytes(),
            ))
            .unwrap(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::PublicKey;
    use ic_agent::identity::BasicIdentity;
    use proptest::test_runner::{Config as TestRunnerConfig, TestRunner};

    #[test]
    fn test_basic_identity_to_edwards() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: 100,
            ..Default::default()
        });
        runner
            .run(&(proptest::prelude::any::<u64>()), |seed| {
                let edw = Arc::new(Ed25519KeyPair::generate_from_u64(seed));
                let bi = Arc::<BasicIdentity>::generate_from_u64(seed);

                assert_eq!(edw.get_curve_type(), bi.get_curve_type());

                assert_eq!(
                    edw.generate_principal_id().unwrap(),
                    bi.generate_principal_id().unwrap()
                );

                assert_eq!(edw.get_pb_key(), bi.get_pb_key());

                let bytes = b"Hello, World!";
                assert_eq!(edw.sign(bytes), bi.sign(bytes));

                assert_eq!(edw.hex_encode_pk(), bi.hex_encode_pk());

                assert_eq!(
                    Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap(),
                    Arc::<BasicIdentity>::der_encode_pk(bi.get_pb_key()).unwrap()
                );

                assert_eq!(edw.hex_encode_pk(), bi.hex_encode_pk());

                assert_eq!(
                    Arc::<Ed25519KeyPair>::get_principal_id(&edw.hex_encode_pk()).unwrap(),
                    Arc::<BasicIdentity>::get_principal_id(&bi.hex_encode_pk()).unwrap()
                );

                assert_eq!(
                    edw.generate_principal_id().unwrap(),
                    PrincipalId::new_self_authenticating(
                        &Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap()
                    )
                );
                assert_eq!(
                    bi.generate_principal_id().unwrap(),
                    PrincipalId::new_self_authenticating(
                        &Arc::<Ed25519KeyPair>::der_encode_pk(bi.get_pb_key()).unwrap()
                    )
                );

                let pk: PublicKey = (&edw).into();
                assert_eq!(
                    pk.get_der_encoding().unwrap(),
                    Arc::<Ed25519KeyPair>::der_encode_pk(edw.get_pb_key()).unwrap()
                );
                assert_eq!(
                    pk.get_principal().unwrap(),
                    edw.generate_principal_id().unwrap().0
                );

                Ok(())
            })
            .unwrap();
    }
}
