pub use crate::objects::CurveType;
use anyhow::anyhow;
use anyhow::Context;
use ic_agent::identity::BasicIdentity;
use ic_agent::identity::Identity;
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
pub use ic_canister_client_sender::{ed25519_public_key_from_der, Secp256k1KeyPair};
use ic_crypto_ecdsa_secp256k1;
use ic_types::PrincipalId;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::io::Cursor;
use std::sync::Arc;
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

    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        let public_key_der =
            ic_canister_client_sender::ed25519_public_key_to_der(self.public_key.to_vec());
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.public_key)
    }
    fn hex_decode_pk(pk_encoded: &str) -> anyhow::Result<Vec<u8>> {
        hex::decode(pk_encoded).context(format!("Could not decode public key {}", pk_encoded))
    }

    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e.context(format!("Could not decode public key {}", pk_encoded))),
        }
    }
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> anyhow::Result<Vec<u8>> {
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
    fn generate_principal_id(&self) -> anyhow::Result<PrincipalId> {
        let public_key_der = self.get_public_key().serialize_der();
        let pid = PrincipalId::new_self_authenticating(&public_key_der);
        Ok(pid)
    }
    fn hex_encode_pk(&self) -> String {
        hex::encode(self.get_public_key().serialize_sec1(false))
    }
    fn hex_decode_pk(pk_hex_encoded: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(pk_hex_encoded)?)
    }
    fn get_principal_id(pk_hex_encoded: &str) -> anyhow::Result<PrincipalId> {
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)
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
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)
                .with_context(|| format!("Could not deserialize sec1 public key: {:?}.", pk_sec1,))?
                .serialize_der(),
        )
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)
                .with_context(|| format!("Could not deserialize der public key: {:?}.", pk_der,))?
                .serialize_sec1(false),
        )
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
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_encoded: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(ed25519_public_key_from_der(pk_encoded))
    }
    fn get_principal_id(pk_encoded: &str) -> anyhow::Result<PrincipalId> {
        match EdKeypair::hex_decode_pk(pk_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e.context(format!("Could not decode hex public key {}", pk_encoded))),
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
        match Secp256k1KeyPair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let public_key_der =
                    ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_decoded)
                        .with_context(|| {
                            format!("Could not deserialize sec1 public key: {:?}.", pk_decoded,)
                        })?
                        .serialize_der();
                Ok(PrincipalId::new_self_authenticating(&public_key_der))
            }
            Err(e) => Err(e),
        }
    }
    fn der_encode_pk(pk_sec1: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_sec1(&pk_sec1)
                .with_context(|| format!("Could not deserialize sec1 public key: {:?}.", pk_sec1,))?
                .serialize_der(),
        )
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(
            ic_crypto_ecdsa_secp256k1::PublicKey::deserialize_der(&pk_der)
                .with_context(|| format!("Could not deserialize der public key: {:?}.", pk_der,))?
                .serialize_sec1(false),
        )
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
                EdKeypair::generate(&mut rng).to_pem().into_bytes(),
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
        match EdKeypair::hex_decode_pk(pk_hex_encoded) {
            Ok(pk_decoded) => {
                let pub_der = ic_canister_client_sender::ed25519_public_key_to_der(pk_decoded);
                Ok(PrincipalId::new_self_authenticating(&pub_der))
            }
            Err(e) => Err(e.context(format!("Could not decode public key {}", pk_hex_encoded))),
        }
    }
    fn der_encode_pk(pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(ic_canister_client_sender::ed25519_public_key_to_der(pk))
    }
    fn der_decode_pk(pk_der: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(ed25519_public_key_from_der(pk_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::PublicKey;
    use ic_agent::identity::BasicIdentity;
    use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
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
                let edw = Arc::new(EdKeypair::generate_from_u64(seed));
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
                    Arc::<EdKeypair>::der_encode_pk(edw.get_pb_key()).unwrap(),
                    Arc::<BasicIdentity>::der_encode_pk(bi.get_pb_key()).unwrap()
                );

                assert_eq!(edw.hex_encode_pk(), bi.hex_encode_pk());

                assert_eq!(
                    Arc::<EdKeypair>::get_principal_id(&edw.hex_encode_pk()).unwrap(),
                    Arc::<BasicIdentity>::get_principal_id(&bi.hex_encode_pk()).unwrap()
                );

                assert_eq!(
                    edw.generate_principal_id().unwrap(),
                    PrincipalId::new_self_authenticating(
                        &Arc::<EdKeypair>::der_encode_pk(edw.get_pb_key()).unwrap()
                    )
                );
                assert_eq!(
                    bi.generate_principal_id().unwrap(),
                    PrincipalId::new_self_authenticating(
                        &Arc::<EdKeypair>::der_encode_pk(bi.get_pb_key()).unwrap()
                    )
                );

                let pk: PublicKey = (&edw).into();
                assert_eq!(
                    pk.get_der_encoding().unwrap(),
                    Arc::<EdKeypair>::der_encode_pk(edw.get_pb_key()).unwrap()
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
