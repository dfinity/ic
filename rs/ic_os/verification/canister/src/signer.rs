use crate::ROOT_CA_PUBLIC_KEY;
use anyhow::{anyhow, Context};
use candid::{CandidType, Principal};
use ed25519::signature::{Keypair, KeypairRef};
use ed25519::PublicKeyBytes;
use ic_cdk::api::management_canister::schnorr::{
    SchnorrAlgorithm, SchnorrKeyId, SignWithSchnorrArgument, SignWithSchnorrResponse,
};
use x509_cert::spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};

#[derive(Debug, Clone, Copy)]
pub enum KeyName {
    DfxTestKey,
    TestKey1,
    Key1,
}

impl KeyName {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyName::DfxTestKey => "dfx_test_key",
            KeyName::TestKey1 => "test_key_1",
            KeyName::Key1 => "key_1",
        }
    }
}

pub struct Ed25519Signer {
    public_key: PublicKeyBytes,
    key_id: SchnorrKeyId,
}

impl Ed25519Signer {
    pub fn new(key_name: KeyName, public_key: PublicKeyBytes) -> Result<Self, String> {
        Ok(Self {
            public_key,
            key_id: SchnorrKeyId {
                algorithm: SchnorrAlgorithm::Ed25519,
                name: key_name.as_str().into(),
            },
        })
    }

    pub async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (internal_reply,): (SignWithSchnorrResponse,) =
            ic_cdk::api::management_canister::schnorr::sign_with_schnorr(SignWithSchnorrArgument {
                message: msg.to_vec(),
                derivation_path: vec![], // TODO
                key_id: self.key_id.clone(),
            })
            .await
            .map_err(|(code, err)| anyhow!("sign_with_schnorr failed").context(err))?;

        Ok(internal_reply.signature)
    }
}

impl KeypairRef for Ed25519Signer {
    type VerifyingKey = PublicKeyBytes;
}

impl AsRef<PublicKeyBytes> for Ed25519Signer {
    fn as_ref(&self) -> &PublicKeyBytes {
        &self.public_key
    }
}

impl DynSignatureAlgorithmIdentifier for Ed25519Signer {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ed25519::pkcs8::ALGORITHM_OID.clone(),
            parameters: None,
        })
    }
}
