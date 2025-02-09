use std::sync::Arc;

use candid::Principal;
use ic_agent::{
    agent::AgentBuilder,
    identity::{AnonymousIdentity, BasicIdentity, PemError, Prime256v1Identity, Secp256k1Identity},
    Identity,
};
use ic_identity_hsm::HardwareIdentity;
use ic_nns_handler_recovery_interface::{
    signing::{
        anonymous::AnonymousSigner, ed25519::EdwardsCurve, k256::Secp256k1, p256::Prime256, Signer,
    },
    RecoveryError, RECOVERY_CANISTER_ID,
};

use crate::implementation::RecoveryCanisterImpl;

#[derive(Clone)]
pub enum SenderOpts {
    Pem {
        path: String,
    },
    Hsm {
        slot: usize,
        key_id: String,
        pin: String,
    },
    Anonymous,
}

pub struct RecoveryCanisterBuilder {
    canister_id: String,
    url: String,
    sender: SenderOpts,
}

impl Default for RecoveryCanisterBuilder {
    fn default() -> Self {
        Self {
            canister_id: RECOVERY_CANISTER_ID.to_string(),
            url: "https://ic0.app".to_string(),
            sender: SenderOpts::Anonymous,
        }
    }
}

impl RecoveryCanisterBuilder {
    pub fn with_url(&mut self, url: &str) -> &mut Self {
        self.url = url.to_string();
        self
    }

    pub fn with_canister_id(&mut self, canister_id: &str) -> &mut Self {
        self.canister_id = canister_id.to_string();
        self
    }

    pub fn with_sender(&mut self, sender: SenderOpts) -> &mut Self {
        self.sender = sender;
        self
    }

    pub fn build(self) -> Result<RecoveryCanisterImpl, RecoveryError> {
        let signer = self.sender.clone().try_into()?;
        let identity: Box<dyn Identity> = self.sender.try_into()?;
        let ic_agent = AgentBuilder::default()
            .with_url(self.url)
            .with_identity(identity)
            .build()
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?;

        let canister_id = Principal::from_text(self.canister_id)
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?;
        Ok(RecoveryCanisterImpl::new(ic_agent, canister_id, signer))
    }
}

impl TryFrom<SenderOpts> for Arc<dyn Signer> {
    type Error = RecoveryError;

    fn try_from(value: SenderOpts) -> Result<Self, Self::Error> {
        match value {
            SenderOpts::Pem { path } => {
                let maybe_signer: Result<Arc<dyn Signer>, RecoveryError> =
                    EdwardsCurve::from_pem(&path)
                        .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
                        .or_else(|e| {
                            eprintln!("Received error: {:?}", e);
                            Prime256::from_pem(&path)
                                .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
                        })
                        .or_else(|e| {
                            eprintln!("Received error: {:?}", e);
                            Secp256k1::from_pem(&path)
                                .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
                        });

                let signer = maybe_signer.map_err(|e| {
                    eprintln!("Received error: {:?}", e);
                    RecoveryError::InvalidIdentity(
                        "Couldn't deserialize identity into any known implementation".to_string(),
                    )
                })?;
                Ok(signer)
            }
            SenderOpts::Hsm {
                slot: _,
                key_id: _,
                pin: _,
            } => unimplemented!("Ic agent blocks the session"),
            SenderOpts::Anonymous => Ok(Arc::new(AnonymousSigner)),
        }
    }
}

impl TryFrom<SenderOpts> for Box<dyn Identity> {
    type Error = RecoveryError;

    fn try_from(value: SenderOpts) -> Result<Self, Self::Error> {
        match value {
            SenderOpts::Pem { path } => {
                let maybe_identity: Result<Box<dyn Identity>, PemError> =
                    BasicIdentity::from_pem_file(&path)
                        .map(|identity| Box::new(identity) as Box<dyn Identity>)
                        .or_else(|_| {
                            Prime256v1Identity::from_pem_file(&path)
                                .map(|identity| Box::new(identity) as Box<dyn Identity>)
                        })
                        .or_else(|_| {
                            Secp256k1Identity::from_pem_file(&path)
                                .map(|identity| Box::new(identity) as Box<dyn Identity>)
                        });

                let identity =
                    maybe_identity.map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;

                Ok(identity)
            }
            SenderOpts::Hsm { slot, key_id, pin } => {
                HardwareIdentity::new("/usr/lib/opensc-pkcs11.so", slot, &key_id, || Ok(pin))
                    .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))
                    .map(|identity| Box::new(identity) as Box<dyn Identity>)
            }
            SenderOpts::Anonymous => Ok(Box::new(AnonymousIdentity)),
        }
    }
}
