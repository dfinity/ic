use std::sync::Arc;

use candid::Principal;
use ic_agent::{
    agent::AgentBuilder,
    identity::{AnonymousIdentity, BasicIdentity, PemError, Secp256k1Identity},
    Identity,
};
use ic_identity_hsm::HardwareIdentity;
use ic_nns_handler_recovery_interface::{
    signing::{
        anonymous::AnonymousSigner, ed25519::EdwardsCurve, hsm::Hsm, k256::Secp256k1, Signer,
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
        let (signer, identity) = self.sender.try_into()?;
        let ic_agent = AgentBuilder::default()
            .with_url(self.url)
            .with_arc_identity(identity)
            .build()
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?;

        let canister_id = Principal::from_text(self.canister_id)
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?;
        Ok(RecoveryCanisterImpl::new(ic_agent, canister_id, signer))
    }
}

impl TryFrom<SenderOpts> for (Arc<dyn Signer>, Arc<dyn Identity>) {
    type Error = RecoveryError;

    fn try_from(value: SenderOpts) -> Result<Self, Self::Error> {
        match value {
            SenderOpts::Anonymous => Ok((Arc::new(AnonymousSigner), Arc::new(AnonymousIdentity))),
            SenderOpts::Pem { path } => {
                let maybe_identity: Result<Arc<dyn Identity>, PemError> =
                    BasicIdentity::from_pem_file(&path)
                        .map(|identity| Arc::new(identity) as Arc<dyn Identity>)
                        .or_else(|_| {
                            Secp256k1Identity::from_pem_file(&path)
                                .map(|identity| Arc::new(identity) as Arc<dyn Identity>)
                        });

                let identity =
                    maybe_identity.map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;

                let maybe_signer: Result<Arc<dyn Signer>, RecoveryError> =
                    EdwardsCurve::from_pem(&path)
                        .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
                        .or_else(|_| {
                            Secp256k1::from_pem(&path)
                                .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
                        });

                let signer = maybe_signer.map_err(|_| {
                    RecoveryError::InvalidIdentity(
                        "Couldn't deserialize identity into any known implementation".to_string(),
                    )
                })?;

                Ok((signer, identity))
            }
            SenderOpts::Hsm { slot, key_id, pin } => {
                let hardware_identity =
                    HardwareIdentity::new("/usr/lib/opensc-pkcs11.so", slot, &key_id, || Ok(pin))
                        .map_err(|e| RecoveryError::InvalidIdentity(e.to_string()))?;

                let hardware_identity = Arc::new(hardware_identity);
                let hardware_identity_clone = hardware_identity.clone();
                let sign_func = move |payload: &[u8]| {
                    let signature = hardware_identity_clone
                        .sign_arbitrary(payload)
                        .map_err(|e| RecoveryError::InvalidSignature(e.to_string()))?;

                    let bytes =
                        signature
                            .signature
                            .ok_or(RecoveryError::InvalidSignatureFormat(
                                "Missing signature bytes".to_ascii_lowercase(),
                            ))?;

                    Ok(bytes)
                };
                let sign_func = Arc::new(sign_func);

                let signer = Hsm::new(&hardware_identity.public_key().unwrap(), sign_func)?;
                let signer = Arc::new(signer);

                Ok((signer, hardware_identity))
            }
        }
    }
}
