use crate::registration::NodeRegistrationCrypto;
use ic_agent::{
    Identity, Signature, agent::EnvelopeContent, export::Principal, identity::Secp256k1Identity,
};
use ic_protobuf::registry::crypto::v1::{AlgorithmId, PublicKey};
use ic_sys::utility_command::{UtilityCommand, UtilityCommandResult};
use ic_types::messages::MessageId;
use std::{path::Path, sync::Arc};

/// An abstract message signer interface.
pub trait Signer: Send + Sync {
    /// Returns the message signer bundle containing the public key and a signing command. This
    /// object is intended to be used with an agent to send messages to IC canisters.
    fn get(&self) -> UtilityCommandResult<Box<dyn Identity>>;
}

type SignBytes = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> + Send + Sync>;
pub(crate) type SignMessageId =
    Arc<dyn Fn(&MessageId) -> Result<Vec<u8>, Box<dyn std::error::Error>> + Send + Sync>;

pub struct Hsm;

impl Signer for Hsm {
    fn get(&self) -> UtilityCommandResult<Box<dyn Identity>> {
        UtilityCommand::notify_host("Starting node registration.", 1);
        UtilityCommand::try_to_attach_hsm();
        let pub_key = UtilityCommand::read_public_key(None, None).execute()?;
        UtilityCommand::try_to_detach_hsm();
        fn get_sign_command(msg: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            UtilityCommand::try_to_attach_hsm();
            UtilityCommand::notify_host("Sending join request.", 1);
            let res = UtilityCommand::sign_message(msg.to_vec(), None, None, None)
                .execute()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            UtilityCommand::try_to_detach_hsm();
            res
        }
        Ok(Box::new(ExternalHsmSender {
            der_encoded_pub_key: pub_key,
            sign: Arc::new(get_sign_command),
        }))
    }
}

/// The sender is authenticated via an external HSM device and the signature mechanism is specified
/// through the provided function reference.
struct ExternalHsmSender {
    /// DER encoded public key
    der_encoded_pub_key: Vec<u8>,
    /// Function that abstracts the external HSM.
    sign: SignBytes,
}

impl Identity for ExternalHsmSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(
            self.der_encoded_pub_key.as_slice(),
        ))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der_encoded_pub_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        let msg = content.to_request_id().signable();
        let signature =
            Some((self.sign)(&msg).map_err(|err| format!("Cannot create hsm signature: {err}"))?);
        let public_key = self.public_key();
        Ok(Signature {
            public_key,
            signature,
            delegations: None,
        })
    }
}

pub struct NodeProviderSigner {
    identity: Secp256k1Identity,
}

impl NodeProviderSigner {
    pub fn new(path: &Path) -> Option<Self> {
        let identity = Secp256k1Identity::from_pem_file(path).ok()?;
        Some(Self { identity })
    }
}

impl Signer for NodeProviderSigner {
    fn get(&self) -> UtilityCommandResult<Box<dyn Identity>> {
        Ok(Box::new(self.identity.clone()))
    }
}

/// Signed from the node itself, with its key.
pub struct NodeSender {
    /// DER encoded public key
    der_encoded_pub_key: Vec<u8>,
    /// Function that signs the message id
    sign: SignMessageId,
}

impl NodeSender {
    pub fn new(pub_key: PublicKey, sign: SignMessageId) -> Result<Self, String> {
        if pub_key.algorithm() != AlgorithmId::Ed25519 {
            return Err(format!(
                "Unsupported algorithm: {}",
                pub_key.algorithm().as_str_name()
            ));
        }

        let der_encoded_pub_key = ic_ed25519::PublicKey::convert_raw_to_der(&pub_key.key_value)
            .map_err(|err| err.to_string())?;

        Ok(Self {
            der_encoded_pub_key,
            sign,
        })
    }

    /// A sender that signs as this node, with the node signing key held by the
    /// crypto component.
    pub(crate) fn for_this_node(crypto: Arc<dyn NodeRegistrationCrypto>) -> Result<Self, String> {
        // Reading the public keys is an RPC to the CSP vault that uses Tokio's
        // `block_on` internally, which panics in an async context without this.
        #[allow(clippy::disallowed_methods)]
        let public_keys = tokio::task::block_in_place({
            let crypto = Arc::clone(&crypto);
            move || crypto.current_node_public_keys()
        })
        .map_err(|err| format!("Failed to retrieve current node public keys: {err}"))?;
        let public_key = public_keys
            .node_signing_public_key
            .ok_or("Missing node signing key.")?;

        let sign = move |message: &MessageId| {
            // `sign_basic` blocks on an RPC to the crypto service in the same
            // way, so it needs the same treatment.
            #[allow(clippy::disallowed_methods)]
            tokio::task::block_in_place(|| {
                crypto
                    .sign_basic(message)
                    .map(|signature| signature.get().0)
                    .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
            })
        };

        Self::new(public_key, Arc::new(sign))
    }
}

impl Identity for NodeSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(
            self.der_encoded_pub_key.as_slice(),
        ))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der_encoded_pub_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        let msg = MessageId::from(*content.to_request_id());
        let signature =
            Some((self.sign)(&msg).map_err(|err| format!("Cannot create node signature: {err}"))?);
        let public_key = self.public_key();
        Ok(Signature {
            public_key,
            signature,
            delegations: None,
        })
    }
}
