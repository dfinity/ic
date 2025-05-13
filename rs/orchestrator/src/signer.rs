use ic_agent::{
    agent::EnvelopeContent, export::Principal, identity::Secp256k1Identity, Identity, Signature,
};
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
type SignMessageId =
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
            pub_key,
            sign: Arc::new(get_sign_command),
        }))
    }
}

struct ExternalHsmSender {
    pub_key: Vec<u8>,
    sign: SignBytes,
}

impl Identity for ExternalHsmSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(self.pub_key.as_slice()))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.pub_key.clone())
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

pub struct NodeSender {
    pub_key: Vec<u8>,
    sign: SignMessageId,
}

impl NodeSender {
    pub fn new(mut pub_key: Vec<u8>, sign: SignMessageId) -> Self {
        // The constant is the prefix of the DER encoding of the ASN.1
        // SubjectPublicKeyInfo data structure. It can be read as follows:
        // 0x30 0x2A: Sequence of length 42 bytes
        //   0x30 0x05: Sequence of length 5 bytes
        //     0x06 0x03 0x2B 0x65 0x70: OID of length 3 bytes, 1.3.101.112 (where 43 =
        //              1 * 40 + 3)
        //   0x03 0x21: Bit string of length 33 bytes
        //     0x00 [raw key]: No padding [raw key]
        let mut der_encoded: Vec<u8> = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der_encoded.append(&mut pub_key);

        Self {
            pub_key: der_encoded,
            sign,
        }
    }
}

impl Identity for NodeSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(self.pub_key.as_slice()))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.pub_key.clone())
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
