use ic_canister_client::Sender;
use ic_canister_client_sender::{Secp256k1KeyPair, SigKeys};
use ic_sys::utility_command::{UtilityCommand, UtilityCommandResult};
use std::path::Path;
use std::sync::Arc;

/// An abstract message signer interface.
pub trait Signer: Send + Sync {
    /// Returns the message signer bundle containing the public key and a signing command. This
    /// object is intended to be used with an agent to send messages to IC canisters.
    fn get(&self) -> UtilityCommandResult<Sender>;
}

pub struct Hsm;

impl Signer for Hsm {
    fn get(&self) -> UtilityCommandResult<Sender> {
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
        Ok(Sender::ExternalHsm {
            pub_key,
            sign: Arc::new(get_sign_command),
        })
    }
}

pub struct NodeProviderSigner {
    keypair: Secp256k1KeyPair,
}

impl NodeProviderSigner {
    pub fn new(path: &Path) -> Option<Self> {
        let contents = std::fs::read_to_string(path).ok()?;
        let keypair = Secp256k1KeyPair::from_pem(&contents).ok()?;
        Some(Self { keypair })
    }
}

impl Signer for NodeProviderSigner {
    fn get(&self) -> UtilityCommandResult<Sender> {
        Ok(Sender::SigKeys(SigKeys::EcdsaSecp256k1(
            self.keypair.clone(),
        )))
    }
}
