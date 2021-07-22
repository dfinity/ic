use crate::crypto::basic_utilities::ed25519_public_key_to_der;
use crate::types::ids::{canister_test_id, user_test_id};
use ic_canister_client::Sender;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_types::{
    messages::{
        Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent, Ingress, MessageId,
        SignedIngress,
    },
    time::current_time_and_expiry_time,
    CanisterId, PrincipalId, Time, UserId,
};
use rand_core::OsRng;
use std::convert::TryFrom;

/// A simple ingress message builder.
pub struct IngressBuilder {
    ingress: Ingress,
}

impl Default for IngressBuilder {
    /// Creates a dummy Ingress message with default values.
    fn default() -> Self {
        Self {
            ingress: Ingress {
                source: user_test_id(2),
                receiver: canister_test_id(0),
                method_name: "".to_string(),
                method_payload: Vec::new(),
                message_id: MessageId::from([0; 32]),
                expiry_time: current_time_and_expiry_time().1,
            },
        }
    }
}

impl IngressBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the source attribute for an ingress message.
    pub fn source(mut self, source: UserId) -> Self {
        self.ingress.source = source;
        self
    }

    /// Sets the receiver attribute for an ingress message.
    pub fn receiver(mut self, receiver: CanisterId) -> Self {
        self.ingress.receiver = receiver;
        self
    }

    /// Sets the method_name attribute for an ingress message.
    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.ingress.method_name = method_name.to_string();
        self
    }

    /// Sets the method_payload attribute for an ingress message.
    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.ingress.method_payload = method_payload;
        self
    }

    /// Sets the message_id attribute for an ingress message.
    pub fn message_id(mut self, message_id: MessageId) -> Self {
        self.ingress.message_id = message_id;
        self
    }

    pub fn expiry_time(mut self, expiry_time: Time) -> Self {
        self.ingress.expiry_time = expiry_time;
        self
    }

    /// Returns the Ingress message that has been constructed by the
    /// builder.
    pub fn build(&self) -> Ingress {
        self.ingress.clone()
    }
}

pub struct SignedIngressBuilder {
    update: HttpCanisterUpdate,
    sender_pubkey: Option<Vec<u8>>,
    sender_sig: Option<Vec<u8>>,
}

impl Default for SignedIngressBuilder {
    fn default() -> Self {
        let update = HttpCanisterUpdate {
            canister_id: Blob(canister_test_id(0).get().into_vec()),
            method_name: "".to_string(),
            arg: Blob(vec![]),
            sender: Blob(PrincipalId::new_anonymous().into()),
            ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        Self {
            update,
            sender_pubkey: None,
            sender_sig: None,
        }
    }
}

impl SignedIngressBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn sender(mut self, user_id: UserId) -> Self {
        self.update.sender = Blob(user_id.get().into_vec());
        self
    }

    pub fn canister_id(mut self, canister_id: CanisterId) -> Self {
        self.update.canister_id = Blob(canister_id.get().into_vec());
        self
    }

    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.update.method_name = method_name.to_string();
        self
    }

    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.update.arg = Blob(method_payload);
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.update.nonce = Some(Blob(nonce.to_le_bytes().to_vec()));
        self
    }

    pub fn expiry_time(mut self, expiry_time: Time) -> Self {
        self.update.ingress_expiry = expiry_time.as_nanos_since_unix_epoch();
        self
    }

    pub fn sign_for_sender(mut self, sender: &Sender) -> Self {
        let pub_key = sender.sender_pubkey_der();
        self.sender_pubkey = pub_key.clone();

        self.update.sender = Blob(
            UserId::from(PrincipalId::new_self_authenticating(&pub_key.unwrap()))
                .get()
                .into_vec(),
        );
        let message_id = self.update.id();
        self.sender_sig = sender
            .sign_message_id(&message_id)
            .map_err(|e| format!("failed to sign submit message: {}", e))
            .unwrap();

        self
    }

    /// Create keypair, set sender and signature accordingly
    pub fn sign_for_randomly_generated_sender(mut self) -> Self {
        use ed25519_dalek::Signer;
        // create key pair
        let ed25519_keypair = {
            // use `ChaChaRng::seed_from_u64` for deterministic keys
            let mut rng = OsRng::default();
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let sender_pubkey = ed25519_public_key_to_der(ed25519_keypair.public.to_bytes().to_vec());
        self.sender_pubkey = Some(sender_pubkey.clone());
        self.update.sender = Blob(
            UserId::from(PrincipalId::new_self_authenticating(&sender_pubkey))
                .get()
                .into_vec(),
        );
        let message_id = self.update.id();
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(message_id.as_bytes());
            buf
        };
        self.sender_sig = Some(ed25519_keypair.sign(&bytes_to_sign).to_bytes().to_vec());
        self
    }

    pub fn build(&self) -> SignedIngress {
        // TODO(NNS1-502): Consider panicking if expiry_time() was not called

        let content = HttpSubmitContent::Call {
            update: self.update.clone(),
        };
        let sender_pubkey = self.sender_pubkey.as_ref().map(|key| Blob(key.clone()));
        let sender_sig = self.sender_sig.as_ref().map(|sig| Blob(sig.clone()));
        let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_pubkey,
            sender_sig,
            sender_delegation: None,
        };

        SignedIngress::try_from(envelope).unwrap()
    }
}
