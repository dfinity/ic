use crate::ids::{canister_test_id, user_test_id};
use ic_canister_client_sender::{Sender, ed25519_public_key_to_der};
use ic_types::{
    CanisterId, PrincipalId, Time, UserId,
    crypto::DOMAIN_IC_REQUEST,
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, Ingress, MessageId,
        SignedIngress,
    },
    time::expiry_time_from_now,
};
use rand::thread_rng;
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
                effective_canister_id: Some(canister_test_id(0)),
                method_name: "".to_string(),
                method_payload: Vec::new(),
                message_id: MessageId::from([0; 32]),
                expiry_time: expiry_time_from_now(),
            },
        }
    }
}

impl IngressBuilder {
    /// Create a new `IngressBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `source` field.
    pub fn source(mut self, source: UserId) -> Self {
        self.ingress.source = source;
        self
    }

    /// Sets the `receiver` field.
    pub fn receiver(mut self, receiver: CanisterId) -> Self {
        self.ingress.receiver = receiver;
        self
    }

    /// Sets the `effective_canister_id` field.
    pub fn effective_canister_id(mut self, effective_canister_id: Option<CanisterId>) -> Self {
        self.ingress.effective_canister_id = effective_canister_id;
        self
    }

    /// Sets the `method_name` field.
    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.ingress.method_name = method_name.to_string();
        self
    }

    /// Sets the `method_payload` field.
    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.ingress.method_payload = method_payload;
        self
    }

    /// Sets the `message_id` field.
    pub fn message_id(mut self, message_id: MessageId) -> Self {
        self.ingress.message_id = message_id;
        self
    }

    /// Sets the `expiry_time` field.
    pub fn expiry_time(mut self, expiry_time: Time) -> Self {
        self.ingress.expiry_time = expiry_time;
        self
    }

    /// Returns the built `Ingress`.
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
            ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
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

    /// Sets the `sender` field.
    pub fn sender(mut self, user_id: UserId) -> Self {
        self.update.sender = Blob(user_id.get().into_vec());
        self
    }

    /// Sets the `canister_id` field.
    pub fn canister_id(mut self, canister_id: CanisterId) -> Self {
        self.update.canister_id = Blob(canister_id.get().into_vec());
        self
    }

    /// Sets the `method_name` field.
    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.update.method_name = method_name.to_string();
        self
    }

    /// Sets the `arg` (i.e. method payload) field.
    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.update.arg = Blob(method_payload);
        self
    }

    /// Sets the `nonce` field.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.update.nonce = Some(Blob(nonce.to_le_bytes().to_vec()));
        self
    }

    /// Sets the `ingress_expiry` field.
    pub fn expiry_time(mut self, expiry_time: Time) -> Self {
        self.update.ingress_expiry = expiry_time.as_nanos_since_unix_epoch();
        self
    }

    pub fn sign_for_sender(mut self, sender: &Sender) -> Self {
        let pub_key = sender.sender_pubkey_der();
        self.sender_pubkey.clone_from(&pub_key);

        self.update.sender = Blob(
            UserId::from(PrincipalId::new_self_authenticating(&pub_key.unwrap()))
                .get()
                .into_vec(),
        );
        let message_id = self.update.id();
        self.sender_sig = sender
            .sign_message_id(&message_id)
            .map_err(|e| format!("failed to sign submit message: {e}"))
            .unwrap();

        self
    }

    /// Create keypair, set sender and signature accordingly
    pub fn sign_for_randomly_generated_sender(mut self) -> Self {
        let private_key = ic_ed25519::PrivateKey::generate_using_rng(&mut thread_rng());
        let sender_pubkey =
            ed25519_public_key_to_der(private_key.public_key().serialize_raw().to_vec());
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
        self.sender_sig = Some(private_key.sign_message(&bytes_to_sign).to_vec());
        self
    }

    /// Returns the built `SignedIngress`.
    pub fn build(&self) -> SignedIngress {
        // TODO(NNS1-502): Consider panicking if expiry_time_from_now() was not called

        let content = HttpCallContent::Call {
            update: self.update.clone(),
        };
        let sender_pubkey = self.sender_pubkey.as_ref().map(|key| Blob(key.clone()));
        let sender_sig = self.sender_sig.as_ref().map(|sig| Blob(sig.clone()));
        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_pubkey,
            sender_sig,
            sender_delegation: None,
        };

        SignedIngress::try_from(envelope).unwrap()
    }
}
