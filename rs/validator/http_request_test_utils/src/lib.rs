use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_test_utils_canister_sigs::{encode_sig, CanisterState};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{CanisterSig, Signable};
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpRequest, HttpRequestEnvelope,
    MessageId, SignedDelegation, SignedIngressContent,
};
use ic_types::{CanisterId, PrincipalId, Time};

#[cfg(test)]
mod tests;

const ANONYMOUS_SENDER: u8 = 0x04;

#[derive(Debug)]
pub struct HttpRequestBuilder {
    content: HttpCanisterUpdate,
    sender_public_key: Option<Blob>,
    sender_signature: Option<Blob>,
    sender_delegation: Option<Vec<SignedDelegation>>,
}

impl Default for HttpRequestBuilder {
    fn default() -> Self {
        HttpRequestBuilder {
            content: dummy_request_content(),
            sender_public_key: None,
            sender_signature: None,
            sender_delegation: None,
        }
    }
}

fn dummy_request_content() -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(vec![42; 8]),
        method_name: "some_method".to_string(),
        arg: Blob(b"".to_vec()),
        sender: Default::default(),
        ingress_expiry: 0,
        nonce: None,
    }
}

impl HttpRequestBuilder {
    pub fn with_ingress_expiry_at(mut self, ingress_expiry_time: Time) -> Self {
        self.content.ingress_expiry = ingress_expiry_time.as_nanos_since_unix_epoch();
        self
    }

    pub fn with_authentication<T: HttpRequestEnvelopeFactory>(mut self, authentication: T) -> Self {
        self.content.sender = authentication.sender();
        let message_id = self.content.id();
        self.sender_public_key = authentication.sender_public_key();
        self.sender_signature = authentication.sender_signature(&message_id);
        self.sender_delegation = authentication.sender_delegations();
        self
    }

    pub fn build(self) -> HttpRequest<SignedIngressContent> {
        HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: self.content,
            },
            sender_pubkey: self.sender_public_key,
            sender_sig: self.sender_signature,
            sender_delegation: self.sender_delegation,
        })
        .expect("invalid HTTP request")
    }
}

#[derive(Debug, Clone)]
pub enum AuthenticationScheme {
    Anonymous,
    Direct(DirectAuthenticationScheme),
    Delegation(DelegationChain),
}

#[derive(Debug, Clone)]
pub enum DirectAuthenticationScheme {
    UserKeyPair(Ed25519KeyPair),
    CanisterSignature {
        seed: Vec<u8>,
        canister_id: CanisterId,
        root_public_key: ThresholdSigPublicKey,
        root_secret_key: SecretKeyBytes,
    },
}

pub trait HttpRequestEnvelopeFactory {
    fn sender(&self) -> Blob;
    fn sender_public_key(&self) -> Option<Blob>;
    fn sender_signature(&self, message: &MessageId) -> Option<Blob>;
    fn sender_delegations(&self) -> Option<Vec<SignedDelegation>>;
}

impl HttpRequestEnvelopeFactory for AuthenticationScheme {
    fn sender(&self) -> Blob {
        match self {
            AuthenticationScheme::Anonymous => Blob(vec![ANONYMOUS_SENDER]),
            AuthenticationScheme::Direct(auth) => {
                Blob(PrincipalId::new_self_authenticating(&auth.public_key_der()).to_vec())
            }
            AuthenticationScheme::Delegation(chain) => {
                Blob(PrincipalId::new_self_authenticating(&chain.start.public_key_der()).to_vec())
            }
        }
    }

    fn sender_public_key(&self) -> Option<Blob> {
        match &self {
            AuthenticationScheme::Anonymous => None,
            AuthenticationScheme::Direct(auth) => Some(Blob(auth.public_key_der())),
            AuthenticationScheme::Delegation(chain) => Some(Blob(chain.start.public_key_der())),
        }
    }

    fn sender_signature(&self, message: &MessageId) -> Option<Blob> {
        match &self {
            AuthenticationScheme::Anonymous => None,
            AuthenticationScheme::Direct(auth) => Some(Blob(auth.sign(message))),
            AuthenticationScheme::Delegation(chain) => Some(Blob(chain.end.sign(message))),
        }
    }

    fn sender_delegations(&self) -> Option<Vec<SignedDelegation>> {
        match &self {
            AuthenticationScheme::Anonymous => None,
            AuthenticationScheme::Direct(_) => None,
            AuthenticationScheme::Delegation(chain) => Some(chain.signed_delegations.clone()),
        }
    }
}

impl DirectAuthenticationScheme {
    fn public_key_der(&self) -> Vec<u8> {
        use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
        use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
        use simple_asn1::oid;

        match self {
            DirectAuthenticationScheme::UserKeyPair(keypair) => {
                ed25519_public_key_to_der(keypair.public_key.to_vec())
            }
            DirectAuthenticationScheme::CanisterSignature {
                seed, canister_id, ..
            } => {
                let pubkey_bytes = canister_sig_pub_key_to_bytes(*canister_id, seed);
                subject_public_key_info_der(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2), &pubkey_bytes)
                    .expect("error encoding to DER")
            }
        }
    }
    fn sign<T: Signable>(&self, message: &T) -> Vec<u8> {
        match self {
            DirectAuthenticationScheme::UserKeyPair(keypair) => {
                keypair.sign(&message.as_signed_bytes()).to_vec()
            }
            DirectAuthenticationScheme::CanisterSignature {
                seed,
                canister_id,
                root_public_key,
                root_secret_key,
            } => {
                canister_signature_for_message(
                    message.as_signed_bytes(),
                    *canister_id,
                    seed,
                    *root_public_key,
                    root_secret_key.clone(),
                )
                .0
            }
        }
    }

    fn delegate_to(
        &self,
        other: &DirectAuthenticationScheme,
        expiration: Time,
    ) -> SignedDelegation {
        let delegation = Delegation::new(other.public_key_der(), expiration);
        let signature = self.sign(&delegation);
        SignedDelegation::new(delegation, signature)
    }
}

#[derive(Debug, Clone)]
pub struct DelegationChain {
    start: DirectAuthenticationScheme,
    end: DirectAuthenticationScheme,
    signed_delegations: Vec<SignedDelegation>,
}

impl DelegationChain {
    pub fn rooted_at(start: DirectAuthenticationScheme) -> DelegationChainBuilder {
        DelegationChainBuilder::new(start)
    }
}

pub struct DelegationChainBuilder {
    start: DirectAuthenticationScheme,
    end: Option<DirectAuthenticationScheme>,
    signed_delegations: Vec<SignedDelegation>,
}

impl DelegationChainBuilder {
    pub fn new(start: DirectAuthenticationScheme) -> Self {
        DelegationChainBuilder {
            start,
            end: None,
            signed_delegations: vec![],
        }
    }

    pub fn delegate_to(mut self, new_end: DirectAuthenticationScheme, expiration: Time) -> Self {
        let current_end = self.end.unwrap_or_else(|| self.start.clone());
        self.signed_delegations
            .push(current_end.delegate_to(&new_end, expiration));
        self.end = Some(new_end);
        self
    }

    pub fn build(self) -> DelegationChain {
        DelegationChain {
            start: self.start,
            end: self.end.expect("Missing end of delegation chain"),
            signed_delegations: self.signed_delegations,
        }
    }
}

fn canister_signature_for_message(
    message: Vec<u8>,
    canister_id: CanisterId,
    seed: &[u8],
    root_public_key: ThresholdSigPublicKey,
    root_secret_key: SecretKeyBytes,
) -> CanisterSig {
    use ic_certification_test_utils::CertificateBuilder;
    use ic_certification_test_utils::CertificateData;
    use ic_crypto_iccsa::types::Signature;

    let canister_state = canister_state_with_message(message, seed);
    let certificate_data = CertificateData::CanisterData {
        canister_id,
        certified_data: canister_state.root_digest,
    };
    let (_cert, _root_pk, cbor_cert) = CertificateBuilder::new(certificate_data)
        .with_root_of_trust(root_public_key, root_secret_key)
        .build();
    let sig_with_canister_witness = Signature {
        certificate: Blob(cbor_cert),
        tree: canister_state.witness,
    };
    CanisterSig(encode_sig(sig_with_canister_witness))
}

fn canister_state_with_message(message: Vec<u8>, seed: &[u8]) -> CanisterState {
    use ic_crypto_test_utils_canister_sigs::{new_canister_state_tree, witness_from_tree};

    let canister_state_tree = new_canister_state_tree(seed, &message[..]);
    let mixed_tree = witness_from_tree(canister_state_tree);
    let hash_tree_digest = mixed_tree.digest();

    CanisterState {
        seed: seed.to_vec(),
        msg: message,
        witness: mixed_tree,
        root_digest: hash_tree_digest,
    }
}
