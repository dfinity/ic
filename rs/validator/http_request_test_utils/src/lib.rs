use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair};
use ic_certification_test_utils::serialize_to_cbor;
use ic_crypto_internal_basic_sig_iccsa_test_utils::CanisterState;
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{CanisterSig, Signable};
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpRequest, HttpRequestEnvelope,
    MessageId, SignedDelegation, SignedIngressContent,
};
use ic_types::{CanisterId, PrincipalId, Time};
use simple_asn1::OID;
use std::convert::identity;
use strum_macros::EnumCount;

#[cfg(test)]
mod tests;

const ANONYMOUS_SENDER: u8 = 0x04;

pub struct HttpRequestBuilder<T> {
    content: HttpCanisterUpdate,
    authentication: T,
    overwrite_sender: Box<dyn FnOnce(Blob) -> Blob>,
    overwrite_sender_public_key: Box<dyn FnOnce(Option<Blob>) -> Option<Blob>>,
    overwrite_sender_signature: Box<dyn FnOnce(Option<Blob>) -> Option<Blob>>,
    #[allow(clippy::type_complexity)]
    overwrite_sender_delegations:
        Box<dyn FnOnce(Option<Vec<SignedDelegation>>) -> Option<Vec<SignedDelegation>>>,
}

impl Default for HttpRequestBuilder<AuthenticationScheme> {
    fn default() -> Self {
        HttpRequestBuilder {
            content: dummy_request_content(),
            authentication: AuthenticationScheme::Anonymous,
            overwrite_sender: Box::new(identity),
            overwrite_sender_public_key: Box::new(identity),
            overwrite_sender_signature: Box::new(identity),
            overwrite_sender_delegations: Box::new(identity),
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

impl<T: HttpRequestEnvelopeFactory> HttpRequestBuilder<T> {
    pub fn with_ingress_expiry_at(mut self, ingress_expiry_time: Time) -> Self {
        self.content.ingress_expiry = ingress_expiry_time.as_nanos_since_unix_epoch();
        self
    }

    pub fn with_canister_id(mut self, new_canister_id: Blob) -> Self {
        self.content.canister_id = new_canister_id;
        self
    }

    pub fn with_authentication<U: HttpRequestEnvelopeFactory>(
        self,
        authentication: U,
    ) -> HttpRequestBuilder<U> {
        HttpRequestBuilder {
            content: self.content,
            authentication,
            overwrite_sender: self.overwrite_sender,
            overwrite_sender_public_key: self.overwrite_sender_public_key,
            overwrite_sender_signature: self.overwrite_sender_signature,
            overwrite_sender_delegations: self.overwrite_sender_delegations,
        }
    }

    pub fn with_authentication_sender(mut self, new_sender: Blob) -> Self {
        self.overwrite_sender = Box::new(|_old_sender| new_sender);
        self
    }

    pub fn with_authentication_sender_being_anonymous(self) -> Self {
        self.with_authentication_sender(Blob(vec![ANONYMOUS_SENDER]))
    }

    pub fn with_authentication_sender_public_key(mut self, new_public_key: Option<Blob>) -> Self {
        self.overwrite_sender_public_key = Box::new(|_old_public_key| new_public_key);
        self
    }

    pub fn with_authentication_sender_delegations(
        mut self,
        new_delegations: Option<Vec<SignedDelegation>>,
    ) -> Self {
        self.overwrite_sender_delegations = Box::new(|_old_delegations| new_delegations);
        self
    }

    pub fn corrupt_authentication_sender_signature(mut self) -> Self {
        self.overwrite_sender_signature = Box::new(|signature| {
            let mut corrupted_signature = signature.expect("cannot corrupt emnpty signature");
            flip_a_bit_mut(&mut corrupted_signature.0);
            Some(corrupted_signature)
        });
        self
    }

    pub fn build(mut self) -> HttpRequest<SignedIngressContent> {
        self.content.sender = (self.overwrite_sender)(self.authentication.sender());
        let message_id = self.content.id();
        let sender_pubkey =
            (self.overwrite_sender_public_key)(self.authentication.sender_public_key());
        let sender_sig =
            (self.overwrite_sender_signature)(self.authentication.sender_signature(&message_id));
        let sender_delegation =
            (self.overwrite_sender_delegations)(self.authentication.sender_delegations());

        HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: self.content,
            },
            sender_pubkey,
            sender_sig,
            sender_delegation,
        })
        .expect("invalid HTTP request")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, EnumCount)]
pub enum AuthenticationScheme {
    Anonymous,
    Direct(DirectAuthenticationScheme),
    Delegation(DelegationChain),
}

#[derive(Debug, Clone, Eq, PartialEq)]
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
    pub fn public_key_raw(&self) -> Vec<u8> {
        use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
        match self {
            DirectAuthenticationScheme::UserKeyPair(keypair) => keypair.public_key.to_vec(),
            DirectAuthenticationScheme::CanisterSignature {
                seed, canister_id, ..
            } => canister_sig_pub_key_to_bytes(*canister_id, seed),
        }
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;

        match self {
            DirectAuthenticationScheme::UserKeyPair(_) => {
                ed25519_public_key_to_der(self.public_key_raw())
            }

            DirectAuthenticationScheme::CanisterSignature { .. } => {
                subject_public_key_info_der(oid_canister_signature(), &self.public_key_raw())
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

    /// Creates a delegation that only applies to requests sent to one of the canisters in the list of targets.
    fn delegate_to_with_targets(
        &self,
        other: &DirectAuthenticationScheme,
        expiration: Time,
        targets: Vec<CanisterId>,
    ) -> SignedDelegation {
        let delegation = Delegation::new_with_targets(other.public_key_der(), expiration, targets);
        let signature = self.sign(&delegation);
        SignedDelegation::new(delegation, signature)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DelegationChain {
    start: DirectAuthenticationScheme,
    end: DirectAuthenticationScheme,
    signed_delegations: Vec<SignedDelegation>,
}

impl DelegationChain {
    pub fn rooted_at(start: DirectAuthenticationScheme) -> DelegationChainBuilder {
        DelegationChainBuilder::new(start)
    }

    pub fn len(&self) -> usize {
        self.signed_delegations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signed_delegations.is_empty()
    }
}

#[derive(Debug, Clone)]
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

    pub fn current_end(&self) -> &DirectAuthenticationScheme {
        self.end.as_ref().unwrap_or(&self.start)
    }

    pub fn delegate_to(mut self, new_end: DirectAuthenticationScheme, expiration: Time) -> Self {
        let current_end = self.current_end();
        self.signed_delegations
            .push(current_end.delegate_to(&new_end, expiration));
        self.end = Some(new_end);
        self
    }

    pub fn delegate_to_with_targets(
        mut self,
        new_end: DirectAuthenticationScheme,
        expiration: Time,
        targets: Vec<CanisterId>,
    ) -> Self {
        let current_end = self.end.unwrap_or_else(|| self.start.clone());
        self.signed_delegations
            .push(current_end.delegate_to_with_targets(&new_end, expiration, targets));
        self.end = Some(new_end);
        self
    }

    pub fn change_last_delegation<F: FnOnce(SignedDelegationBuilder) -> SignedDelegationBuilder>(
        mut self,
        change: F,
    ) -> Self {
        let last_delegation = self
            .signed_delegations
            .pop()
            .expect("no delegations to change!");
        let new_delegation = change(last_delegation.into_builder()).build();
        self.signed_delegations.push(new_delegation);
        self
    }

    pub fn number_of_signed_delegations(&self) -> usize {
        self.signed_delegations.len()
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
    CanisterSig(serialize_to_cbor(&sig_with_canister_witness))
}

fn canister_state_with_message(message: Vec<u8>, seed: &[u8]) -> CanisterState {
    use ic_crypto_internal_basic_sig_iccsa_test_utils::{
        new_canister_state_tree, witness_from_tree,
    };

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

fn flip_a_bit_mut(input: &mut [u8]) {
    *input
        .last_mut()
        .expect("cannot flip a bit in an empty slice!") ^= 1;
}

pub trait IntoBuilder {
    type BuilderType;

    /// Creates a new builder that starts out with all the values given by `self`.
    /// This is particularly useful when `self` is an instance of an immutable struct
    /// and a slightly different instance is needed.
    fn into_builder(self) -> Self::BuilderType;
}

impl IntoBuilder for SignedDelegation {
    type BuilderType = SignedDelegationBuilder;

    fn into_builder(self) -> Self::BuilderType {
        let signature = self.signature().clone().0;
        let delegation = self.take_delegation();
        let pubkey = delegation.pubkey().clone();
        let expiration = delegation.expiration();
        let targets = delegation.targets().expect("invalid canister IDs");
        SignedDelegationBuilder {
            pubkey,
            expiration,
            targets: targets.map(|ids| ids.into_iter().collect()),
            signature,
        }
    }
}

pub struct SignedDelegationBuilder {
    pubkey: Vec<u8>,
    expiration: Time,
    targets: Option<Vec<CanisterId>>,
    signature: Vec<u8>,
}

impl SignedDelegationBuilder {
    pub fn build(self) -> SignedDelegation {
        let delegation = match self.targets {
            Some(canister_ids) => {
                Delegation::new_with_targets(self.pubkey, self.expiration, canister_ids)
            }
            None => Delegation::new(self.pubkey, self.expiration),
        };
        SignedDelegation::new(delegation, self.signature)
    }

    pub fn corrupt_signature(mut self) -> Self {
        flip_a_bit_mut(&mut self.signature);
        self
    }

    pub fn with_public_key(mut self, new_public_key: Vec<u8>) -> Self {
        self.pubkey = new_public_key;
        self
    }
}

fn oid_canister_signature() -> OID {
    use simple_asn1::oid;

    // OID 1.3.6.1.4.1.56387.1.2
    // (iso.org.dod.internet.private.enterprise.dfinity.mechanisms.canister-signature)
    // See https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
    oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2)
}
