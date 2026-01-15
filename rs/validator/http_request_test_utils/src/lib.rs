use crate::DirectAuthenticationScheme::{CanisterSignature, UserKeyPair};
use ic_canister_client_sender::{Ed25519KeyPair, ed25519_public_key_to_der};
use ic_certification_test_utils::{generate_root_of_trust, serialize_to_cbor};
use ic_crypto_internal_basic_sig_iccsa_test_utils::CanisterState;
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_tree_hash::Path;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{CanisterSig, Signable};
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
    HttpReadStateContent, HttpRequest, HttpRequestEnvelope, HttpUserQuery, MessageId, Query,
    ReadState, SignedDelegation, SignedIngressContent,
};
use ic_types::time::GENESIS;
use ic_types::{CanisterId, PrincipalId, Time};
use rand::{CryptoRng, Rng};
use simple_asn1::OID;
use std::convert::identity;
use std::fmt::{Debug, Formatter};
use strum_macros::EnumCount;

#[cfg(test)]
mod tests;

const ANONYMOUS_SENDER: u8 = 0x04;
pub const CANISTER_ID_SIGNER: CanisterId = CanisterId::from_u64(1185);
pub const CANISTER_SIGNATURE_SEED: [u8; 1] = [42];
pub const CURRENT_TIME: Time = GENESIS;

pub type HttpRequestBuilder<C> = HttpRequestBuilderGeneric<C, AuthenticationScheme>;
pub struct HttpRequestBuilderGeneric<C, T> {
    content: C,
    authentication: T,
    overwrite_sender: Box<dyn FnOnce(Blob) -> Blob>,
    overwrite_sender_public_key: Box<dyn FnOnce(Option<Blob>) -> Option<Blob>>,
    overwrite_sender_signature: Box<dyn FnOnce(Option<Blob>) -> Option<Blob>>,
    #[allow(clippy::type_complexity)]
    overwrite_sender_delegations:
        Box<dyn FnOnce(Option<Vec<SignedDelegation>>) -> Option<Vec<SignedDelegation>>>,
}

impl HttpRequestBuilderGeneric<HttpCanisterUpdate, AuthenticationScheme> {
    pub fn new_update_call() -> Self {
        HttpRequestBuilderGeneric {
            content: dummy_call_request_content(),
            authentication: AuthenticationScheme::Anonymous,
            overwrite_sender: Box::new(identity),
            overwrite_sender_public_key: Box::new(identity),
            overwrite_sender_signature: Box::new(identity),
            overwrite_sender_delegations: Box::new(identity),
        }
    }
}

impl HttpRequestBuilderGeneric<HttpUserQuery, AuthenticationScheme> {
    pub fn new_query() -> Self {
        HttpRequestBuilderGeneric {
            content: dummy_query_call_request_content(),
            authentication: AuthenticationScheme::Anonymous,
            overwrite_sender: Box::new(identity),
            overwrite_sender_public_key: Box::new(identity),
            overwrite_sender_signature: Box::new(identity),
            overwrite_sender_delegations: Box::new(identity),
        }
    }
}

impl HttpRequestBuilderGeneric<HttpReadState, AuthenticationScheme> {
    pub fn new_read_state() -> Self {
        HttpRequestBuilderGeneric {
            content: dummy_read_state_request_content(),
            authentication: AuthenticationScheme::Anonymous,
            overwrite_sender: Box::new(identity),
            overwrite_sender_public_key: Box::new(identity),
            overwrite_sender_signature: Box::new(identity),
            overwrite_sender_delegations: Box::new(identity),
        }
    }
}

impl<C: Debug, T: Debug> Debug for HttpRequestBuilderGeneric<C, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HttpRequestBuilder {{ content: {:?}, authentication: {:?} }}",
            self.content, self.authentication
        )
    }
}

fn dummy_call_request_content() -> HttpCanisterUpdate {
    HttpCanisterUpdate {
        canister_id: Blob(vec![42; 8]),
        method_name: "some_method".to_string(),
        arg: Default::default(),
        sender: Default::default(),
        ingress_expiry: 0,
        nonce: None,
    }
}

fn dummy_query_call_request_content() -> HttpUserQuery {
    HttpUserQuery {
        canister_id: Blob(vec![42; 8]),
        method_name: "some_method".to_string(),
        arg: Default::default(),
        sender: Default::default(),
        ingress_expiry: 0,
        nonce: None,
    }
}

fn dummy_read_state_request_content() -> HttpReadState {
    HttpReadState {
        sender: Default::default(),
        paths: vec![],
        ingress_expiry: 0,
        nonce: None,
    }
}

impl<C, T: HttpRequestEnvelopeFactory> HttpRequestBuilderGeneric<C, T> {
    pub fn with_authentication<U: HttpRequestEnvelopeFactory>(
        self,
        authentication: U,
    ) -> HttpRequestBuilderGeneric<C, U> {
        HttpRequestBuilderGeneric {
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
            let mut corrupted_signature = signature.expect("cannot corrupt empty signature");
            flip_a_bit_mut(&mut corrupted_signature.0);
            Some(corrupted_signature)
        });
        self
    }
}

impl<C: HttpRequestEnvelopeContent, T> HttpRequestBuilderGeneric<C, T> {
    pub fn with_ingress_expiry_at(mut self, ingress_expiry_time: Time) -> Self {
        self.content.set_ingress_expiry(ingress_expiry_time);
        self
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.content.set_nonce(nonce);
        self
    }
}

impl<T> HttpRequestBuilderGeneric<HttpReadState, T> {
    pub fn with_paths(mut self, paths: Vec<Path>) -> Self {
        self.content.paths = paths;
        self
    }
}

impl<ReqContent, EnvelopeContent, Auth> HttpRequestBuilderGeneric<EnvelopeContent, Auth>
where
    EnvelopeContent: HttpRequestEnvelopeContent<HttpRequestContentType = ReqContent>,
    Auth: HttpRequestEnvelopeFactory,
{
    pub fn build(mut self) -> HttpRequest<ReqContent> {
        self.content
            .set_sender((self.overwrite_sender)(self.authentication.sender()));
        let message_id = self.content.id();
        let sender_pubkey =
            (self.overwrite_sender_public_key)(self.authentication.sender_public_key());
        let sender_sig =
            (self.overwrite_sender_signature)(self.authentication.sender_signature(&message_id));
        let sender_delegation =
            (self.overwrite_sender_delegations)(self.authentication.sender_delegations());

        self.content
            .into_request(sender_pubkey, sender_sig, sender_delegation)
    }
}

impl<C: HttpRequestEnvelopeContentWithCanisterId, T: HttpRequestEnvelopeFactory>
    HttpRequestBuilderGeneric<C, T>
{
    pub fn with_canister_id(mut self, new_canister_id: Blob) -> Self {
        self.content.set_canister_id(new_canister_id);
        self
    }
}

/// A trait to unify HttpCanisterUpdate, HttpUserQuery and HttpReadState
pub trait HttpRequestEnvelopeContent {
    type HttpRequestContentType;

    fn set_sender(&mut self, sender: Blob);
    fn set_ingress_expiry(&mut self, ingress_expiry: Time);

    fn set_nonce(&mut self, nonce: Vec<u8>);
    fn id(&self) -> MessageId;
    fn into_request(
        self,
        sender_pubkey: Option<Blob>,
        sender_sig: Option<Blob>,
        sender_delegation: Option<Vec<SignedDelegation>>,
    ) -> HttpRequest<Self::HttpRequestContentType>;
}

pub trait HttpRequestEnvelopeContentWithCanisterId {
    fn set_canister_id(&mut self, canister_id: Blob);
}

impl HttpRequestEnvelopeContent for HttpCanisterUpdate {
    type HttpRequestContentType = SignedIngressContent;

    fn set_sender(&mut self, sender: Blob) {
        self.sender = sender;
    }

    fn set_ingress_expiry(&mut self, ingress_expiry: Time) {
        self.ingress_expiry = ingress_expiry.as_nanos_since_unix_epoch();
    }

    fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = Some(Blob(nonce));
    }

    fn id(&self) -> MessageId {
        MessageId::from(self.representation_independent_hash())
    }

    fn into_request(
        self,
        sender_pubkey: Option<Blob>,
        sender_sig: Option<Blob>,
        sender_delegation: Option<Vec<SignedDelegation>>,
    ) -> HttpRequest<Self::HttpRequestContentType> {
        HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call { update: self },
            sender_pubkey,
            sender_sig,
            sender_delegation,
        })
        .expect("valid HTTP request")
    }
}

impl HttpRequestEnvelopeContentWithCanisterId for HttpCanisterUpdate {
    fn set_canister_id(&mut self, canister_id: Blob) {
        self.canister_id = canister_id;
    }
}

impl HttpRequestEnvelopeContent for HttpUserQuery {
    type HttpRequestContentType = Query;

    fn set_sender(&mut self, sender: Blob) {
        self.sender = sender;
    }

    fn set_ingress_expiry(&mut self, ingress_expiry: Time) {
        self.ingress_expiry = ingress_expiry.as_nanos_since_unix_epoch();
    }

    fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = Some(Blob(nonce));
    }

    fn id(&self) -> MessageId {
        MessageId::from(self.representation_independent_hash())
    }

    fn into_request(
        self,
        sender_pubkey: Option<Blob>,
        sender_sig: Option<Blob>,
        sender_delegation: Option<Vec<SignedDelegation>>,
    ) -> HttpRequest<Self::HttpRequestContentType> {
        HttpRequest::try_from(HttpRequestEnvelope::<HttpQueryContent> {
            content: HttpQueryContent::Query { query: self },
            sender_pubkey,
            sender_sig,
            sender_delegation,
        })
        .expect("valid HTTP request")
    }
}

impl HttpRequestEnvelopeContentWithCanisterId for HttpUserQuery {
    fn set_canister_id(&mut self, canister_id: Blob) {
        self.canister_id = canister_id;
    }
}

impl HttpRequestEnvelopeContent for HttpReadState {
    type HttpRequestContentType = ReadState;

    fn set_sender(&mut self, sender: Blob) {
        self.sender = sender;
    }

    fn set_ingress_expiry(&mut self, ingress_expiry: Time) {
        self.ingress_expiry = ingress_expiry.as_nanos_since_unix_epoch();
    }

    fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = Some(Blob(nonce));
    }

    fn id(&self) -> MessageId {
        MessageId::from(self.representation_independent_hash())
    }

    fn into_request(
        self,
        sender_pubkey: Option<Blob>,
        sender_sig: Option<Blob>,
        sender_delegation: Option<Vec<SignedDelegation>>,
    ) -> HttpRequest<Self::HttpRequestContentType> {
        HttpRequest::try_from(HttpRequestEnvelope::<HttpReadStateContent> {
            content: HttpReadStateContent::ReadState { read_state: self },
            sender_pubkey,
            sender_sig,
            sender_delegation,
        })
        .expect("valid HTTP request")
    }
}

#[derive(Clone, Eq, PartialEq, Debug, EnumCount)]
pub enum AuthenticationScheme {
    Anonymous,
    Direct(DirectAuthenticationScheme),
    Delegation(DelegationChain),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CanisterSigner {
    pub seed: Vec<u8>,
    pub canister_id: CanisterId,
    pub root_public_key: ThresholdSigPublicKey,
    pub root_secret_key: SecretKeyBytes,
}

impl CanisterSigner {
    pub fn canister_public_key_raw(&self) -> Vec<u8> {
        use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
        canister_sig_pub_key_to_bytes(self.canister_id, &self.seed)
    }

    pub fn sign<T: Signable>(&self, message: &T) -> CanisterSig {
        use ic_certification_test_utils::CertificateBuilder;
        use ic_certification_test_utils::CertificateData;
        use ic_crypto_iccsa::types::Signature;
        use ic_crypto_internal_basic_sig_iccsa_test_utils::{
            new_canister_state_tree, witness_from_tree,
        };

        let canister_state = {
            let message_to_sign = message.as_signed_bytes();
            let canister_state_tree = new_canister_state_tree(&self.seed, &message_to_sign);
            let mixed_tree = witness_from_tree(canister_state_tree);
            let hash_tree_digest = mixed_tree.digest();

            CanisterState {
                seed: self.seed.to_vec(),
                msg: message_to_sign,
                witness: mixed_tree,
                root_digest: hash_tree_digest,
            }
        };

        let certificate_data = CertificateData::CanisterData {
            canister_id: self.canister_id,
            certified_data: canister_state.root_digest,
        };
        let (_cert, _root_pk, cbor_cert) = CertificateBuilder::new(certificate_data)
            .with_root_of_trust(self.root_public_key, self.root_secret_key.clone())
            .build();
        let sig_with_canister_witness = Signature {
            certificate: Blob(cbor_cert),
            tree: canister_state.witness,
        };
        CanisterSig(serialize_to_cbor(&sig_with_canister_witness))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DirectAuthenticationScheme {
    UserKeyPair(Ed25519KeyPair),
    CanisterSignature(CanisterSigner),
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
        match self {
            DirectAuthenticationScheme::UserKeyPair(keypair) => keypair.public_key.to_vec(),
            DirectAuthenticationScheme::CanisterSignature(signer) => {
                signer.canister_public_key_raw()
            }
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
            DirectAuthenticationScheme::CanisterSignature(signer) => signer.sign(message).0,
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

#[derive(Clone, Eq, PartialEq, Debug)]
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

#[derive(Clone, Debug)]
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

/// Construct a delegation chain rooted at the first element in the vector
/// of direct authentication schemes that delegates to the next element.
impl From<(Vec<DirectAuthenticationScheme>, Time)> for DelegationChainBuilder {
    fn from((schemes, expiration): (Vec<DirectAuthenticationScheme>, Time)) -> Self {
        assert!(
            !schemes.is_empty(),
            "cannot build delegation chain from empty vector of authentication schemes"
        );
        let mut builder = None;
        for scheme in schemes.into_iter() {
            builder = match builder {
                None => Some(DelegationChain::rooted_at(scheme)),
                Some(prev_builder) => Some(prev_builder.delegate_to(scheme, expiration)),
            }
        }
        builder.expect("cannot be empty")
    }
}

pub fn flip_a_bit_mut(input: &mut [u8]) {
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

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RootOfTrust {
    pub public_key: ThresholdSigPublicKey,
    pub secret_key: SecretKeyBytes,
}

impl RootOfTrust {
    pub fn new_random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let (public_key, secret_key) = generate_root_of_trust(rng);
        RootOfTrust {
            public_key,
            secret_key,
        }
    }
}

pub fn all_authentication_schemes<R: Rng + CryptoRng>(rng: &mut R) -> Vec<AuthenticationScheme> {
    use strum::EnumCount;

    let schemes = vec![
        AuthenticationScheme::Anonymous,
        AuthenticationScheme::Direct(random_user_key_pair(rng)),
        AuthenticationScheme::Direct(canister_signature_with_hard_coded_root_of_trust()),
        AuthenticationScheme::Delegation(
            DelegationChain::rooted_at(random_user_key_pair(rng))
                .delegate_to(random_user_key_pair(rng), CURRENT_TIME)
                .build(),
        ),
    ];
    assert_eq!(schemes.len(), AuthenticationScheme::COUNT + 1);
    schemes
}

pub fn all_authentication_schemes_except<R: Rng + CryptoRng>(
    exception: AuthenticationScheme,
    rng: &mut R,
) -> Vec<AuthenticationScheme> {
    let all_schemes = all_authentication_schemes(rng);
    all_schemes
        .into_iter()
        .filter(|scheme| scheme != &exception)
        .collect()
}

pub fn random_user_key_pair<R: Rng + CryptoRng>(rng: &mut R) -> DirectAuthenticationScheme {
    UserKeyPair(Ed25519KeyPair::generate(rng))
}

pub fn canister_signature_with_hard_coded_root_of_trust() -> DirectAuthenticationScheme {
    canister_signature(hard_coded_root_of_trust())
}

pub fn canister_signature(root_of_trust: RootOfTrust) -> DirectAuthenticationScheme {
    CanisterSignature(CanisterSigner {
        seed: CANISTER_SIGNATURE_SEED.to_vec(),
        canister_id: CANISTER_ID_SIGNER,
        root_public_key: root_of_trust.public_key,
        root_secret_key: root_of_trust.secret_key,
    })
}

pub fn hard_coded_root_of_trust() -> RootOfTrust {
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
    use ic_crypto_secrets_containers::SecretArray;

    const ROOT_OF_TRUST_PUBLIC_KEY_BYTES: [u8; 96] = [
        152, 219, 31, 20, 68, 111, 213, 221, 156, 86, 221, 18, 142, 166, 221, 206, 74, 193, 225,
        199, 24, 146, 180, 58, 0, 224, 163, 131, 175, 49, 45, 203, 92, 166, 2, 191, 98, 128, 79,
        191, 103, 152, 95, 3, 230, 140, 98, 80, 23, 139, 212, 185, 70, 195, 15, 58, 10, 73, 28,
        186, 83, 34, 195, 148, 210, 6, 115, 167, 155, 233, 213, 229, 174, 102, 44, 112, 231, 238,
        186, 167, 154, 241, 122, 206, 52, 52, 127, 205, 84, 203, 97, 160, 135, 103, 43, 74,
    ];
    const ROOT_OF_TRUST_SECRET_KEY: [u8; 32] = [
        91, 5, 19, 183, 21, 92, 188, 34, 41, 208, 100, 138, 160, 79, 45, 79, 251, 98, 10, 131, 65,
        199, 151, 20, 46, 28, 231, 217, 89, 240, 217, 154,
    ];
    let public_key =
        ThresholdSigPublicKey::from(bls12_381::PublicKeyBytes(ROOT_OF_TRUST_PUBLIC_KEY_BYTES));
    let secret_key = SecretKeyBytes::new(SecretArray::new_and_dont_zeroize_argument(
        &ROOT_OF_TRUST_SECRET_KEY,
    ));
    RootOfTrust {
        public_key,
        secret_key,
    }
}
