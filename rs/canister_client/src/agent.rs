//! An agent to talk to the Internet Computer through the public endpoints.
use crate::{
    cbor::{parse_canister_query_response, parse_read_state_response, RequestStatus},
    http_client::HttpClient,
};
use ed25519_dalek::{Keypair, Signer, KEYPAIR_LENGTH};
use ic_crypto_sha256::Sha256;
use ic_crypto_tree_hash::Path;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::catchup::CatchUpPackageParam,
    messages::{
        Blob, HttpReadContent, HttpRequestEnvelope, HttpStatusResponse, HttpSubmitContent,
        MessageId,
    },
    CanisterId, PrincipalId,
};
use prost::Message;
use serde_cbor::value::Value as CBOR;
use std::{error::Error, fmt, sync::Arc, time::Duration, time::Instant};
use tokio::time::delay_for;
use url::Url;

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_update' call.
const INGRESS_TIMEOUT: Duration = Duration::from_secs(60 * 6);

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_query' call.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// The HTTP path for query calls on the replica.
// TODO is this how v1 api works can we just change the URL?
pub fn query_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{}/query", cid)
}

pub fn read_state_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{}/read_state", cid)
}

/// The HTTP path for update calls on the replica.
pub fn update_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{}/call", cid)
}

const NODE_STATUS_PATH: &str = &"api/v2/status";
const CATCH_UP_PACKAGE_PATH: &str = &"/_/catch_up_package";

/// A version of Keypair with a clone instance.
/// Originally this was done with a reference, but I'm avoiding them in async
/// testing because it makes the tests much harder to write.
/// This is a little inefficient, but it's only used for testing
#[derive(Clone, Copy)]
pub struct ClonableKeyPair {
    pub bytes: [u8; KEYPAIR_LENGTH],
}

impl ClonableKeyPair {
    fn new(kp: &Keypair) -> Self {
        ClonableKeyPair {
            bytes: kp.to_bytes(),
        }
    }

    fn get(&self) -> Keypair {
        Keypair::from_bytes(&self.bytes).unwrap()
    }
}

pub type SignF = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;

#[derive(Clone)]
pub struct Secp256k1KeyPair {
    sk: ecdsa_secp256k1::types::SecretKeyBytes,
    pk: ecdsa_secp256k1::types::PublicKeyBytes,
}

#[derive(Clone)]
pub enum SigKeys {
    EcdsaSecp256k1(Secp256k1KeyPair),
}

/// Represents the identity of the sender.
#[derive(Clone)]
pub enum Sender {
    /// The sender is defined as public/private keypair.
    KeyPair(ClonableKeyPair),

    /// The sender is defined as a public/private keypair of a signature scheme,
    /// not bound to a specific scheme.
    /// TODO: add handling of Ed25519-keys, and remove `KeyPair`-variant above
    SigKeys(SigKeys),

    /// The sender is authenticated via an external HSM devices and the
    /// signature mechanism is specified through the provided function
    /// reference.
    ExternalHsm {
        /// DER encoded public key
        pub_key: Vec<u8>,
        /// Function that abstracts the external HSM.
        sign: SignF,
    },
    /// The anonymous sender is used (no signature).
    Anonymous,
    /// Principal ID (no signature)
    PrincipalId(PrincipalId),
}

impl Sender {
    pub fn from_keypair(kp: &Keypair) -> Self {
        Sender::KeyPair(ClonableKeyPair::new(kp))
    }

    pub fn from_secp256k1_keys(sk_bytes: &[u8], pk_bytes: &[u8]) -> Self {
        let pk = ecdsa_secp256k1::types::PublicKeyBytes::from(pk_bytes.to_vec());
        let sk = ecdsa_secp256k1::api::secret_key_from_components(sk_bytes, &pk).unwrap();
        Sender::SigKeys(SigKeys::EcdsaSecp256k1(Secp256k1KeyPair { sk, pk }))
    }

    pub fn from_external_hsm(pub_key: Vec<u8>, sign: SignF) -> Self {
        Sender::ExternalHsm { pub_key, sign }
    }

    pub fn from_principal_id(principal_id: PrincipalId) -> Self {
        Sender::PrincipalId(principal_id)
    }

    pub fn get_principal_id(&self) -> PrincipalId {
        match self {
            Self::KeyPair(keypair) => PrincipalId::new_self_authenticating(
                &ed25519_public_key_to_der(keypair.get().public.to_bytes().to_vec()),
            ),
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::EcdsaSecp256k1(key_pair) => PrincipalId::new_self_authenticating(
                    &ecdsa_secp256k1::api::public_key_to_der(&key_pair.pk).unwrap(),
                ),
            },
            Self::ExternalHsm { pub_key, .. } => PrincipalId::new_self_authenticating(pub_key),
            Self::Anonymous => PrincipalId::new_anonymous(),
            Self::PrincipalId(id) => *id,
        }
    }

    pub fn sign_message_id(&self, msg_id: &MessageId) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut sig_data = vec![];
        sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
        sig_data.extend_from_slice(msg_id.as_bytes());
        self.sign(&sig_data)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        match self {
            Self::KeyPair(keypair) => Ok(Some(keypair.get().sign(msg).to_bytes().to_vec())),
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    // ECDSA CLib impl. does not hash the message (as hash algorithm can vary
                    // in ECDSA), so we do it here with SHA256, which is the only
                    // supported hash currently.
                    let msg_hash = Sha256::hash(msg);
                    Ok(Some(
                        ecdsa_secp256k1::api::sign(&msg_hash, &key_pair.sk)
                            .expect("ECDSA-secp256k1 signing failed")
                            .0
                            .to_vec(),
                    ))
                }
            },
            Self::ExternalHsm { sign, .. } => sign(msg).map(Some),
            Self::Anonymous => Ok(None),
            Self::PrincipalId(_) => Ok(None),
        }
    }

    pub fn sender_pubkey_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::KeyPair(keypair) => Some(ed25519_public_key_to_der(
                keypair.get().public.to_bytes().to_vec(),
            )),
            Self::SigKeys(sig_keys) => match sig_keys {
                SigKeys::EcdsaSecp256k1(key_pair) => {
                    Some(ecdsa_secp256k1::api::public_key_to_der(&key_pair.pk).unwrap())
                }
            },
            Self::ExternalHsm { pub_key, .. } => Some(pub_key.clone()),
            Self::Anonymous => None,
            Self::PrincipalId(_) => None,
        }
    }
}

/// An agent to talk to the Internet Computer through the public endpoints.
#[derive(Clone)]
pub struct Agent {
    /// Url of the replica to target. This should NOT contain a URL path like
    /// "/api/v1/submit".
    pub url: Url,

    // How long to wait for ingress requests.
    ingress_timeout: Duration,

    // How long to wait for queries.
    query_timeout: Duration,

    // Per reqwest document, cloning a client does not clone the actual connection pool inside.
    // Therefore directly owning a client as opposed to a reference is the standard way to go.
    http_client: Arc<HttpClient>,

    pub sender: Sender,

    /// The values that any 'sender' field should have when issuing
    /// calls with the user corresponding to this Agent.
    pub sender_field: Blob,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("url", &self.url)
            .field("ingress_timeout", &self.ingress_timeout)
            .field("query_timeout", &self.query_timeout)
            .field("sender", &self.sender_field)
            .finish()
    }
}

impl Agent {
    /// Creates an agent.
    ///
    /// `url`: Url of the replica to target. This should NOT contain a URL path
    /// like "/api/v1/submit". It should contain a port, if needed.
    ///
    /// The `sender` identifies the sender on whose behalf the requests are
    /// sent. If the requests are authenticated, the corresponding `pub_key` and
    /// `sender_sig` field are set in the request envelope.
    pub fn new(url: Url, sender: Sender) -> Self {
        let http_client = Arc::new(HttpClient::new());
        Self::build_agent(url, http_client, sender)
    }

    /// Creates an agent.
    ///
    /// Same as above except gives the caller the option to retain a
    /// pre-existing client.
    pub fn new_with_client(http_client: HttpClient, url: Url, sender: Sender) -> Self {
        Self::build_agent(url, Arc::new(http_client), sender)
    }

    /// This is needed by rust_canister tests
    pub fn new_for_test(&self, sender: Sender) -> Self {
        Self::build_agent(self.url.clone(), self.http_client.clone(), sender)
    }

    /// Helper to create the agent
    fn build_agent(url: Url, http_client: Arc<HttpClient>, sender: Sender) -> Self {
        let sender_field = Blob(sender.get_principal_id().into_vec());
        Self {
            url,
            ingress_timeout: INGRESS_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            http_client,
            sender,
            sender_field,
        }
    }

    /// Sets the timeout for ingress requests.
    pub fn with_ingress_timeout(mut self, ingress_timeout: Duration) -> Self {
        self.ingress_timeout = ingress_timeout;
        self
    }

    /// Sets the timeout for queries.
    pub fn with_query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }

    /// Queries the cup endpoint given the provided CatchUpPackageParams.
    pub async fn query_cup_endpoint(
        &self,
        param: Option<CatchUpPackageParam>,
    ) -> Result<Option<pb::CatchUpPackage>, String> {
        let body = param
            .and_then(|param| serde_cbor::to_vec(&param).ok())
            .unwrap_or_default();
        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                CATCH_UP_PACKAGE_PATH,
                body,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await?;

        // Response is either empty or a protobuf encoded byte stream.
        let cup = if bytes.is_empty() {
            None
        } else {
            Some(pb::CatchUpPackage::decode(&bytes[..]).map_err(|e| {
                format!(
                    "Failed to deserialize CUP from protobuf, got: {:?} - error {:?}",
                    bytes, e
                )
            })?)
        };

        Ok(cup)
    }

    /// Calls the query method 'method' on the given canister,
    /// optionally with 'arguments'.
    pub async fn execute_query(
        &self,
        canister_id: &CanisterId,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let envelope = self
            .prepare_query(canister_id, method, arg)
            .map_err(|e| format!("Failed to prepare query: {}", e))?;
        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                &query_path(*canister_id),
                envelope,
                tokio::time::Instant::now() + self.query_timeout,
            )
            .await?;
        let cbor = bytes_to_cbor(bytes)?;

        let call_response = parse_canister_query_response(&cbor)?;
        if call_response.status == "replied" {
            Ok(call_response.reply)
        } else {
            Err(format!(
                "The response of a canister query call contained status '{}' and message '{:?}'",
                call_response.status, call_response.reject_message
            ))
        }
    }

    /// Calls the query method 'method' on the canister located at 'url',
    /// optionally with 'arguments'.
    pub async fn execute_update<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + self.ingress_timeout;
        let (http_body, request_id) = self
            .prepare_update(canister_id, method, arguments, nonce)
            .map_err(|err| format!("{}", err))?;
        self.http_client
            .post_with_response(
                &self.url,
                &update_path(*canister_id),
                http_body,
                tokio::time::Instant::from_std(deadline),
            )
            .await?;

        // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
        const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
        const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;

        let mut poll_interval = MIN_POLL_INTERVAL;
        let mut next_poll_time = Instant::now() + poll_interval;

        while next_poll_time < deadline {
            delay_for(poll_interval).await;

            match self
                .wait_ingress(request_id.clone(), deadline, canister_id)
                .await
            {
                Ok(request_status) => match request_status.status.as_ref() {
                    "replied" => {
                        return Ok(request_status.reply);
                    }
                    "unknown" | "received" | "processing" => {}
                    _ => {
                        return Err(format!(
                            "unexpected result: {:?} - {:?}",
                            request_status.status, request_status.reject_message
                        ))
                    }
                },
                Err(e) => return Err(format!("Unexpected error: {:?}", e)),
            }

            // Bump the poll interval and compute the next poll time (based on current wall
            // time, so we don't spin without delay after a slow poll).
            poll_interval = poll_interval
                .mul_f32(POLL_INTERVAL_MULTIPLIER)
                .min(MAX_POLL_INTERVAL);
            next_poll_time += poll_interval;
        }
        Err(format!(
            "Request took longer than the deadline {:?} to complete.",
            deadline
        ))
    }

    /// Requests the status of a pending request once.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    ///
    /// Returns the entire CBOR value from the response, without trying to
    /// interpret it.
    async fn request_status_once(
        &self,
        request_id: MessageId,
        deadline: Instant,
        canister_id: &CanisterId,
    ) -> Result<CBOR, String> {
        let path = Path::new(vec!["request_status".into(), request_id.into()]);
        let status_request_body = self
            .prepare_read_state(&[path])
            .map_err(|e| format!("Failed to prepare read state: {:?}", e))?;

        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                &read_state_path(*canister_id),
                status_request_body,
                tokio::time::Instant::from_std(deadline),
            )
            .await?;
        bytes_to_cbor(bytes)
    }

    /// Requests the status of a pending canister update call request exactly
    /// once using the `read_state` API.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    pub async fn wait_ingress(
        &self,
        request_id: MessageId,
        deadline: Instant,
        canister_id: &CanisterId,
    ) -> Result<RequestStatus, String> {
        let cbor = self
            .request_status_once(request_id.clone(), deadline, canister_id)
            .await?;
        parse_read_state_response(&request_id, cbor)
    }

    async fn get_status_with_response(&self) -> Result<HttpStatusResponse, String> {
        let bytes = self
            .http_client
            .get_with_response(
                &self.url,
                NODE_STATUS_PATH,
                tokio::time::Instant::now() + self.query_timeout,
            )
            .await?;
        let resp = bytes_to_cbor(bytes)?;
        serde_cbor::value::from_value::<HttpStatusResponse>(resp)
            .map_err(|source| format!("decoding to HttpStatusResponse failed: {}", source))
    }

    /// Requests the version of the public spec supported by this node by
    /// querying /api/v1/status.
    pub async fn ic_api_version(&self) -> Result<String, String> {
        let response = self.get_status_with_response().await?;
        Ok(response.ic_api_version)
    }

    /// Requests the Replica impl version of this node by querying
    /// /api/v1/status
    pub async fn impl_version(&self) -> Result<Option<String>, String> {
        let response = self.get_status_with_response().await?;
        Ok(response.impl_version)
    }

    /// Requests the root key of this node by querying /api/v1/status
    pub async fn root_key(&self) -> Result<Option<Blob>, String> {
        let response = self.get_status_with_response().await?;

        Ok(response.root_key)
    }

    pub fn http_client(&self) -> &HttpClient {
        self.http_client.as_ref()
    }
}

/// This is a minimal implementation of DER-encoding for Ed25519, as the keys
/// are constant-length. The format is an ASN.1 SubjectPublicKeyInfo, whose
/// header contains the OID for Ed25519, as specified in RFC 8410:
/// https://tools.ietf.org/html/rfc8410
pub fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    // The constant is the prefix of the DER encoding of the ASN.1
    // SubjectPublicKeyInfo data structure. It can be read as follows:
    // 0x30 0x2A: Sequence of length 42 bytes
    //   0x30 0x05: Sequence of length 5 bytes
    //     0x06 0x03 0x2B 0x65 0x70: OID of length 3 bytes, 1.3.101.112 (where 43 =
    //              1 * 40 + 3)
    //   0x03 0x21: Bit string of length 33 bytes
    //     0x00 [raw key]: No padding [raw key]
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    encoded.append(&mut key);
    encoded
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: `content` contains a `sender` field that is compatible with
/// the `keypair` argument.
pub fn sign_submit(
    content: HttpSubmitContent,
    sender: &Sender,
) -> Result<(HttpRequestEnvelope<HttpSubmitContent>, MessageId), Box<dyn Error>> {
    // Open question: should this also set the `sender` field of the `content`? The
    // two are linked, but it's a bit weird for a function that presents itself
    // as 'wrapping a content into an envelope' to mess up with the content.

    let message_id = match &content {
        HttpSubmitContent::Call { update } => update.id(),
    };

    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    };
    Ok((envelope, message_id))
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: if `content` contains a `sender` field (this is the case for
/// queries, but not for request_status), then this 'sender' must be compatible
/// with the `keypair` argument.
pub fn sign_read(
    content: HttpReadContent,
    sender: &Sender,
) -> Result<HttpRequestEnvelope<HttpReadContent>, Box<dyn Error>> {
    let message_id = content.id();
    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    Ok(HttpRequestEnvelope::<HttpReadContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    })
}

fn bytes_to_cbor(bytes: Vec<u8>) -> Result<CBOR, String> {
    let cbor = serde_cbor::from_slice(&bytes).map_err(|e| {
        format!(
            "Agent::bytes_to_cbor: Failed to parse result from IC, got: {:?} - error {:?}",
            String::from_utf8(
                bytes
                    .iter()
                    .copied()
                    .map(std::ascii::escape_default)
                    .flatten()
                    .collect()
            )
            .expect("ASCII is legal utf8"),
            e
        )
    })?;
    Ok(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_types::messages::{HttpCanisterUpdate, HttpRequest, HttpUserQuery, ReadContent};
    use ic_types::time::current_time;
    use ic_types::{PrincipalId, RegistryVersion, UserId};
    use ic_validator::get_authorized_canisters;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::convert::TryFrom;
    use tokio_test::assert_ok;

    // The node id of the node that validates message signatures
    const VALIDATOR_NODE_ID: u64 = 42;
    fn mock_registry_version() -> RegistryVersion {
        RegistryVersion::from(0)
    }

    /// Create an HttpRequest with a non-anonymous user and then verify
    /// that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_with_ed25519() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);
        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(789 as u64);
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(
                    UserId::from(PrincipalId::new_self_authenticating(
                        &ed25519_public_key_to_der(keypair.public.to_bytes().to_vec()),
                    ))
                    .get()
                    .into_vec(),
                ),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let sender = Sender::from_keypair(&keypair);
        let (submit, id) = sign_submit(content.clone(), &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version()
        )
        .unwrap()
        .contains(&request.content().canister_id()));
    }

    /// Create an HttpRequest with a non-anonymous user and then verify
    /// that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_with_ecdsa_secp256k1() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);
        // Set up an arbitrary legal input
        // Set up an arbitrary legal input
        let (sk, pk) = {
            let mut rng = ChaChaRng::seed_from_u64(89 as u64);
            let sk = secp256k1::SecretKey::random(&mut rng);
            let pk = secp256k1::PublicKey::from_secret_key(&sk);
            (sk.serialize(), pk.serialize())
        };
        let sender_id = UserId::from(PrincipalId::new_self_authenticating(
            &ecdsa_secp256k1::api::public_key_to_der(
                &ecdsa_secp256k1::types::PublicKeyBytes::from(pk.to_vec()),
            )
            .expect("DER encoding failed"),
        ));
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),
                nonce: None,
                sender: Blob(sender_id.get().into_vec()),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let sender = Sender::from_secp256k1_keys(&sk, &pk);
        let (submit, id) = sign_submit(content.clone(), &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version()
        )
        .unwrap()
        .contains(&request.content().canister_id()));
    }

    /// Create an HttpRequest with an explicit anonymous user and then
    /// verify that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_explicit_anonymous() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(UserId::from(PrincipalId::new_anonymous()).get().into_vec()),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let (submit, id) = sign_submit(content.clone(), &Sender::Anonymous).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version()
        )
        .unwrap()
        .contains(&request.content().canister_id()));
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query_with_ed25519() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(89 as u64);
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let sender = UserId::from(PrincipalId::new_self_authenticating(
            &ed25519_public_key_to_der(keypair.public.to_bytes().to_vec()),
        ));
        let content = HttpReadContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(sender.get().into_vec()),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpReadContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpReadContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let read = sign_read(content, &Sender::from_keypair(&keypair)).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let read_request = HttpRequest::<ReadContent>::try_from(read).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert_ok!(get_authorized_canisters(
            &read_request,
            &validator,
            test_start_time,
            mock_registry_version()
        ));
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query_with_ecdsa_secp256k1() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let (sk, pk) = {
            let mut rng = ChaChaRng::seed_from_u64(89 as u64);
            let sk = secp256k1::SecretKey::random(&mut rng);
            let pk = secp256k1::PublicKey::from_secret_key(&sk);
            (sk.serialize(), pk.serialize())
        };

        let sender_id = UserId::from(PrincipalId::new_self_authenticating(
            &ecdsa_secp256k1::api::public_key_to_der(
                &ecdsa_secp256k1::types::PublicKeyBytes::from(pk.to_vec()),
            )
            .expect("DER encoding failed"),
        ));
        let content = HttpReadContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(sender_id.get().into_vec()),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpReadContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpReadContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let sender = Sender::from_secp256k1_keys(&sk, &pk);
        let read = sign_read(content, &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let read_request = HttpRequest::<ReadContent>::try_from(read).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert_ok!(get_authorized_canisters(
            &read_request,
            &validator,
            test_start_time,
            mock_registry_version()
        ));
    }
}
