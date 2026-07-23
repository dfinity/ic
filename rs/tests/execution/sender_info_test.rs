/* tag::catalog[]
end::catalog[] */

//! System test for the `sender_info` ingress feature.
//!
//! Verifies that a canister can read `msg_caller_info_data` and
//! `msg_caller_info_signer` when the caller attaches canister-signed
//! `sender_info` to a query and to an update. The request path is exercised
//! through the standard `ic-agent`, which carries `sender_info` via
//! `InfoAwareIdentity`.

use anyhow::Result;
use ic_agent::Identity;
use ic_agent::export::Principal;
use ic_agent::identity::InfoAwareIdentity;
use ic_crypto_sha2::Sha256;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, agent_with_identity, block_on};
use ic_types::crypto::Signable;
use ic_types::messages::SenderInfoContent;
use ic_universal_canister::wasm;
use serde::Serialize;
use serde_bytes::ByteBuf;
use slog::info;

const SIGNER_SEED: &[u8] = b"sender_info_test_seed";
const INFO_BYTES: &[u8] = b"some user attributes";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(query_reads_sender_info))
                .add_test(systest!(update_reads_sender_info)),
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

// ---------------------------------------------------------------------------
// UC-backed canister signer
// ---------------------------------------------------------------------------

/// A canister signer backed by a canister that responds to Universal Canister
/// bytecode: it sets `certified_data` to the digest of a witness tree over
/// `(seed, message)` and reads back the state certificate, forming an ICCSA
/// signature.
///
/// Owns its `Agent` and `canister_id` so it can be embedded in a `'static`
/// `Identity` handed to `agent_with_identity`.
#[derive(Clone)]
struct CanisterSigner {
    agent: ic_agent::Agent,
    canister_id: Principal,
    seed: Vec<u8>,
}

impl CanisterSigner {
    fn new(agent: ic_agent::Agent, canister_id: Principal, seed: Vec<u8>) -> Self {
        Self {
            agent,
            canister_id,
            seed,
        }
    }

    /// Raw canister-signature public key bytes: length-prefixed canister id
    /// followed by seed.
    fn public_key_raw(&self) -> Vec<u8> {
        let cid_bytes = self.canister_id.as_slice();
        let mut buf = vec![u8::try_from(cid_bytes.len()).expect("canister id too long for u8")];
        buf.extend_from_slice(cid_bytes);
        buf.extend_from_slice(&self.seed);
        buf
    }

    /// DER-encoded SubjectPublicKeyInfo with the canister-signature algorithm
    /// OID 1.3.6.1.4.1.56387.1.2.
    fn public_key_der(&self) -> Vec<u8> {
        use simple_asn1::{ASN1Block, oid};
        let oid_canister_signature = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2);
        let raw_key = self.public_key_raw();
        let algorithm = ASN1Block::Sequence(
            0,
            vec![ASN1Block::ObjectIdentifier(0, oid_canister_signature)],
        );
        let subject_public_key = ASN1Block::BitString(0, raw_key.len() * 8, raw_key);
        let subject_public_key_info = ASN1Block::Sequence(0, vec![algorithm, subject_public_key]);
        simple_asn1::to_der(&subject_public_key_info).expect("failed to DER-encode public key")
    }

    /// Produce an ICCSA signature over `message`. Sets `certified_data` on the
    /// underlying canister and captures the state certificate.
    async fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ic_certification::{HashTree, labeled, leaf};

        let seed_hash = Sha256::hash(&self.seed);
        let msg_hash = Sha256::hash(message);
        let sig_tree = labeled(b"sig", labeled(seed_hash, labeled(msg_hash, leaf(b""))));

        self.agent
            .update(&self.canister_id, "update")
            .with_arg(
                wasm()
                    .certified_data_set(&sig_tree.digest())
                    .reply()
                    .build(),
            )
            .call_and_wait()
            .await
            .expect("failed to set certified data on canister signer");
        let certificate_cbor = self
            .agent
            .query(&self.canister_id, "query")
            .with_arg(wasm().data_certificate().append_and_reply().build())
            .call()
            .await
            .expect("failed to read canister signer's certificate");

        #[derive(Serialize)]
        struct CanisterSignature {
            certificate: ByteBuf,
            tree: HashTree,
        }
        let canister_sig = CanisterSignature {
            certificate: ByteBuf::from(certificate_cbor),
            tree: sig_tree,
        };
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        canister_sig.serialize(&mut serializer).unwrap();
        serializer.into_inner()
    }
}

/// An `ic_agent::Identity` that authenticates as `self_authenticating(pk_der)`
/// where `pk_der` is a canister-signature SPKI. Signing produces an ICCSA
/// signature over the request id.
#[derive(Clone)]
struct CanisterSignerIdentity {
    signer: CanisterSigner,
    public_key_der: Vec<u8>,
    principal: Principal,
}

impl CanisterSignerIdentity {
    fn new(signer: CanisterSigner) -> Self {
        let public_key_der = signer.public_key_der();
        let principal = Principal::self_authenticating(&public_key_der);
        Self {
            signer,
            public_key_der,
            principal,
        }
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let fut = self.signer.sign(bytes);
        // The `Identity` trait's `sign*` methods are sync; the underlying
        // signer is async. Bridge with `block_in_place` since we run under a
        // multi-thread Tokio runtime.
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }
}

impl Identity for CanisterSignerIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.principal)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.public_key_der.clone())
    }

    fn sign(
        &self,
        content: &ic_agent::agent::EnvelopeContent,
    ) -> Result<ic_agent::Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(
        &self,
        content: &ic_agent::identity::Delegation,
    ) -> Result<ic_agent::Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<ic_agent::Signature, String> {
        Ok(ic_agent::Signature {
            public_key: Some(self.public_key_der.clone()),
            signature: Some(self.sign_bytes(content)),
            delegations: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Test bodies
// ---------------------------------------------------------------------------

/// Given an already-installed UC that will act as both signer and target,
/// returns an `ic-agent` that carries a canister-signed `sender_info` on every
/// request via `InfoAwareIdentity`.
async fn build_info_aware_agent(
    node_url: &str,
    bootstrap_agent: ic_agent::Agent,
    canister_id: Principal,
) -> ic_agent::Agent {
    let signer = CanisterSigner::new(bootstrap_agent, canister_id, SIGNER_SEED.to_vec());
    let inner = CanisterSignerIdentity::new(signer.clone());

    let sender_info_signable = SenderInfoContent(INFO_BYTES).as_signed_bytes();
    let sig = signer.sign(&sender_info_signable).await;

    let identity = InfoAwareIdentity::new_unchecked(inner, INFO_BYTES.to_vec(), sig)
        .expect("failed to build InfoAwareIdentity");
    agent_with_identity(node_url, identity)
        .await
        .expect("failed to build agent with InfoAwareIdentity")
}

/// Which ingress entry point to exercise.
#[derive(Clone, Copy, Debug)]
enum CallMode {
    Query,
    Update,
}

impl CallMode {
    fn method(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Update => "update",
        }
    }
}

/// Invokes the target canister with `arg` on the entry point picked by
/// `mode`, returning the reply bytes.
async fn call(
    agent: &ic_agent::Agent,
    canister_id: &Principal,
    mode: CallMode,
    arg: Vec<u8>,
) -> Vec<u8> {
    let method = mode.method();
    match mode {
        CallMode::Query => agent.query(canister_id, method).with_arg(arg).call().await,
        CallMode::Update => {
            agent
                .update(canister_id, method)
                .with_arg(arg)
                .call_and_wait()
                .await
        }
    }
    .unwrap_or_else(|e| panic!("{:?} call failed: {}", mode, e))
}

fn run_sender_info_test(env: TestEnv, mode: CallMode) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    block_on(async move {
        let bootstrap_agent = node.build_default_agent_async().await;
        let canister = UniversalCanister::new_with_retries(
            &bootstrap_agent,
            node.effective_canister_id(),
            &logger,
        )
        .await;
        let canister_id = canister.canister_id();
        let agent = build_info_aware_agent(
            node.get_public_url().as_str(),
            bootstrap_agent.clone(),
            canister_id,
        )
        .await;

        info!(logger, "{:?}: reading msg_caller_info_data", mode);
        let reply = call(
            &agent,
            &canister_id,
            mode,
            wasm().msg_caller_info_data().append_and_reply().build(),
        )
        .await;
        assert_eq!(reply, INFO_BYTES);

        info!(logger, "{:?}: reading msg_caller_info_signer", mode);
        let reply = call(
            &agent,
            &canister_id,
            mode,
            wasm().msg_caller_info_signer().append_and_reply().build(),
        )
        .await;
        assert_eq!(reply, canister_id.as_slice());
    });
}

pub fn query_reads_sender_info(env: TestEnv) {
    run_sender_info_test(env, CallMode::Query)
}

pub fn update_reads_sender_info(env: TestEnv) {
    run_sender_info_test(env, CallMode::Update)
}
