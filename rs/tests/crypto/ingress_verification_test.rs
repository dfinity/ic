/* tag::catalog[]
end::catalog[] */
use anyhow::Result;
use candid::Encode;
use ic_agent::Identity;
use ic_agent::export::Principal;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::types::CanisterIdRecord;
use ic_system_test_driver::util::{
    UniversalCanister, agent_with_identity, block_on, expiry_time, sign_query, sign_read_state,
    sign_update,
};
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
    HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, MessageId, SignedDelegation,
};
use ic_types::{CanisterId, PrincipalId, Time};
use ic_universal_canister::wasm;
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};
use reqwest::{StatusCode, Url};
use slog::debug;

const ALL_QUERY_API_VERSIONS: &[usize] = &[2, 3];
const ALL_UPDATE_API_VERSIONS: &[usize] = &[2, 3, 4];
const ALL_READ_STATE_API_VERSIONS: &[usize] = &[2, 3];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(requests_with_delegations))
                .add_test(systest!(requests_with_delegations_with_targets))
                .add_test(systest!(requests_with_delegation_loop))
                .add_test(systest!(requests_to_mgmt_canister_with_delegations))
                .add_test(systest!(requests_with_invalid_expiry))
                .add_test(systest!(requests_with_canister_signature)),
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

#[derive(Clone, Debug)]
struct TestInformation {
    url: Url,
    canister_id: CanisterId,
}

#[derive(Copy, Clone)]
enum GenericIdentityType<'a> {
    Ed25519,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    Canister(&'a UniversalCanister<'a>),
    WebAuthnEcdsaSecp256r1,
    WebAuthnRsaPkcs1,
}

impl<'a> GenericIdentityType<'a> {
    fn random_incl_canister<R: Rng + CryptoRng>(
        canister: &'a UniversalCanister<'a>,
        rng: &mut R,
    ) -> Self {
        match rng.r#gen::<usize>() % 6 {
            0 => Self::EcdsaSecp256k1,
            1 => Self::EcdsaSecp256r1,
            2 => Self::Canister(canister),
            3 => Self::WebAuthnEcdsaSecp256r1,
            4 => Self::WebAuthnRsaPkcs1,
            _ => Self::Ed25519,
        }
    }

    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        match rng.r#gen::<usize>() % 5 {
            0 => Self::EcdsaSecp256k1,
            1 => Self::EcdsaSecp256r1,
            2 => Self::WebAuthnEcdsaSecp256r1,
            3 => Self::WebAuthnRsaPkcs1,
            _ => Self::Ed25519,
        }
    }
}

#[derive(Clone)]
enum GenericIdentityInner<'a> {
    K256(ic_secp256k1::PrivateKey),
    P256(ic_secp256r1::PrivateKey),
    Ed25519(ic_ed25519::PrivateKey),
    Canister(CanisterSigner<'a>),
    WebAuthnEcdsaSecp256r1(ic_secp256r1::PrivateKey),
    WebAuthnRsaPkcs1(rsa::RsaPrivateKey),
}

#[derive(Clone)]
struct GenericIdentity<'a> {
    inner: GenericIdentityInner<'a>,
    public_key_der: Vec<u8>,
    principal: Principal,
}

impl<'a> GenericIdentity<'a> {
    fn new<R: Rng + CryptoRng>(typ: GenericIdentityType<'a>, rng: &mut R) -> Self {
        let (inner, public_key_der) = match typ {
            GenericIdentityType::Ed25519 => {
                let sk = ic_ed25519::PrivateKey::generate_using_rng(rng);
                let pk = sk.public_key().serialize_rfc8410_der();
                (GenericIdentityInner::Ed25519(sk), pk)
            }
            GenericIdentityType::EcdsaSecp256k1 => {
                let sk = ic_secp256k1::PrivateKey::generate_using_rng(rng);
                let pk = sk.public_key().serialize_der();
                (GenericIdentityInner::K256(sk), pk)
            }
            GenericIdentityType::EcdsaSecp256r1 => {
                let sk = ic_secp256r1::PrivateKey::generate_using_rng(rng);
                let pk = sk.public_key().serialize_der();
                (GenericIdentityInner::P256(sk), pk)
            }
            GenericIdentityType::Canister(canister) => {
                let seed = random_n_bytes(32, rng); // Different seed means different identity/public key.
                let signer = CanisterSigner::new(canister, seed);
                let pk = signer.public_key_der();
                (GenericIdentityInner::Canister(signer), pk)
            }
            GenericIdentityType::WebAuthnEcdsaSecp256r1 => {
                let sk = ic_secp256r1::PrivateKey::generate_using_rng(rng);
                let pk = webauthn_cose_wrap_ecdsa_secp256r1_key(&sk.public_key());
                (GenericIdentityInner::WebAuthnEcdsaSecp256r1(sk), pk)
            }
            GenericIdentityType::WebAuthnRsaPkcs1 => {
                let sk = rsa::RsaPrivateKey::new(rng, 2048).expect("RSA keygen failed");
                let pk = webauthn_cose_wrap_rsa_pkcs1_key(&rsa::RsaPublicKey::from(&sk));
                (GenericIdentityInner::WebAuthnRsaPkcs1(sk), pk)
            }
        };

        let principal = Principal::self_authenticating(&public_key_der);

        Self {
            inner,
            public_key_der,
            principal,
        }
    }

    fn new_canister(canister_signer: CanisterSigner<'a>) -> Self {
        let pk = canister_signer.public_key_der();
        let principal = Principal::self_authenticating(&pk);
        Self {
            inner: GenericIdentityInner::Canister(canister_signer),
            public_key_der: pk,
            principal,
        }
    }

    fn principal(&self) -> &Principal {
        &self.principal
    }

    fn public_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    fn sign_query(&self, query: &HttpQueryContent) -> Vec<u8> {
        sign_query(query, self)
            .signature
            .clone()
            .expect("Signature missing")
    }

    fn sign_update(&self, update: &HttpCallContent) -> Vec<u8> {
        sign_update(update, self)
            .signature
            .clone()
            .expect("Signature missing")
    }

    fn sign_read_state(&self, read_state: &HttpReadStateContent) -> Vec<u8> {
        sign_read_state(read_state, self)
            .signature
            .clone()
            .expect("Signature missing")
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        match &self.inner {
            GenericIdentityInner::Ed25519(sk) => sk.sign_message(bytes).to_vec(),
            GenericIdentityInner::K256(sk) => sk.sign_message_with_ecdsa(bytes).to_vec(),
            GenericIdentityInner::P256(sk) => sk.sign_message(bytes).to_vec(),
            GenericIdentityInner::WebAuthnEcdsaSecp256r1(sk) => {
                webauthn_sign_ecdsa_secp256r1(sk, bytes)
            }
            GenericIdentityInner::WebAuthnRsaPkcs1(sk) => webauthn_sign_rsa_pkcs1(sk, bytes),
            GenericIdentityInner::Canister(canister_signer) => {
                let sign_future = canister_signer.sign(bytes);
                // We are in a sync method and need to call the async `CanisterSigner::sign`,
                // which can be done with `tokio::runtime::Handle::block_on`. However, we
                // cannot call `block_on` directly because the containing method itself is
                // (directly) executed within a `block_on`, i.e,. without, e.g., any
                // `spawn_blocking`s in between. Therefore, we need to wrap the call to
                // `block_on` in a `block_in_place` as a workaround (which is usually discouraged,
                // because it points to a design flaw in the overall architecture).
                #[allow(clippy::disallowed_methods)]
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(sign_future)
                })
            }
        }
    }
}

impl Identity for GenericIdentity<'_> {
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
        let signature = self.sign_bytes(content);

        Ok(ic_agent::Signature {
            public_key: Some(self.public_key_der()),
            signature: Some(signature),
            delegations: None,
        })
    }
}

#[derive(Clone)]
struct CanisterSigner<'a> {
    canister: &'a UniversalCanister<'a>,
    seed: Vec<u8>,
    // If set, this RNG seed will be used to create a random BLS12-381
    // signature for the canister signature's certificate. We use a
    // seed for simplicity instead of an RNG to avoid further generics.
    random_certificate_signature_rng_seed: Option<[u8; 32]>,
}

impl<'a> CanisterSigner<'a> {
    pub fn new(canister: &'a UniversalCanister<'a>, seed: Vec<u8>) -> Self {
        Self {
            canister,
            seed,
            random_certificate_signature_rng_seed: None,
        }
    }

    pub fn with_random_certificate_signature(self, seed: [u8; 32]) -> Self {
        Self {
            random_certificate_signature_rng_seed: Some(seed),
            ..self
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        canister_id_from_principal(&self.canister.canister_id())
    }

    pub fn public_key_raw(&self) -> Vec<u8> {
        use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
        canister_sig_pub_key_to_bytes(self.canister_id(), &self.seed)
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
        use simple_asn1::oid;
        // OID 1.3.6.1.4.1.56387.1.2
        // (iso.org.dod.internet.private.enterprise.dfinity.mechanisms.canister-signature)
        // See https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures
        let oid_canister_signature = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2);
        subject_public_key_info_der(oid_canister_signature, &self.public_key_raw()).unwrap()
    }

    pub async fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ic_certification::{HashTree, labeled, leaf};
        use ic_crypto_sha2::Sha256;
        use serde::Serialize;
        use serde_bytes::ByteBuf;

        let seed_hash = Sha256::hash(&self.seed);
        let msg_hash = Sha256::hash(message);
        let sig_tree = labeled(b"sig", labeled(seed_hash, labeled(msg_hash, leaf(b""))));

        let mut certificate_cbor = self.certify_variable(&sig_tree.digest()).await;

        if let Some(rng_seed) = self.random_certificate_signature_rng_seed {
            let rng = &mut StdRng::from_seed(rng_seed);
            certificate_cbor = resign_certificate_with_random_signature(&certificate_cbor, rng);
        }

        #[derive(serde::Serialize)]
        struct CanisterSignature {
            certificate: ByteBuf,
            tree: HashTree,
        }
        let canister_sig = CanisterSignature {
            certificate: ByteBuf::from(certificate_cbor),
            tree: sig_tree,
        };
        // serialize to self-describing CBOR
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        canister_sig.serialize(&mut serializer).unwrap();
        serializer.into_inner()
    }

    async fn certify_variable(&self, variable_data: &[u8]) -> Vec<u8> {
        use ic_universal_canister::wasm;

        let _ = self
            .canister
            .update(wasm().certified_data_set(variable_data).reply().build())
            .await
            .expect("failed to call universal canister to set certified data");

        self.canister
            .query(wasm().data_certificate().append_and_reply().build())
            .await
            .expect("failed to call universal canister to get data certificate")
    }
}

// Test requests with delegations without targets
//
// This tests with various numbers of delegations (including no delegations)
pub fn requests_with_delegations(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            let test_info = TestInformation {
                url: node_url,
                canister_id: canister_id_from_principal(&canister.canister_id()),
            };

            for delegation_count in 0..32 {
                let mut identities = Vec::with_capacity(delegation_count + 1);

                for _ in 0..=delegation_count {
                    let id_type = GenericIdentityType::random_incl_canister(&canister, rng);
                    identities.push(GenericIdentity::new(id_type, rng));
                }

                let delegations = create_delegations(&identities);

                let sender = &identities[0];
                let signer = &identities[identities.len() - 1];

                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response = perform_update_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    if delegation_count <= 20 {
                        if api_ver == 2 {
                            assert_eq!(response.status(), 202);
                            response.expect_empty_body();
                        } else {
                            assert_eq!(response.status(), 200);
                            response.expect_certificate();
                        }
                    } else {
                        assert_eq!(response.status(), 400);
                        response.expect_text_error(&format!("Invalid delegation: Chain of delegations is too long: got {delegation_count} delegations, but at most 20 are allowed."));
                    }
                }

                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response = perform_query_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    if delegation_count <= 20 {
                        assert_eq!(response.status(), 200);
                        response.expect_cbor_reply();
                    } else {
                        assert_eq!(response.status(), 400);
                        response.expect_text_error(&format!("Invalid delegation: Chain of delegations is too long: got {delegation_count} delegations, but at most 20 are allowed."));
                    }
                }
            }
        }
    });
}

// Tests for ingress messages with delegations using canister targets
pub fn requests_with_delegations_with_targets(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            let canister_id = canister_id_from_principal(&canister.canister_id());

            let test_info = TestInformation {
                url: node_url,
                canister_id,
            };

            struct DelegationTest {
                note: &'static str,
                targets: Vec<Vec<CanisterId>>,
                expected_err: Option<String>,
            }

            impl DelegationTest {
                fn expect_success(&self) -> bool {
                    self.expected_err.is_none()
                }

                fn accept(note: &'static str, targets: Vec<Vec<CanisterId>>) -> Self {
                    Self {
                        note,
                        targets,
                        expected_err: None,
                    }
                }

                fn reject(
                    note: &'static str,
                    targets: Vec<Vec<CanisterId>>,
                    expected_err: &str,
                ) -> Self {
                    Self {
                        note,
                        targets,
                        expected_err: Some(expected_err.to_owned()),
                    }
                }
            }

            let scenarios = [
                DelegationTest::accept(
                    "Two delegations each with a singleton target containing the requested canister ID",
                    vec![vec![canister_id], vec![canister_id]],
                ),
                DelegationTest::accept(
                    "One delegation with no target restriction and one with the canister ID",
                    vec![vec![], vec![canister_id]],
                ),
                DelegationTest::accept(
                    "One delegation with the canister ID and one with no target restriction",
                    vec![vec![canister_id], vec![]],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (10), including the canister ID",
                    vec![random_canister_ids_including(&canister_id, 10, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (100), including the canister ID",
                    vec![random_canister_ids_including(&canister_id, 100, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (1000), including the canister ID",
                    vec![random_canister_ids_including(&canister_id, 1000, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (10), including the canister ID multiple times",
                    vec![random_canister_ids_including(&canister_id, 10, 2, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (100), including the canister ID multiple times",
                    vec![random_canister_ids_including(&canister_id, 100, 10, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (1000), including the canister ID multiple times",
                    vec![random_canister_ids_including(&canister_id, 1000, 50, rng)],
                ),
                DelegationTest::reject(
                    "Not containing the requested canister ID",
                    vec![vec![random_canister_id(rng)]],
                    "is not one of the delegation targets",
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (1001)",
                    vec![random_canister_ids_including(&canister_id, 1001, 1, rng)],
                    "Invalid delegation: Delegation target error: expected at most 1000 targets per delegation, but got 1001",
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (2000)",
                    vec![random_canister_ids_including(&canister_id, 2000, 1, rng)],
                    "Invalid delegation: Delegation target error: expected at most 1000 targets per delegation, but got 2000",
                ),
                DelegationTest::reject(
                    "With an empty target intersection of multiple delegations with non-empty sets of targets",
                    vec![
                        vec![random_canister_id(rng)],
                        vec![canister_id, random_canister_id(rng)],
                    ],
                    "is not one of the delegation targets",
                ),
                DelegationTest::reject(
                    "With an empty target intersection of multiple delegations",
                    vec![vec![random_canister_id(rng)], vec![random_canister_id(rng)]],
                    "is not one of the delegation targets",
                ),
            ];

            for scenario in &scenarios {
                let delegation_count = scenario.targets.len();

                let mut identities = Vec::with_capacity(delegation_count + 1);

                for _ in 0..=delegation_count {
                    let id_type = GenericIdentityType::random_incl_canister(&canister, rng);
                    identities.push(GenericIdentity::new(id_type, rng));
                }

                let delegations = create_delegations_with_targets(&identities, &scenario.targets);

                let sender = &identities[0];
                let signer = &identities[identities.len() - 1];

                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response = perform_query_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    if scenario.expect_success() {
                        assert_eq!(
                            response.status(),
                            200,
                            "Test scenario {} (query) using {api_ver} unexpectedly failed",
                            scenario.note
                        );
                        response.expect_cbor_reply();
                    } else {
                        assert_eq!(
                            response.status(),
                            400,
                            "Test scenario {} (query) using {api_ver} unexpectedly succeeded",
                            scenario.note
                        );
                        response.expect_text_error(&scenario.expected_err.clone().unwrap());
                    }
                }

                for &api_ver in ALL_READ_STATE_API_VERSIONS {
                    let response = perform_read_state_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    if scenario.expect_success() {
                        assert_eq!(
                            response.status(),
                            200,
                            "Test scenario {} (read_state) using {api_ver} unexpectedly failed",
                            scenario.note
                        );
                    } else {
                        // Which error code is returned depends on API version and the specific scenario
                        assert!(
                            response.status() == 400 || response.status() == 403,
                            "Test scenario {} (read_state) using {api_ver} unexpectedly succeeded",
                            scenario.note
                        );

                        let err_msg = scenario.expected_err.clone().unwrap();

                        // The read request sometimes returns a different error message
                        // than update/query depending on the type of malformed req.

                        if err_msg.contains("expected at most") {
                            response.expect_text_error(&err_msg);
                        } else {
                            response.expect_text_error("The user tries to access request IDs for canisters not belonging to sender delegation targets.");
                        }
                    }
                }

                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response = perform_update_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    if scenario.expect_success() {
                        let expected_update_result = if api_ver == 2 { 202 } else { 200 };

                        assert_eq!(
                            response.status(),
                            expected_update_result,
                            "Test scenario {} (update) using {api_ver} unexpectedly failed",
                            scenario.note
                        );
                        if api_ver == 2 {
                            response.expect_empty_body();
                        } else {
                            response.expect_certificate();
                        }
                    } else {
                        assert_eq!(
                            response.status(),
                            400,
                            "Test scenario {} (update) using {api_ver} returned unexpected code",
                            scenario.note
                        );
                        response.expect_text_error(&scenario.expected_err.clone().unwrap());
                    }
                }
            }
        }
    });
}

// Tests for handling of delegation loops
pub fn requests_with_delegation_loop(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            let canister_id = canister_id_from_principal(&canister.canister_id());

            let test_info = TestInformation {
                url: node_url,
                canister_id,
            };

            // Both a self-loop and an indirect cycle in delegations should be rejected

            let expected_err_msg = "Invalid delegation: Chain of delegations contains at least one cycle: first repeating public key encountered";

            let ids_to_generate = 3;
            for duplicated_id_index in [
                ids_to_generate - 1, /* self-loop */
                ids_to_generate - 2, /* indirect cycle */
            ] {
                let mut identities: Vec<_> = (0..ids_to_generate)
                    .map(|_| GenericIdentity::new(GenericIdentityType::random(rng), rng))
                    .collect();

                identities.push(identities[duplicated_id_index].clone());

                let delegations = create_delegations(&identities);

                let sender = &identities.first().unwrap();
                let signer = &identities.last().unwrap();

                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response = perform_query_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;
                    assert_eq!(response.status(), 400);
                    response.expect_text_error(expected_err_msg);
                }

                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response = perform_update_call_with_delegations(
                        api_ver,
                        &test_info,
                        sender,
                        signer,
                        &delegations,
                    )
                    .await;

                    assert_eq!(response.status(), 400);
                    response.expect_text_error(expected_err_msg);
                }
            }
        }
    });
}

// Tests delegation handling for requests sent to the management canister
pub fn requests_to_mgmt_canister_with_delegations(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let user = GenericIdentity::new(GenericIdentityType::Ed25519, rng);

            // We create an agent with an identity we can control so that
            // the universal canister is installed with `user` as a controller.
            // Otherwise the canister_status calls would be rejected.
            let agent = agent_with_identity(node.get_public_url().as_str(), user.clone())
                .await
                .unwrap();

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            let canister_id = canister_id_from_principal(&canister.canister_id());

            let mgmt_canister = canister_id_from_principal(&Principal::management_canister());

            let test_info = TestInformation {
                url: node_url,
                canister_id: mgmt_canister,
            };

            /*
            This is testing two different scenarios, one of which should succeed and the
            other should fail:

            - With the mgmt canister principal as the target for mgmt canister calls

            - With an empty set of targets or a set of targets not containing the
              requested canister ID for mgmt canister calls.

            The only difference is if the management canister's principal is included in the
            set of delegation targets or not.
            */
            for include_mgmt_canister_id in [true, false] {
                let delegation_count = 4;
                let targets_per_delegation = 10;

                let mut identities = vec![];
                let mut targets = vec![];

                identities.push(user.clone());

                for _ in 1..=delegation_count {
                    let id_type = GenericIdentityType::random(rng);
                    identities.push(GenericIdentity::new(id_type, rng));
                    let target_canister_ids = if include_mgmt_canister_id {
                        random_canister_ids_including(
                            &mgmt_canister,
                            targets_per_delegation,
                            1,
                            rng,
                        )
                    } else {
                        random_canister_ids(targets_per_delegation, rng)
                    };

                    targets.push(target_canister_ids);
                }

                let delegations = create_delegations_with_targets(&identities, &targets);

                let sender = &identities[0];

                let signer = &identities[identities.len() - 1];

                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    // Test behavior with update
                    let content = HttpCallContent::Call {
                        update: HttpCanisterUpdate {
                            canister_id: Blob(mgmt_canister.get().as_slice().to_vec()),
                            method_name: "canister_status".to_string(),
                            arg: Blob(
                                Encode!(&CanisterIdRecord {
                                    canister_id: canister_id.into()
                                })
                                .unwrap(),
                            ),
                            sender: Blob(sender.principal().as_slice().to_vec()),
                            ingress_expiry: expiry_time().as_nanos() as u64,
                            nonce: None,
                        },
                    };

                    let signature = signer.sign_update(&content);

                    let response = send_request(
                        api_ver,
                        &test_info,
                        "call",
                        content,
                        sender.public_key_der(),
                        Some(delegations.to_vec()),
                        signature,
                    )
                    .await;

                    if include_mgmt_canister_id {
                        let expected_update = if api_ver == 2 { 202 } else { 200 };
                        assert_eq!(response.status(), expected_update);
                    } else {
                        assert_eq!(response.status(), 400);
                        response.expect_text_error(
                            "Canister 'aaaaa-aa' is not one of the delegation targets.",
                        );
                    }
                }

                for &api_ver in ALL_READ_STATE_API_VERSIONS {
                    /*
                     * In order to properly test read state request we must have another
                     * call to check the status of.
                     */
                    let request_id = {
                        let content = HttpCallContent::Call {
                            update: HttpCanisterUpdate {
                                canister_id: Blob(mgmt_canister.get().as_slice().to_vec()),
                                method_name: "canister_status".to_string(),
                                arg: Blob(
                                    Encode!(&CanisterIdRecord {
                                        canister_id: canister_id.into()
                                    })
                                    .unwrap(),
                                ),
                                sender: Blob(sender.principal().as_slice().to_vec()),
                                ingress_expiry: expiry_time().as_nanos() as u64,
                                nonce: None,
                            },
                        };

                        let signature = sender.sign_update(&content);
                        let request_id = MessageId::from(content.representation_independent_hash());

                        // Always use a v3 call to test read state request since the call is sync,
                        // otherwise we have to wait until the call executes before checking the read state, which
                        // requires a potentially flaky retry loop.

                        let response = send_request(
                            /*api_ver=*/ 3,
                            &test_info,
                            "call",
                            content,
                            sender.public_key_der(),
                            None,
                            signature,
                        )
                        .await;

                        assert_eq!(response.status(), 200);

                        request_id
                    };

                    let paths = vec![vec!["request_status".into(), (request_id).into()].into()];

                    let content = HttpReadStateContent::ReadState {
                        read_state: HttpReadState {
                            sender: Blob(sender.principal().as_slice().to_vec()),
                            paths,
                            ingress_expiry: expiry_time().as_nanos() as u64,
                            nonce: None,
                        },
                    };

                    let signature = signer.sign_read_state(&content);

                    let response = send_request(
                        api_ver,
                        &test_info,
                        "read_state",
                        content,
                        sender.public_key_der(),
                        Some(delegations.to_vec()),
                        signature,
                    )
                    .await;

                    if include_mgmt_canister_id {
                        assert_eq!(response.status(), 200);
                        response.expect_certificate();
                    } else {
                        assert_eq!(response.status(), 403);
                        response.expect_text_error("The user tries to access request IDs for canisters not belonging to sender delegation targets.");
                    }
                }

                for &api_ver in ALL_QUERY_API_VERSIONS {
                    // Test behavior with query
                    let content = HttpQueryContent::Query {
                        query: HttpUserQuery {
                            canister_id: Blob(mgmt_canister.get().as_slice().to_vec()),
                            method_name: "canister_status".to_string(),
                            arg: Blob(
                                Encode!(&CanisterIdRecord {
                                    canister_id: canister_id.into()
                                })
                                .unwrap(),
                            ),
                            sender: Blob(sender.principal().as_slice().to_vec()),
                            ingress_expiry: expiry_time().as_nanos() as u64,
                            nonce: None,
                        },
                    };

                    let signature = signer.sign_query(&content);

                    let response = send_request(
                        api_ver,
                        &test_info,
                        "query",
                        content,
                        sender.public_key_der(),
                        Some(delegations.to_vec()),
                        signature,
                    )
                    .await;

                    if include_mgmt_canister_id {
                        assert_eq!(response.status(), 200);
                        response.expect_cbor_reply();
                    } else {
                        assert_eq!(response.status(), 400);
                        response.expect_text_error(
                            "Canister 'aaaaa-aa' is not one of the delegation targets.",
                        );
                    }
                }
            }
        }
    });
}

// Tests that expired or too-future ingress_expiry values are rejected
pub fn requests_with_invalid_expiry(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            let test_info = TestInformation {
                url: node_url,
                canister_id: canister_id_from_principal(&canister.canister_id()),
            };

            // Single identity for sender and signer, no delegations
            let rng = &mut reproducible_rng();
            let id_type = GenericIdentityType::random_incl_canister(&canister, rng);
            let id = GenericIdentity::new(id_type, rng);

            let expiry_error_text =
                "Invalid request expiry: Specified ingress_expiry not within expected range";
            for expiry in [0_u64, u64::MAX] {
                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response =
                        perform_query_with_expiry(api_ver, &test_info, &id, &id, expiry).await;
                    response.expect_text_error(expiry_error_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "query should be rejected for expiry={expiry} and api_ver={api_ver}"
                    );
                }
                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response =
                        perform_update_with_expiry(api_ver, &test_info, &id, &id, expiry).await;
                    response.expect_text_error(expiry_error_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "update should be rejected for expiry={expiry} and api_ver={api_ver}"
                    );
                }
                for &api_ver in ALL_READ_STATE_API_VERSIONS {
                    let response =
                        perform_read_state_call_with_expiry(api_ver, &test_info, &id, &id, expiry)
                            .await;
                    response.expect_text_error(expiry_error_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "read_state should be rejected for expiry={expiry} and api_ver={api_ver}"
                    );
                }
            }
        }
    });
}

pub fn requests_with_canister_signature(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let c1 =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            debug!(
                logger,
                "Installed Universal Canister 1";
                "canister_id" => format!("{:?}", c1.canister_id())
            );

            ///////////////////////////////////////////////////////////////////
            // Empty and non-empty seeds should work
            for seed in [vec![], random_n_bytes(rng.gen_range(1..=32), rng)] {
                // Single canister identity for sender and signer, no delegations
                let id = GenericIdentity::new_canister(CanisterSigner::new(&c1, seed.clone()));
                let test_info = TestInformation {
                    url: node_url.clone(),
                    canister_id: canister_id_from_principal(&c1.canister_id()),
                };
                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response =
                        perform_query_call_with_delegations(api_ver, &test_info, &id, &id, &[])
                            .await;

                    assert_eq!(
                        response.status(),
                        200,
                        "query should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
                    response.expect_cbor_reply();
                }
                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response =
                        perform_update_call_with_delegations(api_ver, &test_info, &id, &id, &[])
                            .await;
                    assert_eq!(
                        response.status(),
                        if api_ver == 2 { 202 } else { 200 },
                        "update should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
                    if api_ver == 2 {
                        response.expect_empty_body();
                    } else {
                        response.expect_certificate();
                    }
                }
                for &api_ver in ALL_READ_STATE_API_VERSIONS {
                    let response = perform_read_state_call_with_delegations(
                        api_ver,
                        &test_info,
                        &id,
                        &id,
                        &[],
                    )
                    .await;

                    assert_eq!(
                        response.status(),
                        200,
                        "read_state should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
                    response.expect_certificate();
                }
            }

            ///////////////////////////////////////////////////////////////////
            // Using wrong seed or canister ID for deriving the sender should fail
            let c2 =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            debug!(
                logger,
                "Installed Universal Canister 2";
                "canister_id" => format!("{:?}", c2.canister_id())
            );

            let canister_sig_err_text = "Invalid signature: Invalid canister signature: ";

            let seed = b"seed";
            let id = GenericIdentity::new_canister(CanisterSigner::new(&c1, seed.to_vec()));
            let wrong_seed = b"wrong_seed";
            assert_ne!(seed.to_vec(), wrong_seed.to_vec());
            for sender in [
                GenericIdentity::new_canister(CanisterSigner::new(&c1, wrong_seed.to_vec())),
                GenericIdentity::new_canister(CanisterSigner::new(&c2, seed.to_vec())), // wrong canister
            ] {
                let test_info = TestInformation {
                    url: node_url.clone(),
                    canister_id: canister_id_from_principal(&c1.canister_id()),
                };
                for &api_ver in ALL_QUERY_API_VERSIONS {
                    let response =
                        perform_query_call_with_delegations(api_ver, &test_info, &sender, &id, &[])
                            .await;
                    response.expect_text_error(canister_sig_err_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "query should be rejected for api_ver={api_ver}"
                    );
                }
                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    let response = perform_update_call_with_delegations(
                        api_ver,
                        &test_info,
                        &sender,
                        &id,
                        &[],
                    )
                    .await;
                    response.expect_text_error(canister_sig_err_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "update should be rejected for api_ver={api_ver}"
                    );
                }
                for &api_ver in ALL_READ_STATE_API_VERSIONS {
                    let response = perform_read_state_call_with_delegations(
                        api_ver,
                        &test_info,
                        &sender,
                        &id,
                        &[],
                    )
                    .await;
                    response.expect_text_error(canister_sig_err_text);
                    assert_eq!(
                        response.status(),
                        400,
                        "read_state should be rejected for api_ver={api_ver}"
                    );
                }
            }

            ///////////////////////////////////////////////////////////////////
            // Requests should fail when the canister signature certificate is
            // signed by an invalid root key
            let id = GenericIdentity::new_canister(
                CanisterSigner::new(&c1, b"seed".to_vec())
                    .with_random_certificate_signature(rng.r#gen()),
            );
            let test_info = TestInformation {
                url: node_url.clone(),
                canister_id: canister_id_from_principal(&c1.canister_id()),
            };
            for &api_ver in ALL_QUERY_API_VERSIONS {
                let response =
                    perform_query_call_with_delegations(api_ver, &test_info, &id, &id, &[]).await;
                response.expect_text_error(canister_sig_err_text);
                assert_eq!(
                    response.status(),
                    400,
                    "query should be rejected for api_ver={api_ver} with invalid certificate signature"
                );
            }
            for &api_ver in ALL_UPDATE_API_VERSIONS {
                let response =
                    perform_update_call_with_delegations(api_ver, &test_info, &id, &id, &[]).await;
                response.expect_text_error(canister_sig_err_text);
                assert_eq!(
                    response.status(),
                    400,
                    "update should be rejected for api_ver={api_ver} with invalid certificate signature"
                );
            }
            for &api_ver in ALL_READ_STATE_API_VERSIONS {
                let response =
                    perform_read_state_call_with_delegations(api_ver, &test_info, &id, &id, &[])
                        .await;
                response.expect_text_error(canister_sig_err_text);
                assert_eq!(
                    response.status(),
                    400,
                    "read_state should be rejected for api_ver={api_ver} with invalid certificate signature"
                );
            }
        }
    });
}

fn create_delegations(identities: &[GenericIdentity]) -> Vec<SignedDelegation> {
    let delegation_expiry = Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

    let delegation_count = identities.len() - 1;
    let mut delegations = Vec::with_capacity(delegation_count);

    if delegation_count > 0 {
        for i in 1..=delegation_count {
            let delegation = Delegation::new(identities[i].public_key_der(), delegation_expiry);
            let signed_delegation = sign_delegation(delegation, &identities[i - 1]);
            delegations.push(signed_delegation);
        }
    }

    delegations
}

fn canister_id_from_principal(p: &Principal) -> CanisterId {
    if *p == Principal::management_canister() {
        CanisterId::ic_00()
    } else {
        CanisterId::try_from_principal_id(PrincipalId::from(*p)).expect("invalid canister ID")
    }
}

fn create_delegations_with_targets(
    identities: &[GenericIdentity],
    targets: &[Vec<CanisterId>],
) -> Vec<SignedDelegation> {
    let delegation_expiry = Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

    let delegation_count = identities.len() - 1;
    let mut delegations = Vec::with_capacity(delegation_count);

    if delegation_count > 0 {
        for i in 1..=delegation_count {
            let delegation = if targets[i - 1].is_empty() {
                Delegation::new(identities[i].public_key_der(), delegation_expiry)
            } else {
                Delegation::new_with_targets(
                    identities[i].public_key_der(),
                    delegation_expiry,
                    targets[i - 1].clone(),
                )
            };

            let signed_delegation = sign_delegation(delegation, &identities[i - 1]);

            delegations.push(signed_delegation);
        }
    }

    delegations
}

fn random_canister_id<R: Rng + CryptoRng>(rng: &mut R) -> CanisterId {
    CanisterId::from_u64(rng.r#gen::<u64>())
}

fn random_canister_ids<R: Rng + CryptoRng>(cnt: usize, rng: &mut R) -> Vec<CanisterId> {
    let mut result = Vec::with_capacity(cnt);

    for _ in 0..cnt {
        result.push(random_canister_id(rng));
    }

    result
}

fn random_canister_ids_including<R: Rng + CryptoRng>(
    canister_id: &CanisterId,
    total_cnt: usize,
    include_cnt: usize,
    rng: &mut R,
) -> Vec<CanisterId> {
    assert!(total_cnt > 0);
    assert!(include_cnt > 0 && include_cnt < total_cnt);

    let mut result = random_canister_ids(total_cnt, rng);

    // Overwrite some of the random canister IDs with our desired target
    for i in rand::seq::index::sample(rng, total_cnt, include_cnt) {
        result[i] = *canister_id;
    }

    result
}

fn sign_delegation(delegation: Delegation, identity: &GenericIdentity<'_>) -> SignedDelegation {
    use ic_types::crypto::Signable;
    let signature = identity.sign_bytes(&delegation.as_signed_bytes());
    SignedDelegation::new(delegation, signature)
}

#[derive(Clone, Debug)]
enum ResponseBody {
    Empty,
    Text(String),
    Cbor(serde_cbor::Value),
}

#[derive(Clone, Debug)]
struct ReplicaResponse {
    status: StatusCode,
    body: ResponseBody,
}

impl ReplicaResponse {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn expect_empty_body(&self) {
        match &self.body {
            ResponseBody::Empty => {}
            ResponseBody::Cbor(c) => panic!("Expected empty body but got CBOR instead: {:?}", c),
            ResponseBody::Text(t) => panic!("Expected empty body but got text instead: {:?}", t),
        }
    }

    fn expect_certificate(&self) {
        match &self.body {
            ResponseBody::Empty => panic!("Expected certificate response but got empty instead"),
            ResponseBody::Cbor(c) => match &c {
                serde_cbor::Value::Map(m) => {
                    if !m.contains_key(&serde_cbor::Value::Text("certificate".to_owned())) {
                        panic!("Missing certificate field in CBOR {:?}", m);
                    }
                }
                other => {
                    panic!("Unexpected CBOR response type {:?}", other);
                }
            },
            ResponseBody::Text(t) => panic!(
                "Expected certificate response but got text instead: {:?}",
                t
            ),
        }
    }

    fn expect_cbor_reply(&self) {
        match &self.body {
            ResponseBody::Empty => panic!("Expected CBOR response but got empty instead"),
            ResponseBody::Cbor(c) => match &c {
                serde_cbor::Value::Map(m) => {
                    if !m.contains_key(&serde_cbor::Value::Text("reply".to_owned())) {
                        panic!("Missing reply field in CBOR {:?}", m);
                    }
                }
                other => {
                    panic!("Unexpected CBOR response type {:?}", other);
                }
            },
            ResponseBody::Text(t) => panic!("Expected CBOR response but got text instead: {:?}", t),
        }
    }

    fn expect_text_error(&self, substr: &str) {
        match &self.body {
            ResponseBody::Empty => panic!("Expected text body but got empty instead"),
            ResponseBody::Cbor(c) => panic!("Expected text body but got CBOR instead: {:?}", c),
            ResponseBody::Text(t) => {
                assert!(
                    t.contains(substr),
                    "Missing expected error '{}' in '{}'",
                    substr,
                    t
                );
            }
        }
    }
}

async fn send_request<C: serde::ser::Serialize>(
    api_ver: usize,
    test: &TestInformation,
    req_type: &'static str,
    content: C,
    sender_pubkey: Vec<u8>,
    sender_delegation: Option<Vec<SignedDelegation>>,
    sender_sig: Vec<u8>,
) -> ReplicaResponse {
    let envelope = HttpRequestEnvelope {
        content,
        sender_delegation,
        sender_pubkey: Some(Blob(sender_pubkey)),
        sender_sig: Some(Blob(sender_sig)),
    };

    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();

    let url = format!(
        "{}api/v{}/canister/{}/{}",
        test.url, api_ver, test.canister_id, req_type
    );

    let response = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    let status = response.status();

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|s| s.to_str().expect("Invalid Content-Type").to_owned());

    let bytes = response
        .bytes()
        .await
        .expect("Failed to get response body")
        .to_vec();

    let body = match content_type.as_deref() {
        None => {
            assert_eq!(bytes.len(), 0);
            ResponseBody::Empty
        }
        Some("application/cbor") => ResponseBody::Cbor(
            serde_cbor::from_slice(&bytes).expect("Failed to parse CBOR response"),
        ),
        Some("text/plain; charset=utf-8") => ResponseBody::Text(
            String::from_utf8(bytes).expect("Replica sent invalid text response"),
        ),
        Some(other) => {
            panic!("Unknown content type {}", other);
        }
    };

    ReplicaResponse { status, body }
}

async fn perform_query_call_with_delegations(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> ReplicaResponse {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().reply_data(b"query_reply").build()),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_query(&content);

    send_request(
        api_ver,
        test,
        "query",
        content,
        sender.public_key_der(),
        Some(delegations.to_vec()),
        signature,
    )
    .await
}

async fn perform_update_call_with_delegations(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> ReplicaResponse {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().reply_data(b"update_reply").build()),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_update(&content);

    send_request(
        api_ver,
        test,
        "call",
        content,
        sender.public_key_der(),
        Some(delegations.to_vec()),
        signature,
    )
    .await
}

async fn perform_read_state_call_with_delegations(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> ReplicaResponse {
    /*
     * In order to properly test read state request we must have another
     * call to check the status of.
     */
    let request_id = {
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
                method_name: "update".to_string(),
                arg: Blob(wasm().reply_data(b"read state test").build()),
                sender: Blob(sender.principal().as_slice().to_vec()),
                ingress_expiry: expiry_time().as_nanos() as u64,
                nonce: None,
            },
        };

        let signature = sender.sign_update(&content);
        let request_id = MessageId::from(content.representation_independent_hash());

        // Always use a v3 call to test read state request since the call is sync,
        // otherwise we have to wait until the call executes before checking the read state, which
        // requires a potentially flaky retry loop.

        let _response = send_request(
            /*api_ver=*/ 3,
            test,
            "call",
            content,
            sender.public_key_der(),
            None,
            signature,
        )
        .await;

        request_id
    };

    let paths = vec![vec!["request_status".into(), (request_id).into()].into()];

    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(sender.principal().as_slice().to_vec()),
            paths,
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_read_state(&content);

    send_request(
        api_ver,
        test,
        "read_state",
        content,
        sender.public_key_der(),
        Some(delegations.to_vec()),
        signature,
    )
    .await
}

async fn perform_query_with_expiry(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> ReplicaResponse {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().reply_data(b"update_reply").build()),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry,
            nonce: None,
        },
    };

    let signature = signer.sign_query(&content);

    send_request(
        api_ver,
        test,
        "query",
        content,
        sender.public_key_der(),
        None,
        signature,
    )
    .await
}

async fn perform_update_with_expiry(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> ReplicaResponse {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().reply_data(b"update_reply").build()),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry,
            nonce: None,
        },
    };

    let signature = signer.sign_update(&content);

    send_request(
        api_ver,
        test,
        "call",
        content,
        sender.public_key_der(),
        None,
        signature,
    )
    .await
}

async fn perform_read_state_call_with_expiry(
    api_ver: usize,
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> ReplicaResponse {
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(sender.principal().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry,
            nonce: None,
        },
    };

    let signature = signer.sign_read_state(&content);

    send_request(
        api_ver,
        test,
        "read_state",
        content,
        sender.public_key_der(),
        None,
        signature,
    )
    .await
}

fn random_n_bytes<R: Rng + CryptoRng>(n: u32, rng: &mut R) -> Vec<u8> {
    (0..n).map(|_| rng.r#gen::<u8>()).collect()
}

fn resign_certificate_with_random_signature<R: Rng + CryptoRng>(
    certificate_cbor: &[u8],
    rng: &mut R,
) -> Vec<u8> {
    use ic_crypto_internal_bls12_381_type::G1Affine;
    // sanity check for self-describing CBOR tag
    // 0xd9d9f7 (cf. https://tools.ietf.org/html/rfc7049#section-2.4.5) is the
    // self-describing CBOR tag required to be present by the interface spec.
    if certificate_cbor.len() < 3 || certificate_cbor[0..3] != [0xd9, 0xd9, 0xf7] {
        panic!("certificate CBOR doesn't have a self-describing tag");
    }
    let mut certificate: ic_certification::Certificate =
        serde_cbor::from_slice(certificate_cbor).expect("failed to parse certificate CBOR");

    let previous_signature = certificate.signature.clone();
    assert_eq!(previous_signature.len(), 48);

    let random_g1 = G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>());
    certificate.signature = random_g1.serialize().to_vec();
    assert_eq!(certificate.signature.len(), 48);
    assert_ne!(certificate.signature, previous_signature);

    // serialize back to self-describing CBOR
    use serde::Serialize;
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    certificate.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

fn wrap_cose_key_in_der_spki(cose: &serde_cbor::Value) -> Vec<u8> {
    use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
    use simple_asn1::oid;
    // OID 1.3.6.1.4.1.56387.1.1
    // See https://internetcomputer.org/docs/current/references/ic-interface-spec#signatures
    let webauthn_key_oid = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 1);
    let pk_cose = serde_cbor::to_vec(cose).unwrap();
    subject_public_key_info_der(webauthn_key_oid, &pk_cose).unwrap()
}

fn webauthn_cose_wrap_rsa_pkcs1_key(pk: &rsa::RsaPublicKey) -> Vec<u8> {
    use rsa::traits::PublicKeyParts;

    let n = pk.n();
    let e = pk.e();

    let mut map = std::collections::BTreeMap::new();

    use serde_cbor::Value;

    /*
    Reference

    - RFC 8152 "CBOR Object Signing and Encryption (COSE)"

    - RFC 8230 "Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages"

    - RFC 8812 "CBOR Object Signing and Encryption (COSE) and JSON
      Object Signing and Encryption (JOSE) Registrations for Web
      Authentication (WebAuthn) Algorithms"
     */
    const COSE_PARAM_KTY: serde_cbor::Value = serde_cbor::Value::Integer(1);
    const COSE_PARAM_KTY_RSA: serde_cbor::Value = serde_cbor::Value::Integer(3);

    const COSE_PARAM_ALG: serde_cbor::Value = serde_cbor::Value::Integer(3);
    const COSE_PARAM_ALG_RS256: serde_cbor::Value = serde_cbor::Value::Integer(-257);

    const COSE_PARAM_RSA_N: serde_cbor::Value = serde_cbor::Value::Integer(-1);
    const COSE_PARAM_RSA_E: serde_cbor::Value = serde_cbor::Value::Integer(-2);

    map.insert(COSE_PARAM_KTY, COSE_PARAM_KTY_RSA);
    map.insert(COSE_PARAM_ALG, COSE_PARAM_ALG_RS256);
    map.insert(COSE_PARAM_RSA_E, Value::Bytes(e.to_bytes_be()));
    map.insert(COSE_PARAM_RSA_N, Value::Bytes(n.to_bytes_be()));

    wrap_cose_key_in_der_spki(&Value::Map(map))
}

fn webauthn_cose_wrap_ecdsa_secp256r1_key(pk: &ic_secp256r1::PublicKey) -> Vec<u8> {
    let sec1 = pk.serialize_sec1(false);

    let mut map = std::collections::BTreeMap::new();

    use serde_cbor::Value;

    /*
    See RFC 8152 ("CBOR Object Signing and Encryption (COSE)"), sections 8.1
    and 13.1 for these constants
     */
    const COSE_PARAM_KTY: serde_cbor::Value = serde_cbor::Value::Integer(1);
    const COSE_PARAM_KTY_EC2: serde_cbor::Value = serde_cbor::Value::Integer(2);

    const COSE_PARAM_ALG: serde_cbor::Value = serde_cbor::Value::Integer(3);
    const COSE_PARAM_ALG_ES256: serde_cbor::Value = serde_cbor::Value::Integer(-7);

    const COSE_PARAM_EC2_CRV: serde_cbor::Value = serde_cbor::Value::Integer(-1);
    const COSE_PARAM_EC2_CRV_P256: serde_cbor::Value = serde_cbor::Value::Integer(1);

    const COSE_PARAM_EC2_X: serde_cbor::Value = serde_cbor::Value::Integer(-2);
    const COSE_PARAM_EC2_Y: serde_cbor::Value = serde_cbor::Value::Integer(-3);

    let x = &sec1[1..33];
    let y = &sec1[33..];

    map.insert(COSE_PARAM_KTY, COSE_PARAM_KTY_EC2);
    map.insert(COSE_PARAM_EC2_CRV, COSE_PARAM_EC2_CRV_P256);
    map.insert(COSE_PARAM_ALG, COSE_PARAM_ALG_ES256);
    map.insert(COSE_PARAM_EC2_X, Value::Bytes(x.to_vec()));
    map.insert(COSE_PARAM_EC2_Y, Value::Bytes(y.to_vec()));

    wrap_cose_key_in_der_spki(&Value::Map(map))
}

fn webauthn_sign_message<F: FnOnce(&[u8]) -> Vec<u8>>(msg: &[u8], sign_fn: F) -> Vec<u8> {
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct ClientData {
        r#type: String,
        challenge: String,
        origin: String,
    }

    let client_data = ClientData {
        r#type: "webauthn.get".to_string(),
        challenge: base64::encode_config(msg, base64::URL_SAFE_NO_PAD),
        origin: "ic-ingress-verification-test".to_string(),
    };

    let authenticator_data = Blob(b"arbitrary".to_vec());
    let client_data_json = serde_json::to_vec(&client_data).unwrap();

    let signed_message = {
        let mut sm = vec![];
        sm.extend_from_slice(&authenticator_data.0);
        sm.extend_from_slice(&ic_crypto_sha2::Sha256::hash(&client_data_json));
        sm
    };
    let signature = Blob(sign_fn(&signed_message));
    let sig = ic_types::messages::WebAuthnSignature::new(
        authenticator_data,
        Blob(client_data_json),
        signature,
    );

    // serialize to self-describing CBOR
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    sig.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

fn webauthn_sign_ecdsa_secp256r1(sk: &ic_secp256r1::PrivateKey, msg: &[u8]) -> Vec<u8> {
    let sign_fn = |to_sign: &[u8]| -> Vec<u8> { sk.sign_message_with_der_encoded_sig(to_sign) };
    webauthn_sign_message(msg, sign_fn)
}

fn webauthn_sign_rsa_pkcs1(sk: &rsa::RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    let sign_fn = |to_sign: &[u8]| -> Vec<u8> {
        let signing_key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(sk.clone());
        use rsa::signature::{SignatureEncoding, Signer};
        signing_key.sign(to_sign).to_vec()
    };
    webauthn_sign_message(msg, sign_fn)
}
