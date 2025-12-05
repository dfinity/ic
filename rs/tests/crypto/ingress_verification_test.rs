/* tag::catalog[]
end::catalog[] */
use anyhow::Result;
use ic_agent::Identity;
use ic_agent::export::Principal;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, block_on, expiry_time, sign_query, sign_read_state, sign_update,
};
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
    HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, SignedDelegation,
};
use ic_types::{CanisterId, PrincipalId, Time};
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};
use reqwest::{StatusCode, Url};
use slog::{debug, info};

const ALL_QUERY_API_VERSIONS: &[usize] = &[2, 3];
const ALL_UPDATE_API_VERSIONS: &[usize] = &[2, 3, 4];
const ALL_READ_STATE_API_VERSIONS: &[usize] = &[2, 3];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(requests_with_delegations; 2))
                .add_test(systest!(requests_with_delegations; 3))
                .add_test(systest!(requests_with_delegations_with_targets; 2))
                .add_test(systest!(requests_with_delegations_with_targets; 3))
                .add_test(systest!(requests_with_delegation_loop; 2))
                .add_test(systest!(requests_with_delegation_loop; 3))
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
    api_ver: usize,
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
pub fn requests_with_delegations(env: TestEnv, api_ver: usize) {
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
                api_ver,
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

                let query_result =
                    perform_query_call_with_delegations(&test_info, sender, signer, &delegations)
                        .await;
                let update_result =
                    perform_update_call_with_delegations(&test_info, sender, signer, &delegations)
                        .await;

                if delegation_count <= 20 {
                    assert_eq!(query_result, 200);

                    let expected_update = if test_info.api_ver == 2 { 202 } else { 200 };
                    assert_eq!(update_result, expected_update);
                } else {
                    assert_eq!(query_result, 400);
                    assert_eq!(update_result, 400);
                }
            }
        }
    });
}

// Tests for ingress messages with delegations using canister targets
pub fn requests_with_delegations_with_targets(env: TestEnv, api_ver: usize) {
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
                api_ver,
                url: node_url,
                canister_id,
            };

            struct DelegationTest {
                note: &'static str,
                targets: Vec<Vec<CanisterId>>,
                expect_success: bool,
            }

            impl DelegationTest {
                fn accept(note: &'static str, targets: Vec<Vec<CanisterId>>) -> Self {
                    Self {
                        note,
                        targets,
                        expect_success: true,
                    }
                }

                fn reject(note: &'static str, targets: Vec<Vec<CanisterId>>) -> Self {
                    Self {
                        note,
                        targets,
                        expect_success: false,
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
                    vec![vec![], vec![canister_id]],
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
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (1001)",
                    vec![random_canister_ids_including(&canister_id, 1001, 1, rng)],
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (2000)",
                    vec![random_canister_ids_including(&canister_id, 2000, 1, rng)],
                ),
                DelegationTest::reject(
                    "With an empty target intersection of multiple delegations with non-empty sets of targets",
                    vec![
                        vec![random_canister_id(rng)],
                        vec![canister_id, random_canister_id(rng)],
                    ],
                ),
                DelegationTest::reject(
                    "With an empty target intersection of multiple delegations",
                    vec![vec![random_canister_id(rng)], vec![random_canister_id(rng)]],
                ),
                // TODO: with an empty set of targets or a set of targets containing the requested canister ID for mgmt canister calls.
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

                let query_result =
                    perform_query_call_with_delegations(&test_info, sender, signer, &delegations)
                        .await;
                let update_result =
                    perform_update_call_with_delegations(&test_info, sender, signer, &delegations)
                        .await;

                info!(
                    logger,
                    "Testing scenario '{}' got {:?}/{:?}",
                    scenario.note,
                    query_result,
                    update_result,
                );

                if scenario.expect_success {
                    assert_eq!(query_result, 200);
                    assert_eq!(
                        update_result,
                        if test_info.api_ver == 2 { 202 } else { 200 }
                    );
                } else {
                    assert_eq!(query_result, 400);
                    assert_eq!(update_result, 400);
                }
            }
        }
    });
}

// Tests for handling of delegation loops
pub fn requests_with_delegation_loop(env: TestEnv, api_ver: usize) {
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
                api_ver,
                url: node_url,
                canister_id,
            };

            // Test case: A self-loop in delegations should be detected and rejected

            let mut identities = vec![];

            for _ in 0..4 {
                let id_type = GenericIdentityType::random_incl_canister(&canister, rng);
                identities.push(GenericIdentity::new(id_type, rng));
            }

            // Duplicate the identity, causing a delegation loop
            identities.push(identities[identities.len() - 1].clone());

            let delegations = create_delegations(&identities);

            let sender = &identities[0];
            let signer = &identities[identities.len() - 1];

            let query_result =
                perform_query_call_with_delegations(&test_info, sender, signer, &delegations).await;
            let update_result =
                perform_update_call_with_delegations(&test_info, sender, signer, &delegations)
                    .await;

            assert_eq!(query_result, 400);
            assert_eq!(update_result, 400);

            // TODO Test case: An indirect cycle in delegations should be detected and rejected
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

            let mut test_info = TestInformation {
                api_ver: 999, // To be set later...
                url: node_url,
                canister_id: canister_id_from_principal(&canister.canister_id()),
            };

            // Single identity for sender and signer, no delegations
            let rng = &mut reproducible_rng();
            let id_type = GenericIdentityType::random_incl_canister(&canister, rng);
            let id = GenericIdentity::new(id_type, rng);

            for expiry in [0_u64, u64::MAX] {
                for api_ver in [2, 3] {
                    test_info.api_ver = api_ver;
                    assert_eq!(
                        perform_query_with_expiry(&test_info, &id, &id, expiry).await,
                        400,
                        "query should be rejected for expiry={expiry} and api_ver={api_ver}"
                    );
                }
                for api_ver in [2, 3, 4] {
                    test_info.api_ver = api_ver;
                    assert_eq!(
                        perform_update_with_expiry(&test_info, &id, &id, expiry).await,
                        400,
                        "update should be rejected for expiry={expiry} and api_ver={api_ver}"
                    );
                }
                for api_ver in [2, 3] {
                    test_info.api_ver = api_ver;
                    assert_eq!(
                        perform_read_state_with_expiry(&test_info, &id, &id, expiry).await,
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
                let mut test_info = TestInformation {
                    api_ver: 999, // To be set later...
                    url: node_url.clone(),
                    canister_id: canister_id_from_principal(&c1.canister_id()),
                };
                for api_ver in ALL_QUERY_API_VERSIONS {
                    test_info.api_ver = *api_ver;
                    assert_eq!(
                        perform_query_call_with_delegations(&test_info, &id, &id, &[]).await,
                        200,
                        "query should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
                }
                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    test_info.api_ver = api_ver;
                    assert_eq!(
                        perform_update_call_with_delegations(&test_info, &id, &id, &[]).await,
                        if api_ver == 2 { 202 } else { 200 },
                        "update should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
                }
                for api_ver in ALL_READ_STATE_API_VERSIONS {
                    test_info.api_ver = *api_ver;
                    assert_eq!(
                        perform_read_state_call_with_delegations(&test_info, &id, &id, &[]).await,
                        200,
                        "read_state should succeed for api_ver={api_ver} and seed={seed:?}"
                    );
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
            let seed = b"seed";
            let id = GenericIdentity::new_canister(CanisterSigner::new(&c1, seed.to_vec()));
            let wrong_seed = b"wrong_seed";
            assert_ne!(seed.to_vec(), wrong_seed.to_vec());
            for sender in [
                GenericIdentity::new_canister(CanisterSigner::new(&c1, wrong_seed.to_vec())),
                GenericIdentity::new_canister(CanisterSigner::new(&c2, seed.to_vec())), // wrong canister
            ] {
                let mut test_info = TestInformation {
                    api_ver: 999, // To be set later...
                    url: node_url.clone(),
                    canister_id: canister_id_from_principal(&c1.canister_id()),
                };
                for api_ver in ALL_QUERY_API_VERSIONS {
                    test_info.api_ver = *api_ver;
                    assert_eq!(
                        perform_query_call_with_delegations(&test_info, &sender, &id, &[]).await,
                        400,
                        "query should be rejected for api_ver={api_ver}"
                    );
                }
                for &api_ver in ALL_UPDATE_API_VERSIONS {
                    test_info.api_ver = api_ver;
                    assert_eq!(
                        perform_update_call_with_delegations(&test_info, &sender, &id, &[]).await,
                        400,
                        "update should be rejected for api_ver={api_ver}"
                    );
                }
                for api_ver in ALL_READ_STATE_API_VERSIONS {
                    test_info.api_ver = *api_ver;
                    assert_eq!(
                        perform_read_state_call_with_delegations(&test_info, &sender, &id, &[])
                            .await,
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
            let mut test_info = TestInformation {
                api_ver: 999, // To be set later...
                url: node_url.clone(),
                canister_id: canister_id_from_principal(&c1.canister_id()),
            };
            for api_ver in ALL_QUERY_API_VERSIONS {
                test_info.api_ver = *api_ver;
                assert_eq!(
                    perform_query_call_with_delegations(&test_info, &id, &id, &[]).await,
                    400,
                    "query should be rejected for api_ver={api_ver} with invalid certificate signature"
                );
            }
            for &api_ver in ALL_UPDATE_API_VERSIONS {
                test_info.api_ver = api_ver;
                assert_eq!(
                    perform_update_call_with_delegations(&test_info, &id, &id, &[]).await,
                    400,
                    "update should be rejected for api_ver={api_ver} with invalid certificate signature"
                );
            }
            for api_ver in ALL_READ_STATE_API_VERSIONS {
                test_info.api_ver = *api_ver;
                assert_eq!(
                    perform_read_state_call_with_delegations(&test_info, &id, &id, &[]).await,
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
    CanisterId::try_from_principal_id(PrincipalId::from(*p)).expect("invalid canister ID")
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

fn random_canister_ids_including<R: Rng + CryptoRng>(
    canister_id: &CanisterId,
    total_cnt: usize,
    include_cnt: usize,
    rng: &mut R,
) -> Vec<CanisterId> {
    assert!(total_cnt > 0);
    assert!(include_cnt > 0 && include_cnt < total_cnt);

    let mut result = Vec::with_capacity(total_cnt);

    for _ in 0..total_cnt {
        result.push(random_canister_id(rng));
    }

    // Overwrite some of the random canister IDs with our desired target
    for i in rand::seq::index::sample(rng, total_cnt, include_cnt) {
        result[i] = *canister_id;
    }

    result
}

fn sign_delegation(delegation: Delegation, identity: &GenericIdentity) -> SignedDelegation {
    use ic_types::crypto::Signable;
    let signature = identity.sign_bytes(&delegation.as_signed_bytes());
    SignedDelegation::new(delegation, signature)
}

async fn send_request<C: serde::ser::Serialize>(
    test: &TestInformation,
    req_type: &'static str,
    content: C,
    sender_pubkey: Vec<u8>,
    sender_delegation: Option<Vec<SignedDelegation>>,
    sender_sig: Vec<u8>,
) -> StatusCode {
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
        test.url, test.api_ver, test.canister_id, req_type
    );

    let res = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    res.status()
}

async fn perform_query_call_with_delegations(
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_query(&content);

    send_request(
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
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_update(&content);

    send_request(
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
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(sender.principal().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_read_state(&content);

    send_request(
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
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> StatusCode {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry,
            nonce: None,
        },
    };

    let signature = signer.sign_query(&content);

    send_request(
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
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> StatusCode {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry,
            nonce: None,
        },
    };

    let signature = signer.sign_update(&content);

    send_request(
        test,
        "call",
        content,
        sender.public_key_der(),
        None,
        signature,
    )
    .await
}

async fn perform_read_state_with_expiry(
    test: &TestInformation,
    sender: &GenericIdentity<'_>,
    signer: &GenericIdentity<'_>,
    ingress_expiry: u64,
) -> StatusCode {
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
