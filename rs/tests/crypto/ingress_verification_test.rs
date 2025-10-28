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
    UniversalCanister, block_on, expiry_time, sign_query, sign_update,
};
use ic_types::crypto::SignedBytesWithoutDomainSeparator;
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope,
    HttpUserQuery, SignedDelegation,
};
use ic_types::{CanisterId, PrincipalId, Time};
use rand::{CryptoRng, Rng};
use reqwest::{StatusCode, Url};
use slog::{debug, info};

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
                .add_test(systest!(requests_with_delegation_loop; 3)),
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
    canister_id: Principal,
}

#[derive(Copy, Clone, Debug)]
enum GenericIdentityType {
    Ed25519,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    // TODO webauthn RSA
    // TODO webauthn EC
}

impl GenericIdentityType {
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        match rng.r#gen::<usize>() % 3 {
            0 => Self::EcdsaSecp256k1,
            1 => Self::EcdsaSecp256r1,
            _ => Self::Ed25519,
        }
    }
}

#[derive(Clone)]
enum GenericIdentityInner {
    K256(ic_secp256k1::PrivateKey),
    P256(ic_secp256r1::PrivateKey),
    Ed25519(ic_ed25519::PrivateKey),
}

#[derive(Clone)]
struct GenericIdentity {
    inner: GenericIdentityInner,
    public_key: Vec<u8>,
    principal: Principal,
}

impl GenericIdentity {
    fn new<R: Rng + CryptoRng>(typ: GenericIdentityType, rng: &mut R) -> Self {
        let (inner, public_key) = match typ {
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
        };

        let principal = Principal::self_authenticating(&public_key);

        Self {
            inner,
            public_key,
            principal,
        }
    }

    fn principal(&self) -> &Principal {
        &self.principal
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
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

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        match &self.inner {
            GenericIdentityInner::Ed25519(sk) => sk.sign_message(bytes).to_vec(),
            GenericIdentityInner::K256(sk) => sk.sign_message_with_ecdsa(bytes).to_vec(),
            GenericIdentityInner::P256(sk) => sk.sign_message(bytes).to_vec(),
        }
    }
}

impl Identity for GenericIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.principal)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.public_key.clone())
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
            public_key: Some(self.public_key()),
            signature: Some(signature),
            delegations: None,
        })
    }
}

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
                canister_id: canister.canister_id(),
            };

            for delegation_count in 0..32 {
                let mut identities = Vec::with_capacity(delegation_count + 1);

                for _ in 0..(delegation_count + 1) {
                    let id_type = GenericIdentityType::random(rng);
                    identities.push(GenericIdentity::new(id_type, rng));
                }

                let delegations = create_delegations(&identities);

                let sender = &identities[0];
                let signer = &identities[identities.len() - 1];

                let query_result = query_delegation(&test_info, sender, signer, &delegations).await;
                let update_result =
                    update_delegation(&test_info, sender, signer, &delegations).await;

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

            let canister_id = canister.canister_id();

            let test_info = TestInformation {
                api_ver,
                url: node_url,
                canister_id,
            };

            struct DelegationTest {
                note: &'static str,
                targets: Vec<Vec<Principal>>,
                expect_success: bool,
            }

            impl DelegationTest {
                fn accept(note: &'static str, targets: Vec<Vec<Principal>>) -> Self {
                    Self {
                        note,
                        targets,
                        expect_success: true,
                    }
                }

                fn reject(note: &'static str, targets: Vec<Vec<Principal>>) -> Self {
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
                    vec![random_principals_including(&canister_id, 10, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (100), including the canister ID",
                    vec![random_principals_including(&canister_id, 100, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (1000), including the canister ID",
                    vec![random_principals_including(&canister_id, 1000, 1, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (10), including the canister ID multiple times",
                    vec![random_principals_including(&canister_id, 10, 2, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (100), including the canister ID multiple times",
                    vec![random_principals_including(&canister_id, 100, 10, rng)],
                ),
                DelegationTest::accept(
                    "Delegation with different targets (1000), including the canister ID multiple times",
                    vec![random_principals_including(&canister_id, 1000, 50, rng)],
                ),
                DelegationTest::reject(
                    "Not containing the requested canister ID",
                    vec![vec![random_canister_id(rng)]],
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (1001)",
                    vec![random_principals_including(&canister_id, 1001, 1, rng)],
                ),
                DelegationTest::reject(
                    "With more than 1000 different targets containing the requested canister ID (2000)",
                    vec![random_principals_including(&canister_id, 2000, 1, rng)],
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

                for _ in 0..(delegation_count + 1) {
                    let id_type = GenericIdentityType::random(rng);
                    identities.push(GenericIdentity::new(id_type, rng));
                }

                let delegations = create_delegations_with_targets(&identities, &scenario.targets);

                let sender = &identities[0];
                let signer = &identities[identities.len() - 1];

                let query_result = query_delegation(&test_info, sender, signer, &delegations).await;
                let update_result =
                    update_delegation(&test_info, sender, signer, &delegations).await;

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

            let canister_id = canister.canister_id();

            let test_info = TestInformation {
                api_ver,
                url: node_url,
                canister_id,
            };

            // Test case: A self-loop in delegations should be detected and rejected

            let mut identities = vec![];

            for _ in 0..4 {
                let id_type = GenericIdentityType::random(rng);
                identities.push(GenericIdentity::new(id_type, rng));
            }

            // Duplicate the identity, causing a delegation loop
            identities.push(identities[identities.len() - 1].clone());

            let delegations = create_delegations(&identities);

            let sender = &identities[0];
            let signer = &identities[identities.len() - 1];

            let query_result = query_delegation(&test_info, sender, signer, &delegations).await;
            let update_result = update_delegation(&test_info, sender, signer, &delegations).await;

            assert_eq!(query_result, 400);
            assert_eq!(update_result, 400);

            // TODO Test case: An indirect cycle in delegations should be detected and rejected
        }
    });
}

fn create_delegations(identities: &[GenericIdentity]) -> Vec<SignedDelegation> {
    let delegation_expiry = Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

    let delegation_count = identities.len() - 1;
    let mut delegations = Vec::with_capacity(delegation_count);

    if delegation_count > 0 {
        for i in 1..=delegation_count {
            let delegation = Delegation::new(identities[i].public_key(), delegation_expiry);
            let signed_delegation = sign_delegation(delegation, &identities[i - 1]);
            delegations.push(signed_delegation);
        }
    }

    delegations
}

fn canister_id_from_principal(p: &Principal) -> CanisterId {
    CanisterId::unchecked_from_principal(PrincipalId::from(*p))
}

fn create_delegations_with_targets(
    identities: &[GenericIdentity],
    targets: &[Vec<Principal>],
) -> Vec<SignedDelegation> {
    let delegation_expiry = Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

    let delegation_count = identities.len() - 1;
    let mut delegations = Vec::with_capacity(delegation_count);

    if delegation_count > 0 {
        for i in 1..=delegation_count {
            let delegation = if targets[i - 1].is_empty() {
                Delegation::new(identities[i].public_key(), delegation_expiry)
            } else {
                Delegation::new_with_targets(
                    identities[i].public_key(),
                    delegation_expiry,
                    targets[i - 1]
                        .iter()
                        .map(canister_id_from_principal)
                        .collect::<Vec<CanisterId>>(),
                )
            };

            let signed_delegation = sign_delegation(delegation, &identities[i - 1]);

            delegations.push(signed_delegation);
        }
    }

    delegations
}

fn random_canister_id<R: Rng + CryptoRng>(rng: &mut R) -> Principal {
    Principal::from(PrincipalId::new_user_test_id(rng.r#gen::<u64>()))
}

fn random_principals_including<R: Rng + CryptoRng>(
    canister_id: &Principal,
    total_cnt: usize,
    include_cnt: usize,
    rng: &mut R,
) -> Vec<Principal> {
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
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(&delegation.as_signed_bytes_without_domain_separator());
    let signature = identity.sign_bytes(&msg);
    SignedDelegation::new(delegation, signature)
}

async fn status_of_request<C: serde::ser::Serialize>(
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

async fn query_delegation(
    test: &TestInformation,
    sender: &GenericIdentity,
    signer: &GenericIdentity,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_query(&content);

    status_of_request(
        test,
        "query",
        content,
        sender.public_key(),
        Some(delegations.to_vec()),
        signature,
    )
    .await
}

async fn update_delegation(
    test: &TestInformation,
    sender: &GenericIdentity,
    signer: &GenericIdentity,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = signer.sign_update(&content);

    status_of_request(
        test,
        "call",
        content,
        sender.public_key(),
        Some(delegations.to_vec()),
        signature,
    )
    .await
}
