/* tag::catalog[]
end::catalog[] */
use anyhow::Result;
use ic_agent::export::Principal;
use ic_agent::{Identity, identity::Secp256k1Identity};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, block_on, expiry_time, random_ed25519_identity, sign_query, sign_update,
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
                .add_test(systest!(requests_with_delegations))
                .add_test(systest!(requests_with_delegations_with_targets)),
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
    canister_id: Principal,
}

#[derive(Copy, Clone, Debug)]
enum GenericIdentityType {
    Ed25519,
    EcdsaSecp256k1,
    // TODO ECDSA secp256r1
    // TODO webauthn
}

impl GenericIdentityType {
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        if rng.r#gen::<bool>() {
            Self::EcdsaSecp256k1
        } else {
            Self::Ed25519
        }
    }
}

struct GenericIdentity {
    identity: Box<dyn Identity>,
    principal: Principal,
}

impl GenericIdentity {
    fn new<R: Rng + CryptoRng>(typ: GenericIdentityType, rng: &mut R) -> Self {
        let identity: Box<dyn Identity> = match typ {
            GenericIdentityType::Ed25519 => Box::new(random_ed25519_identity()),
            GenericIdentityType::EcdsaSecp256k1 => Box::new(Secp256k1Identity::from_private_key(
                k256::SecretKey::random(rng),
            )),
        };

        let principal = identity
            .sender()
            .expect("Identity somehow has no principal");

        Self {
            identity,
            principal,
        }
    }

    fn identity(&self) -> &dyn Identity {
        &self.identity
    }

    fn principal(&self) -> &Principal {
        &self.principal
    }

    fn public_key(&self) -> Vec<u8> {
        self.identity
            .public_key()
            .expect("Public key missing from identity")
    }

    fn sign_query(&self, query: &HttpQueryContent) -> Vec<u8> {
        sign_query(query, &self.identity())
            .signature
            .clone()
            .expect("Signature missing")
    }

    fn sign_update(&self, update: &HttpCallContent) -> Vec<u8> {
        sign_update(update, &self.identity())
            .signature
            .clone()
            .expect("Signature missing")
    }
}

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
                canister_id: canister.canister_id(),
            };

            for delegation_count in 0..32 {
                info!(
                    logger,
                    "Testing request with {} delegations", delegation_count
                );

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
                    assert_eq!(update_result, 202);
                } else {
                    assert_eq!(query_result, 400);
                    assert_eq!(update_result, 400);
                }
            }
        }
    });
}

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

            let canister_id = canister.canister_id();

            let test_info = TestInformation {
                url: node_url,
                canister_id,
            };

            let rng_for_delegation = &mut rng.fork();

            let mut test_delegation_with_targets =
                async |targets: &[Vec<Principal>]| -> (StatusCode, StatusCode) {
                    let delegation_count = targets.len();

                    let mut identities = Vec::with_capacity(delegation_count + 1);

                    for _ in 0..(delegation_count + 1) {
                        let id_type = GenericIdentityType::random(rng_for_delegation);
                        identities.push(GenericIdentity::new(id_type, rng_for_delegation));
                    }

                    let delegations = create_delegations_with_targets(&identities, &targets);

                    let sender = &identities[0];
                    let signer = &identities[identities.len() - 1];

                    let query_result =
                        query_delegation(&test_info, sender, signer, &delegations).await;
                    let update_result =
                        update_delegation(&test_info, sender, signer, &delegations).await;

                    (query_result, update_result)
                };

            let accepted = (
                StatusCode::from_u16(200).unwrap(),
                StatusCode::from_u16(202).unwrap(),
            );

            // Test Scenario:
            //
            // Two delegations each with a singleton target containing the requested canister ID;
            assert_eq!(
                test_delegation_with_targets(&[vec![canister_id], vec![canister_id]]).await,
                accepted
            );

            // Test Scenario:
            //
            // Delegation targets containing the requested canister ID multiple times;
            assert_eq!(
                test_delegation_with_targets(&[vec![canister_id, canister_id]]).await,
                accepted
            );

            // Test Scenario:
            //
            // One delegation containing a singleton target containing the requested
            // canister ID and one delegation containing no target restriction (for both
            // ordering of these two delegations);
            assert_eq!(
                test_delegation_with_targets(&[vec![canister_id], vec![]]).await,
                accepted
            );
            assert_eq!(
                test_delegation_with_targets(&[vec![], vec![canister_id]]).await,
                accepted
            );

            // Test Scenario:
            //
            // Up to 1000 different targets (incl. arbitrary principals) containing the requested canister ID;
            for targets in [10, 100, 500, 1000] {
                let targets = random_principals_including(&canister_id, targets, rng);
                test_delegation_with_targets(&[targets]);
            }

            // TODO
            // with the mgmt canister principal as the target for mgmt canister calls.
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

fn random_principals_including<R: Rng + CryptoRng>(
    canister_id: &Principal,
    cnt: usize,
    rng: &mut R,
) -> Vec<Principal> {
    assert!(cnt > 0);

    let mut result = Vec::with_capacity(cnt);

    for _ in 0..cnt {
        result.push(Principal::from(PrincipalId::new_user_test_id(
            rng.r#gen::<u64>(),
        )));
    }

    // Overwrite one of the random canister IDs with our desired target
    result[rng.r#gen::<usize>() % cnt] = *canister_id;

    result
}

fn sign_delegation(delegation: Delegation, identity: &GenericIdentity) -> SignedDelegation {
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(&delegation.as_signed_bytes_without_domain_separator());
    let signature = identity.identity().sign_arbitrary(&msg).unwrap();

    SignedDelegation::new(delegation, signature.signature.unwrap())
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
        "{}api/v2/canister/{}/{}",
        test.url, test.canister_id, req_type
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
