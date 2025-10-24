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
use ic_types::Time;
use ic_types::crypto::SignedBytesWithoutDomainSeparator;
use ic_types::messages::{
    Blob, Delegation, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope,
    HttpUserQuery, SignedDelegation,
};
use ic_universal_canister::wasm;
use rand::{CryptoRng, Rng};
use reqwest::{StatusCode, Url};
use slog::{debug, info};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(SystemTestSubGroup::new().add_test(systest!(requests_with_delegations)))
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
                    let id_type = if rng.r#gen::<bool>() {
                        GenericIdentityType::EcdsaSecp256k1
                    } else {
                        GenericIdentityType::Ed25519
                    };
                    identities.push(GenericIdentity::new(id_type, rng));
                }

                let delegation_expiry =
                    Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

                let mut delegations = Vec::with_capacity(delegation_count);

                if delegation_count > 0 {
                    for i in 1..=delegation_count {
                        let delegation =
                            Delegation::new(identities[i].public_key(), delegation_expiry);

                        let signed_delegation = sign_delegation(delegation, &identities[i - 1]);

                        delegations.push(signed_delegation);
                    }
                }

                let sender = &identities[0];
                let signer = &identities[identities.len() - 1];

                let query_result =
                    query_delegation(&test_info, sender, signer, &delegations).await;
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

fn sign_delegation(delegation: Delegation, identity: &GenericIdentity) -> SignedDelegation {
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(&delegation.as_signed_bytes_without_domain_separator());
    let signature = identity.identity().sign_arbitrary(&msg).unwrap();

    SignedDelegation::new(delegation, signature.signature.unwrap())
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

    let signature = sign_query(&content, &signer.identity());

    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: if delegations.is_empty() {
            None
        } else {
            Some(delegations.to_vec())
        },
        sender_pubkey: Some(Blob(sender.public_key())),
        sender_sig: Some(Blob(signature.signature.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{}api/v2/canister/{}/query",
            test.url, test.canister_id
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    res.status()
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

    let signature = sign_update(&content, &signer.identity());

    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: if delegations.is_empty() {
            None
        } else {
            Some(delegations.to_vec())
        },
        sender_pubkey: Some(Blob(sender.public_key())),
        sender_sig: Some(Blob(signature.signature.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{}api/v2/canister/{}/call",
            test.url, test.canister_id
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    res.status()
}
