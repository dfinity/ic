/* tag::catalog[]
end::catalog[] */
use anyhow::Result;
use ic_agent::export::Principal;
use ic_agent::{
    Identity,
    identity::{Secp256k1Identity},
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
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
        .add_test(systest!(query_request_no_delegations))
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

pub fn query_request_no_delegations(env: TestEnv) {
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

            for delegations in 0..=0 {
                info!(
                    logger,
                    "Testing request with {} delegations", delegations
                );

                let identity = random_ecdsa_identity(rng);
                let (delegations, sender) = gen_delegation_chain(rng, delegations, &identity);

                test_accepted_sender_delegation(&test_info, &delegations, &sender, &identity).await;
            }
        }
    });
}

pub fn random_ecdsa_identity<R: Rng + CryptoRng>(rng: &mut R) -> Secp256k1Identity {
    Secp256k1Identity::from_private_key(k256::SecretKey::random(rng))
}

fn sign_delegation(delegation: Delegation, identity: &impl Identity) -> SignedDelegation {
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(&delegation.as_signed_bytes_without_domain_separator());
    let signature = identity.sign_arbitrary(&msg).unwrap();

    SignedDelegation::new(delegation, signature.signature.unwrap())
}

fn gen_delegation_chain<R: Rng + CryptoRng>(
    rng: &mut R,
    cnt: usize,
    identity: &dyn Identity,
) -> (Vec<SignedDelegation>, Principal) {
    if cnt == 0 {
        return (vec![], identity.sender().expect("Principal not available"));
    }

    let delegation_expiry = Time::from_nanos_since_unix_epoch(expiry_time().as_nanos() as u64);

    assert!(cnt == 1);
    let mut delegations = Vec::with_capacity(cnt);

    let delegating_id = random_ed25519_identity();

    let delegation = Delegation::new(
        identity
            .public_key()
            .expect("Public key missing from identity"),
        delegation_expiry,
    );

    let signed_delegation = sign_delegation(delegation, &delegating_id);

    delegations.push(signed_delegation);

    (
        delegations,
        delegating_id.sender().expect("Principal not available"),
    )

    /*
        let mut public_keys = Vec::with_capacity(cnt);
        let mut identities = Vec::with_capacity(cnt);

        public_keys.push(identity.public_key().expect("Public key missing from identity"));

        for i in 0..cnt {
            identities.push(random_ed25519_identity());
            public_keys.push(identities[i].public_key().expect("Public key missing from identity"));

            let delegation = Delegation::new(
                public_keys[i].clone(),
                delegation_expiry,
            );

            let signed_delegation = sign_delegation(delegation, identity);
        }
        Some(delegations)
    */
}

async fn query_delegation(
    test: &TestInformation,
    sender: &Principal,
    identity: &dyn Identity,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(sender.as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_query(&content, &identity);

    // Add the public key but not the signature to the envelope. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: if delegations.is_empty() {
            None
        } else {
            Some(delegations.to_vec())
        },
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
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
    sender: &Principal,
    identity: &dyn Identity,
    delegations: &[SignedDelegation],
) -> StatusCode {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(sender.as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, &identity);

    // Add the public key but not the signature to the envelope. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: if delegations.is_empty() {
            None
        } else {
            Some(delegations.to_vec())
        },
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
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

async fn test_accepted_sender_delegation(
    test: &TestInformation,
    delegations: &[SignedDelegation],
    sender: &Principal,
    identity: &dyn Identity,
) {
    assert_eq!(
        query_delegation(test, sender, &identity, &delegations).await,
        200
    );
    assert_eq!(
        update_delegation(test, sender, &identity, &delegations).await,
        202
    );
}
