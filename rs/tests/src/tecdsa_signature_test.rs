/* tag::catalog[]
Title:: Threshold ECDSA signature test

Goal:: Verify if the threshold ECDSA feature is working properly by exercising
the ECDSA public APIs.

Runbook::
. start a subnet with ecdsa feature enabled.
. get public key of a canister
. have the canister sign a message and get the signature
. verify if the signature is correct with respect to the public key

Success:: An agent can complete the signing process and result signature verifies.

end::catalog[] */

use crate::util::*;
use candid::Encode;
use candid::Principal;
use canister_test::Cycles;
use ic_agent::AgentError;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_fondue::{
    ic_manager::IcHandle,
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_ic00_types::{
    ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, Payload, SignWithECDSAArgs, SignWithECDSAReply,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use secp256k1::{Message, PublicKey, Secp256k1, Signature};
use slog::{debug, info};

const KEY_ID: &str = "secp256k1";

/// Create one system subnet with ecdsa enabled and one application subnet
/// without ecdsa enabled.
pub fn enable_ecdsa_signatures_feature() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(4)
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                }),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(4),
        )
}

pub(crate) async fn get_public_key(
    uni_can: &UniversalCanister<'_>,
    ctx: &ic_fondue::pot::Context,
) -> PublicKey {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![],
        key_id: KEY_ID.to_string(),
    };

    let mut count = 0;
    let public_key = loop {
        let res = uni_can
            .forward_to(
                &Principal::management_canister(),
                "ecdsa_public_key",
                Encode!(&public_key_request).unwrap(),
            )
            .await;
        match res {
            Ok(bytes) => {
                let key = ECDSAPublicKeyResponse::decode(&bytes)
                    .expect("failed to decode ECDSAPublicKeyResponse");
                break key.public_key;
            }
            Err(err) => {
                count += 1;
                if count < 20 {
                    debug!(ctx.logger, "ecdsa_public_key returns {}, try again...", err);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                } else {
                    panic!("ecdsa_public_key failed after {} tries.", count);
                }
            }
        }
    };
    info!(ctx.logger, "ecdsa_public_key returns {:?}", public_key);
    PublicKey::from_slice(&public_key).expect("Response is not a valid public key")
}

pub(crate) async fn get_signature(
    message_hash: &[u8],
    cycles: Cycles,
    uni_can: &UniversalCanister<'_>,
    ctx: &ic_fondue::pot::Context,
) -> Result<Signature, AgentError> {
    let signature_request = SignWithECDSAArgs {
        message_hash: message_hash.to_vec(),
        derivation_path: Vec::new(),
        key_id: KEY_ID.to_string(),
    };

    // Ask for a signature.
    let reply = uni_can
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "sign_with_ecdsa",
            Encode!(&signature_request).unwrap(),
            cycles,
        )
        .await?;

    let signature = SignWithECDSAReply::decode(&reply)
        .expect("failed to decode SignWithECDSAReply")
        .signature;
    info!(ctx.logger, "sign_with_ecdsa returns {:?}", signature);

    Ok(Signature::from_compact(&signature).expect("Response is not a valid signature"))
}

pub(crate) fn verify_signature(message_hash: &[u8], public_key: &PublicKey, signature: &Signature) {
    // Verify the signature:
    let secp = Secp256k1::new();
    let message = Message::from_slice(message_hash).expect("32 bytes");
    assert!(secp.verify(&message, signature, public_key).is_ok());
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`.
pub fn test_threshold_ecdsa_signature(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        // The system subnet has ecdsa enabled.
        let endpoint = get_random_system_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(&uni_can, ctx).await;
        // Send zero cycles because the NNS is excempt from paying for ECDSA signatures.
        let signature = get_signature(&message_hash, Cycles::zero(), &uni_can, ctx)
            .await
            .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature that
/// is verifiable with the result from `get_ecdsa_public_key` when the subnet
/// sending the request doesn't have ecdsa signing enabled.
pub fn test_threshold_ecdsa_signature_from_other_subnet(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        // The application subnet does not have ecdsa enabled.
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(&uni_can, ctx).await;
        let signature = get_signature(&message_hash, ECDSA_SIGNATURE_FEE, &uni_can, ctx)
            .await
            .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` fails when not enough cycles are
/// sent.
pub fn test_threshold_ecdsa_signature_fails_without_cycles(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        // The application subnet does not have ecdsa enabled.
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let error = get_signature(
            &message_hash,
            ECDSA_SIGNATURE_FEE - Cycles::from(1),
            &uni_can,
            ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::ReplicaError {
                reject_code: 4,
                reject_message: format!(
                    "sign_with_ecdsa request sent with {} cycles, but {} cycles are required.",
                    ECDSA_SIGNATURE_FEE.get() - 1,
                    ECDSA_SIGNATURE_FEE.get()
                )
            }
        )
    });
}
