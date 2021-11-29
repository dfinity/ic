/* tag::catalog[]
end::catalog[] */

use crate::types::*;
use crate::util::*;
use candid::Encode;
use candid::Principal;
use ic_fondue::{
    ic_manager::IcHandle,
    internet_computer::{InternetComputer, Subnet},
};
use ic_ic00_types::SignWithECDSAArgs;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use secp256k1::{Message, PublicKey, Secp256k1, Signature};

/// Tests whether a call to `sign_with_ecdsa` is rejected when called on a
/// subnet where the corresponding feature flag is not explicitly enabled.
pub fn ecdsa_signatures_disabled_by_default(handle: IcHandle, ctx: &fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let request = SignWithECDSAArgs::new([0u8; 32].to_vec(), [0u8; 32].to_vec());

        let uni_can = UniversalCanister::new(&agent).await;
        let res = uni_can
            .forward_to(
                &Principal::management_canister(),
                "sign_with_ecdsa",
                Encode!(&request).unwrap(),
            )
            .await;

        assert_reject(res, RejectCode::CanisterReject);
    });
}

pub fn basic_config_with_all_features_enabled() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(4).with_features(
        SubnetFeatures {
            ecdsa_signatures: true,
            canister_sandboxing: false,
        },
    ))
}

/// Tests whether a call to `sign_with_mock_ecdsa` is responded with a signature
/// that is valid under the mock public key.
pub fn mock_ecdsa_signatures_are_supported(handle: IcHandle, ctx: &fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let message_hash = [0xabu8; 32];
        let request = SignWithECDSAArgs::new(message_hash.to_vec(), [0u8; 32].to_vec());

        // Ask for a signature:
        let uni_can = UniversalCanister::new(&agent).await;
        let res = uni_can
            .forward_to(
                &Principal::management_canister(),
                "sign_with_mock_ecdsa",
                Encode!(&request).unwrap(),
            )
            .await;

        let response_signature =
            Signature::from_compact(&res.expect("sign_with_mock_ecdsa returned an error}"))
                .expect("Response is not a valid signature");

        // Ask for the public key:
        let uni_can = UniversalCanister::new(&agent).await;
        let res = uni_can
            .forward_to(
                &Principal::management_canister(),
                "get_mock_ecdsa_public_key",
                Encode!(&[0u8; 0]).unwrap(),
            )
            .await;

        let public_key =
            PublicKey::from_slice(&res.expect("get_mock_ecdsa_public_key returned an error}"))
                .expect("Response is not a valid public key");

        // Verify the signature:
        let secp = Secp256k1::new();
        let message = Message::from_slice(&message_hash).expect("32 bytes");
        assert!(secp
            .verify(&message, &response_signature, &public_key)
            .is_ok());
    });
}
