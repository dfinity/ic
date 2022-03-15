/* tag::catalog[]
end::catalog[] */

use crate::types::*;
use crate::util::*;
use candid::Encode;
use candid::Principal;
use ic_fondue::{
    ic_manager::IcHandle,
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_ic00_types::SignWithECDSAArgs;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;

/// Tests whether a call to `sign_with_ecdsa` is rejected when called on a
/// subnet where the corresponding feature flag is not explicitly enabled.
pub fn ecdsa_signatures_disabled_by_default(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;

        let request = SignWithECDSAArgs {
            message_hash: [0u8; 32].to_vec(),
            derivation_path: Vec::new(),
            key_id: "secp256k1".to_string(),
        };

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
            http_requests: true,
            bitcoin_testnet_feature: None,
        },
    ))
}
