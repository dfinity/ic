/* tag::catalog[]
end::catalog[] */

use crate::tecdsa_signature_test::{get_public_key, get_signature, verify_signature};
use crate::util::*;
use canister_test::Cycles;
use ic_fondue::{
    ic_instance::{LegacyInternetComputer as InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::Height;

pub fn enable_ecdsa_signatures_feature() -> InternetComputer {
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_corrupt_ecdsa_dealings();
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(19))
            .add_nodes(3)
            .add_malicious_nodes(1, malicious_behaviour)
            .with_features(SubnetFeatures {
                ecdsa_signatures: true,
                ..SubnetFeatures::default()
            }),
    )
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`. This is done
/// in the presence of corrupted dealings/complaints.
pub fn test_threshold_ecdsa_complaint(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(&uni_can, ctx).await;
        let signature = get_signature(&message_hash, Cycles::zero(), &uni_can, ctx)
            .await
            .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
