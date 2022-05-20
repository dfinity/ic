/* tag::catalog[]
end::catalog[] */

use crate::nns::NnsExt;
use crate::tecdsa::tecdsa_signature_test::{
    get_public_key, get_signature, make_key, verify_signature, KEY_ID1,
};
use crate::util::*;
use canister_test::{Canister, Cycles};
use ic_fondue::{
    ic_instance::{LegacyInternetComputer as InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::Height;

use super::tecdsa_signature_test::{enable_ecdsa_signing, DKG_INTERVAL};

pub fn config() -> InternetComputer {
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_corrupt_ecdsa_dealings();
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL))
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
    ctx.install_nns_canisters(&handle, true);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    rt.block_on(async move {
        let endpoint = get_random_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID1),
        )
        .await;

        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(make_key(KEY_ID1), &uni_can, ctx)
            .await
            .unwrap();
        let signature = get_signature(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID1),
            &uni_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
