use ic_certification_test_utils::{
    CertificateBuilder, CertificateData, create_certificate_labeled_tree, generate_root_of_trust,
};
use ic_types::{
    CanisterId, SubnetId,
    crypto::threshold_sig::ThresholdSigPublicKey,
    messages::{Blob, CertificateDelegation},
};
use rand::thread_rng;

pub fn create_fake_certificate_delegation(
    canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
    subnet_id: SubnetId,
) -> (CertificateDelegation, ThresholdSigPublicKey) {
    const MAX_RANGES_PER_ROUTING_TABLE_LEAF: usize = 5;

    let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
    let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());
    let certificate_tree = create_certificate_labeled_tree(
        canister_id_ranges,
        subnet_id,
        non_nns_public_key,
        MAX_RANGES_PER_ROUTING_TABLE_LEAF,
        /*time=*/ 42,
        /*with_tree_canister_ranges=*/ true,
        /*with_flat_canister_ranges=*/ true,
    );

    let (_certificate, root_pk, cbor) =
        CertificateBuilder::new(CertificateData::CustomTree(certificate_tree))
            .with_root_of_trust(nns_public_key, nns_secret_key)
            .build();

    let delegation = CertificateDelegation {
        subnet_id: Blob(subnet_id.get_ref().to_vec()),
        certificate: Blob(cbor),
    };

    (delegation, root_pk)
}
