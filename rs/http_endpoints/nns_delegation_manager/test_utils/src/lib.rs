use ic_certification_test_utils::{
    encoded_time, generate_root_of_trust, serialize_to_cbor, CertificateBuilder, CertificateData,
};
use ic_crypto_tree_hash::{flatmap, FlatMap, Label, LabeledTree};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey,
    messages::{Blob, CertificateDelegation},
    CanisterId, SubnetId,
};
use rand::thread_rng;

pub fn create_fake_certificate_delegation(
    canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
    subnet_id: SubnetId,
) -> (CertificateDelegation, ThresholdSigPublicKey) {
    let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
    let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());

    const MAX_RANGES_PER_ROUTING_TABLE_LEAF: usize = 5;

    let canister_ranges_subnet_0_subtree = LabeledTree::SubTree(FlatMap::from_key_values(
        canister_id_ranges
            .chunks(MAX_RANGES_PER_ROUTING_TABLE_LEAF)
            .map(|chunk| {
                (
                    Label::from(chunk[0].0),
                    LabeledTree::Leaf(serialize_to_cbor(&chunk)),
                )
            })
            .collect(),
    ));
    let canister_ranges_subtree = LabeledTree::SubTree(flatmap![
        Label::from(subnet_id.get_ref().to_vec()) => canister_ranges_subnet_0_subtree,
    ]);

    let (_certificate, root_pk, cbor) =
             CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                 Label::from("subnet") => LabeledTree::SubTree(flatmap![
                     Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                         Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(canister_id_ranges)),
                         Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&non_nns_public_key.into_bytes()).unwrap()),
                     ])
                 ]),
                 Label::from("canister_ranges") => canister_ranges_subtree,
                 Label::from("time") => LabeledTree::Leaf(encoded_time(42))
             ])))
             .with_root_of_trust(nns_public_key, nns_secret_key)
             .build();

    let delegation = CertificateDelegation {
        subnet_id: Blob(subnet_id.get_ref().to_vec()),
        certificate: Blob(cbor),
    };

    (delegation, root_pk)
}
