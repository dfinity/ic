use ic_crypto_internal_bls12_381_type::Polynomial;
use ic_crypto_internal_bls12_381_vetkd::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

#[test]
fn should_encrypted_key_share_be_functional() {
    let derivation_path = DerivationPath::new(b"canister-id", &[b"1", b"2"]);
    let did = b"message";

    let rng = &mut reproducible_rng();

    let nodes = 31;
    let threshold = 11;

    let poly = Polynomial::random(threshold + 1, rng);

    let tsk = TransportSecretKey::generate(rng);
    let tpk = tsk.public_key();
    //let (tpk, tsk) = transport_keygen(rng);

    let master_sk = poly.coeff(0);
    let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

    let dpk = DerivedPublicKey::compute_derived_key(&master_pk, &derivation_path);

    let mut node_info = Vec::with_capacity(nodes);

    for node in 0..nodes {
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
        let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

        let eks = EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &derivation_path, did);

        assert!(eks.is_valid(&master_pk, &node_pk, &derivation_path, did, &tpk));

        // check that EKS serialization round trips:
        let eks_bytes = eks.serialize();
        let eks2 = EncryptedKeyShare::deserialize(eks_bytes).unwrap();
        assert_eq!(eks, eks2);

        node_info.push((node as u32, node_pk, eks));
    }

    let ek = EncryptedKey::combine(
        &node_info,
        threshold,
        &master_pk,
        &tpk,
        &derivation_path,
        did,
    )
    .unwrap();

    let _k = tsk.decrypt(&ek, &dpk, did).unwrap();

    let derived_key = tsk
        .decrypt_and_hash(&ek, &dpk, did, 32, b"aes-256-gcm-siv")
        .unwrap();
    assert_eq!(derived_key.len(), 32);
}
