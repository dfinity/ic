use ic_hpke::*;
use rand::{Rng, RngCore, SeedableRng};

#[test]
fn key_generation_and_noauth_encrypt_is_stable() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

    let sk = PrivateKey::generate(&mut rng);

    let sk_bytes = sk.serialize();
    assert_eq!(sk_bytes.len(), 56);
    assert_eq!(
        hex::encode(sk_bytes),
        "49432048504b4501ca9b347c733a5375e97fb372763bd3b3478fce3ab7c7c340521d410051eff1c5cea6efa33cbf0910b919730726c42397"
    );

    let pk = sk.public_key();
    let pk_bytes = pk.serialize();
    assert_eq!(pk_bytes.len(), 105);
    assert_eq!(
        hex::encode(pk_bytes),
        "49432048504b4501041e0fff52d0cb05f440c47614c50c2ace65db74194fc85fc55345140a9543bf1228dab6f0e4254505c7eaf692f7d8478eb8f027d944acc65d2c6818101b55a28861abc6386e6c85ded766e48e211253184ccaf7243685fe7ac36526a9ac7a4311"
    );

    let msg = b"this is a test";
    let aad = b"test associated data";

    let ctext = pk
        .encrypt_noauth(msg, aad, &mut rng)
        .expect("encryption failed");

    // 8 bytes version, 1+2*48 bytes P-384 point, 16 bytes GCM tag
    assert_eq!(ctext.len(), 8 + (1 + 2 * 48) + 16 + msg.len());

    assert_eq!(
        hex::encode(ctext),
        "49432048504b45010489d22b35f935051f9dd57c2e7909c388e97c2d960129ee92a0478710e4da9cfd6cda78881c297610d4776a27d73283675f743e1d20ce9019706d659b77aa78fc30f93000468ff2304b0c442c134f094e5e8d99b784f03eafee1c8f802cf661075a3c6e8e08338ef78f1a0a6731d5db1f0eb5131ce37ad7a0082a6be021d3"
    );
}

#[test]
fn key_generation_and_authticated_encrypt_is_stable() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

    let sk_a = PrivateKey::generate(&mut rng);
    let sk_b = PrivateKey::generate(&mut rng);

    let pk_a = sk_a.public_key();
    let pk_b = sk_b.public_key();

    let msg = b"this is a test";
    let aad = b"test associated data";

    let ctext_b_to_a = {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        pk_a.encrypt(msg, aad, &sk_b, &mut rng)
            .expect("encryption failed")
    };

    let ctext_a_to_b = {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        pk_b.encrypt(msg, aad, &sk_a, &mut rng)
            .expect("encryption failed")
    };

    assert_eq!(
        hex::encode(&ctext_b_to_a),
        "49432048504b450104c9613312faa2b1d5739c89a08ed6d3cb4935b5ad28db5855c19e32eb0f1f6fe6bb9f164da4524c8998d6c1529b99d429c93436a0f2dcdf3c58f806e0824c266dd43d29f2784176d56f2df1632ef1cf454da0ff52e9532eb452c928150f6710f6b80fe5a3ac17b9dc8b5c443f58c985f6365de6c756102e6bdb9e60432e11"
    );

    assert_eq!(
        hex::encode(&ctext_a_to_b),
        "49432048504b450104c9613312faa2b1d5739c89a08ed6d3cb4935b5ad28db5855c19e32eb0f1f6fe6bb9f164da4524c8998d6c1529b99d429c93436a0f2dcdf3c58f806e0824c266dd43d29f2784176d56f2df1632ef1cf454da0ff52e9532eb452c928150f6710f6d95b9ef4b2286c8ad9f0199bb716844ad13dec45cdb7bb265d4838369f72"
    );
}

#[test]
fn smoke_test_noauth() {
    let mut rng = rand::rngs::OsRng;
    let sk = PrivateKey::generate(&mut rng);
    let pk = sk.public_key();

    for ptext_len in 0..128 {
        let mut ptext = vec![0u8; ptext_len];
        rng.fill_bytes(&mut ptext);
        let aad = rng.r#gen::<[u8; 32]>();
        let ctext = pk.encrypt_noauth(&ptext, &aad, &mut rng).unwrap();
        let rec = sk.decrypt_noauth(&ctext, &aad).unwrap();
        assert_eq!(rec, ptext);
    }
}

#[test]
fn smoke_test_auth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let b_sk = PrivateKey::generate(&mut rng);
    let b_pk = b_sk.public_key();

    let aad = rng.r#gen::<[u8; 32]>();

    for ptext_len in 0..128 {
        let mut ptext = vec![0u8; ptext_len];
        rng.fill_bytes(&mut ptext);
        let ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();
        let rec = a_sk.decrypt(&ctext, &aad, &b_pk).unwrap();
        assert_eq!(rec, ptext);

        assert!(a_sk.decrypt_noauth(&ctext, &aad).is_err());
    }
}

#[test]
fn any_bit_flip_causes_rejection_noauth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let ptext = rng.r#gen::<[u8; 16]>().to_vec();
    let aad = rng.r#gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt_noauth(&ptext, &aad, &mut rng).unwrap();

    let bits = ctext.len() * 8;

    for bit in 0..bits {
        ctext[bit / 8] ^= 1 << (bit % 8);
        assert!(a_sk.decrypt_noauth(&ctext, &aad).is_err());

        // restore the bit we just flipped
        ctext[bit / 8] ^= 1 << (bit % 8);
    }

    assert_eq!(a_sk.decrypt_noauth(&ctext, &aad), Ok(ptext));
}

#[test]
fn any_bit_flip_causes_rejection_auth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let b_sk = PrivateKey::generate(&mut rng);
    let b_pk = b_sk.public_key();

    let ptext = rng.r#gen::<[u8; 16]>().to_vec();
    let aad = rng.r#gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();

    let bits = ctext.len() * 8;

    for bit in 0..bits {
        ctext[bit / 8] ^= 1 << (bit % 8);
        assert!(a_sk.decrypt(&ctext, &aad, &b_pk).is_err());

        // restore the bit we just flipped
        ctext[bit / 8] ^= 1 << (bit % 8);
    }

    assert_eq!(a_sk.decrypt(&ctext, &aad, &b_pk), Ok(ptext));
}

#[test]
fn any_truncation_causes_rejection_noauth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let ptext = rng.r#gen::<[u8; 16]>().to_vec();
    let aad = rng.r#gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt_noauth(&ptext, &aad, &mut rng).unwrap();

    assert_eq!(a_sk.decrypt_noauth(&ctext, &aad), Ok(ptext));

    loop {
        ctext.pop();

        assert!(a_sk.decrypt_noauth(&ctext, &aad).is_err());

        if ctext.is_empty() {
            break;
        }
    }
}

#[test]
fn any_truncation_causes_rejection_auth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let b_sk = PrivateKey::generate(&mut rng);
    let b_pk = b_sk.public_key();

    let ptext = rng.r#gen::<[u8; 16]>().to_vec();
    let aad = rng.r#gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();

    assert_eq!(a_sk.decrypt(&ctext, &aad, &b_pk), Ok(ptext));

    loop {
        ctext.pop();

        assert!(a_sk.decrypt(&ctext, &aad, &b_pk).is_err());

        if ctext.is_empty() {
            break;
        }
    }
}
