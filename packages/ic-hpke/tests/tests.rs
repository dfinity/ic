use ic_hpke::*;
use rand::{Rng, RngCore};

#[test]
fn smoke_test_noauth() {
    let mut rng = rand::rngs::OsRng;
    let sk = PrivateKey::generate(&mut rng);
    let pk = sk.public_key();

    for ptext_len in 0..128 {
        let mut ptext = vec![0u8; ptext_len];
        rng.fill_bytes(&mut ptext);
        let aad = rng.gen::<[u8; 32]>();
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

    let aad = rng.gen::<[u8; 32]>();

    for ptext_len in 0..128 {
        let mut ptext = vec![0u8; ptext_len];
        rng.fill_bytes(&mut ptext);
        let ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();
        let rec = a_sk.decrypt(&ctext, &aad, &b_pk).unwrap();
        assert_eq!(rec, ptext);
    }
}

#[test]
fn any_bit_flip_causes_rejection_noauth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let ptext = rng.gen::<[u8; 16]>();
    let aad = rng.gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt_noauth(&ptext, &aad, &mut rng).unwrap();

    let bits = ctext.len() * 8;

    for bit in 0..bits {
        ctext[bit / 8] ^= 1 << (bit % 8);
        assert!(a_sk.decrypt_noauth(&ctext, &aad).is_err());

        // restore the bit we just flipped
        ctext[bit / 8] ^= 1 << (bit % 8);
    }

    assert_eq!(a_sk.decrypt_noauth(&ctext, &aad).unwrap(), ptext);
}

#[test]
fn any_bit_flip_causes_rejection_auth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let b_sk = PrivateKey::generate(&mut rng);
    let b_pk = b_sk.public_key();

    let ptext = rng.gen::<[u8; 16]>();
    let aad = rng.gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();

    let bits = ctext.len() * 8;

    for bit in 0..bits {
        ctext[bit / 8] ^= 1 << (bit % 8);
        assert!(a_sk.decrypt(&ctext, &aad, &b_pk).is_err());

        // restore the bit we just flipped
        ctext[bit / 8] ^= 1 << (bit % 8);
    }

    assert_eq!(a_sk.decrypt(&ctext, &aad, &b_pk).unwrap(), ptext);
}

#[test]
fn any_truncation_causes_rejection_noauth() {
    let mut rng = rand::rngs::OsRng;

    let a_sk = PrivateKey::generate(&mut rng);
    let a_pk = a_sk.public_key();

    let ptext = rng.gen::<[u8; 16]>();
    let aad = rng.gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt_noauth(&ptext, &aad, &mut rng).unwrap();

    assert_eq!(a_sk.decrypt_noauth(&ctext, &aad).unwrap(), ptext);

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

    let ptext = rng.gen::<[u8; 16]>();
    let aad = rng.gen::<[u8; 32]>();

    let mut ctext = a_pk.encrypt(&ptext, &aad, &b_sk, &mut rng).unwrap();

    assert_eq!(a_sk.decrypt(&ctext, &aad, &b_pk).unwrap(), ptext);

    loop {
        ctext.pop();

        assert!(a_sk.decrypt(&ctext, &aad, &b_pk).is_err());

        if ctext.is_empty() {
            break;
        }
    }
}
