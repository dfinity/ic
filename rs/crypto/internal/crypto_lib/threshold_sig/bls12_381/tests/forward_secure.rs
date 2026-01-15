#![allow(clippy::needless_range_loop)]

//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_bls12_381_type::{G2Affine, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{Epoch, forward_secure::*};
use ic_crypto_sha2::Sha256;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng, RngCore};

#[test]
fn output_of_mk_sys_params_is_expected_values() {
    let sys = SysParam::global();

    assert_eq!(sys.f().len(), LAMBDA_T);
    assert_eq!(sys.f_h().len(), LAMBDA_H);

    fn assert_g2_equal(g2: &G2Affine, expected: &'static str) {
        assert_eq!(hex::encode(g2.serialize()), expected);
    }

    assert_g2_equal(
        sys.f0(),
        "8422a9f8fdd31d70efea5a8fff9e0dab7707703cd0654d5b5c92a654b4cf60bbc74ea1b40b9eb6ef036f647ed196418c199c775a89be3e15c1df45cadd48e99e60ef0d7142132876eaf91c03c9f1fcabcec3a61b34e2341f38418d006e02f502",
    );

    assert_g2_equal(
        sys.h(),
        "a130c9e5530dc7d5f4bf5d40ad719f4a0d38e58502ab63ed27d3d9bdc545f21eb9cf18462a04b0fc943e0dd537aa2f2e0b140b0db9adef851e26721ef88caf1da5b20bb3593f9fb7a4312f0c0ea868d6b08d658d08ff832ff1df8d71471b61b6",
    );

    let mut sha256 = Sha256::new();
    for val in sys.f() {
        sha256.write(&val.serialize());
    }
    assert_eq!(
        hex::encode(sha256.finish()),
        "e3c7e40dc4a2793d0f95c591b220d9b60338691babeb41dd4affbaca2e3e6d4f"
    );

    let mut sha256 = Sha256::new();
    for val in sys.f_h() {
        sha256.write(&val.serialize());
    }
    assert_eq!(
        hex::encode(sha256.finish()),
        "e8333333283597a1965a7fb7c07efb9ee35c4f4089bb26008ba4d3edefa61b18"
    );
}

#[test]
fn fs_keys_should_be_valid() {
    let sys = SysParam::global();
    let rng = &mut reproducible_rng();
    let key_gen_assoc_data = rng.r#gen::<[u8; 32]>();

    let (pk, _dk) = kgen(&key_gen_assoc_data, sys, rng);
    assert!(
        pk.verify(&key_gen_assoc_data),
        "Generated public key should be valid"
    );
}

fn keys_and_ciphertext_for<R: RngCore + CryptoRng>(
    epoch: Epoch,
    associated_data: &[u8],
    rng: &mut R,
) -> (
    Vec<(PublicKeyWithPop, SecretKey)>,
    Vec<Scalar>,
    FsEncryptionCiphertext,
) {
    let sys = SysParam::global();
    let key_gen_assoc_data = rng.r#gen::<[u8; 32]>();

    let nodes = 3;

    let mut keys = Vec::new();
    for _ in 0..nodes {
        let key_pair = kgen(&key_gen_assoc_data, sys, rng);
        keys.push(key_pair);
    }
    let pks: Vec<_> = keys.iter().map(|key| key.0.public_key().clone()).collect();

    let ptext = (0..nodes).map(|_| Scalar::random(rng)).collect::<Vec<_>>();

    let ptext_chunks: Vec<_> = ptext
        .iter()
        .map(PlaintextChunks::from_scalar)
        .collect::<Vec<_>>();

    let pks_and_scalars = pks.iter().cloned().zip(ptext_chunks).collect::<Vec<_>>();

    let (crsz, _witness) = enc_chunks(&pks_and_scalars, epoch, associated_data, sys, rng);
    (keys, ptext, crsz)
}

#[test]
fn integrity_check_should_return_error_on_wrong_associated_data() {
    let sys = SysParam::global();
    let rng = &mut reproducible_rng();
    let epoch = Epoch::from(0);
    let associated_data = rng.r#gen::<[u8; 32]>();

    let wrong_associated_data = {
        let mut wrong = associated_data;
        wrong[0] ^= 1;
        wrong
    };

    let (_keys, _message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &wrong_associated_data, sys).is_err());
}

#[test]
fn should_encrypt_with_empty_associated_data() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let rng = &mut reproducible_rng();
    let associated_data = [];
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let out = dec_chunks(&keys[i].1, i, &crsz, epoch, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

#[test]
fn should_decrypt_correctly_for_cheating_dealer() {
    let epoch = Epoch::from(0);
    let rng = &mut reproducible_rng();
    let associated_data = rng.r#gen::<[u8; 10]>();

    let sys = SysParam::global();
    let key_gen_assoc_data = rng.r#gen::<[u8; 32]>();

    let nodes = 3;

    let mut keys = Vec::new();
    for _ in 0..nodes {
        let key_pair = kgen(&key_gen_assoc_data, sys, rng);
        keys.push(key_pair);
    }
    let pks: Vec<_> = keys.iter().map(|key| key.0.public_key().clone()).collect();

    let mut sij = {
        let mut sij = Vec::with_capacity(nodes);

        for _ in 0..nodes {
            let mut chunks = [0; NUM_CHUNKS];

            for i in 0..NUM_CHUNKS {
                // ensure that multiplying by delta pushes us out of Chunk range
                let chunk = (0x8000 | rng.r#gen::<u16>()) as isize;
                chunks[i] = chunk;
            }
            // this ensures that chunks is the encoding of a scalar less
            // than the group order:
            chunks[0] %= 0x73ee;

            sij.push(chunks);
        }

        sij
    };

    let cheating_i = rng.r#gen::<usize>() % nodes;
    let cheating_j = std::cmp::max(1, rng.r#gen::<usize>() % NUM_CHUNKS);

    let delta = (2 + rng.r#gen::<usize>() % 10) as isize;
    sij[cheating_i][cheating_j] *= delta; // doesn't overflow as delta is small and isize >> u16

    // however the new sij *is* larger than the maximum "legal" chunk
    assert!(sij[cheating_i][cheating_j] > CHUNK_MAX);

    let cheating_chunks = sij
        .iter()
        .map(|c| PlaintextChunks::new_unchecked(*c))
        .collect::<Vec<_>>();

    let pks_and_chunks = pks
        .iter()
        .cloned()
        .zip(cheating_chunks.iter().cloned())
        .collect::<Vec<_>>();

    let (crsz, _witness) = enc_chunks(&pks_and_chunks, epoch, &associated_data, sys, rng);

    // still a valid ciphertext
    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, epoch, &associated_data);
        assert_eq!(
            out.unwrap(),
            cheating_chunks[i].recombine_to_scalar(),
            "Message decrypted wrongly"
        );
    }
}

#[test]
fn should_decrypt_correctly_for_epoch_0() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let rng = &mut reproducible_rng();
    let associated_data = rng.r#gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, epoch, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

#[test]
fn should_decrypt_correctly_for_epoch_1() {
    let sys = SysParam::global();
    let epoch = Epoch::from(1);
    let rng = &mut reproducible_rng();
    let associated_data = rng.r#gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, epoch, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_5() {
    let sys = SysParam::global();
    let epoch = Epoch::from(5);
    let rng = &mut reproducible_rng();
    let associated_data = rng.r#gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, epoch, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_10() {
    let sys = SysParam::global();
    let epoch = Epoch::from(10);
    let rng = &mut reproducible_rng();
    let associated_data = rng.r#gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    assert!(verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, epoch, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
