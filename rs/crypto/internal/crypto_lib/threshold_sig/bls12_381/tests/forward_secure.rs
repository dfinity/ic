#![allow(clippy::unwrap_used)]
//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Gt, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{forward_secure::*, Epoch};
use ic_crypto_sha::Sha256;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

#[test]
fn output_of_mk_sys_params_is_expected_values() {
    let sys = SysParam::global();

    assert_eq!(sys.lambda_t, 32);
    assert_eq!(sys.lambda_h, 256);

    assert_eq!(sys.f.len(), sys.lambda_t);
    assert_eq!(sys.f_h.len(), sys.lambda_h);

    fn assert_g2_equal(g2: &G2Affine, expected: &'static str) {
        assert_eq!(hex::encode(g2.serialize()), expected);
    }

    assert_g2_equal(&sys.f0,
                    "8422a9f8fdd31d70efea5a8fff9e0dab7707703cd0654d5b5c92a654b4cf60bbc74ea1b40b9eb6ef036f647ed196418c199c775a89be3e15c1df45cadd48e99e60ef0d7142132876eaf91c03c9f1fcabcec3a61b34e2341f38418d006e02f502");

    assert_g2_equal(&sys.h,
                    "a130c9e5530dc7d5f4bf5d40ad719f4a0d38e58502ab63ed27d3d9bdc545f21eb9cf18462a04b0fc943e0dd537aa2f2e0b140b0db9adef851e26721ef88caf1da5b20bb3593f9fb7a4312f0c0ea868d6b08d658d08ff832ff1df8d71471b61b6");

    let mut sha256 = Sha256::new();
    for val in &sys.f {
        sha256.write(&val.serialize());
    }
    assert_eq!(
        hex::encode(sha256.finish()),
        "e3c7e40dc4a2793d0f95c591b220d9b60338691babeb41dd4affbaca2e3e6d4f"
    );

    let mut sha256 = Sha256::new();
    for val in &sys.f_h {
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
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([99; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[3u8, 0u8, 0u8, 0u8];

    let (pk, _dk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, &mut rng);
    assert!(
        pk.verify(KEY_GEN_ASSOCIATED_DATA),
        "Generated public key should be valid"
    );
}

fn keys_and_ciphertext_for<R: RngCore + CryptoRng>(
    epoch: Epoch,
    associated_data: &[u8],
    rng: &mut R,
) -> (
    Vec<(PublicKeyWithPop, SecretKey)>,
    Vec<Vec<isize>>,
    FsEncryptionCiphertext,
) {
    let sys = SysParam::global();
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[0u8, 1u8, 0u8, 6u8];

    let mut keys = Vec::new();
    for i in 0u8..3 {
        println!("generating key pair {}...", i);
        let key_pair = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
        println!("{:#?}", &key_pair.0);
        keys.push(key_pair);
    }
    let public_keys_with_zk: Vec<_> = keys.iter().map(|key| &key.0).collect();
    let pks = public_keys_with_zk
        .iter()
        .map(|key| key.key_value)
        .collect::<Vec<_>>();

    let sij: Vec<_> = (0..keys.len())
        .map(|receiver_index| {
            let chunk =
                (receiver_index | (receiver_index << 8) | 0x0FF00FF0) % (CHUNK_SIZE as usize);
            vec![chunk as isize; NUM_CHUNKS]
        })
        .collect();
    println!("Messages: {:#?}", sij);

    let tau = tau_from_epoch(sys, epoch);
    let (crsz, _witness) =
        enc_chunks(&sij[..], &pks, &tau, associated_data, sys, rng).expect("Encryption failed");
    (keys, sij, crsz)
}

#[test]
fn integrity_check_should_return_error_on_wrong_associated_data() {
    let sys = SysParam::global();
    let mut rng = rand::thread_rng();
    let epoch = Epoch::from(0);
    let associated_data: Vec<u8> = vec![3u8; 12];
    let wrong_associated_data: Vec<u8> = vec![1u8; 7];

    let (_keys, _message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);
    let tau = tau_from_epoch(sys, epoch);

    assert_eq!(
        Err(()),
        verify_ciphertext_integrity(&crsz, &tau, &wrong_associated_data, sys)
    );
}

#[test]
fn should_encrypt_with_empty_associated_data() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let mut rng = rand::thread_rng();
    let associated_data: Vec<u8> = Vec::new();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let out = dec_chunks(&keys[i].1, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

#[test]
fn should_decrypt_correctly_for_epoch_0() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let mut rng = rand::thread_rng();
    let associated_data: Vec<u8> = rng.gen::<[u8; 10]>().to_vec();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_1() {
    let sys = SysParam::global();
    let epoch = Epoch::from(1);
    let mut rng = rand::thread_rng();
    let associated_data: Vec<u8> = rng.gen::<[u8; 10]>().to_vec();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_5() {
    let sys = SysParam::global();
    let epoch = Epoch::from(5);
    let mut rng = rand::thread_rng();
    let associated_data: Vec<u8> = rng.gen::<[u8; 10]>().to_vec();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_10() {
    let sys = SysParam::global();
    let epoch = Epoch::from(10);
    let mut rng = rand::thread_rng();
    let associated_data: Vec<u8> = rng.gen::<[u8; 10]>().to_vec();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

// Returns a random element of Gt
fn gt_rand() -> Gt {
    let mut rng = rand::thread_rng();
    let g1 = G1Affine::hash(b"ic-crypto-test-fp12-random", &rng.gen::<[u8; 32]>());
    let g2 = G2Affine::generator();
    Gt::pairing(&g1, g2)
}

#[test]
fn baby_giant_1000() {
    for x in 0..1000 {
        let base = gt_rand();
        let tgt = base * Scalar::from_isize(x);
        assert!(
            baby_giant(&tgt, &base, -24, 1024).unwrap() == x,
            "baby-giant finds x"
        );
    }
}

#[test]
fn baby_giant_negative() {
    for x in 0..1000 {
        let base = gt_rand();
        let tgt = base * Scalar::from_isize(x).neg();
        assert!(
            baby_giant(&tgt, &base, -999, 1000).unwrap() == -x,
            "baby-giant finds x"
        );
    }
}

// The bounds of the NIZK chunking proof are loose, so a malicious DKG
// participant can force us to search around 2^40 candidates for a discrete log.
// (This is not the entire cost. We must also search for a cofactor Delta.)
#[test]
fn baby_giant_big_range() {
    let x = (1 << 39) + 123;
    let base = gt_rand();
    let tgt = base * Scalar::from_isize(x);
    assert!(
        baby_giant(&tgt, &base, -(1 << 10), 1 << 40).unwrap() == x,
        "baby-giant finds x"
    );
}

// Find the log for a cheater who exceeds the bounds by a little.
#[test]
fn slightly_dishonest_dlog() {
    let base = Gt::generator();

    // Last I checked:
    //   E = 128
    //   Z = 31960108800 * m * n
    // So searching for Delta < 10 with m = n = 1 should be tolerable.

    let mut answer = Scalar::from_usize(8).inverse().expect("Inverse exists");
    answer *= Scalar::from_usize(12345678);
    assert_eq!(solve_cheater_log(1, 1, &(base * answer)), Some(answer));

    // Check negative numbers also work.
    let mut answer = Scalar::from_usize(5).inverse().expect("Inverse exists");
    answer *= Scalar::from_isize(-12345678);
    assert_eq!(solve_cheater_log(1, 1, &(base * answer)), Some(answer));
}
