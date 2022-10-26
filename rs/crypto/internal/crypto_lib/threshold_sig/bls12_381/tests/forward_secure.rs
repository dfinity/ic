#![allow(clippy::needless_range_loop)]
#![allow(clippy::unwrap_used)]

//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{forward_secure::*, Epoch};
use ic_crypto_sha::Sha256;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

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

pub fn test_rng() -> ChaCha20Rng {
    let mut thread_rng = rand::thread_rng();
    let seed = thread_rng.gen::<u64>();
    println!("RNG seed {}", seed);
    ChaCha20Rng::seed_from_u64(seed)
}

#[test]
fn fs_keys_should_be_valid() {
    let sys = SysParam::global();
    let mut rng = test_rng();
    let key_gen_assoc_data = rng.gen::<[u8; 32]>();

    let (pk, _dk) = kgen(&key_gen_assoc_data, sys, &mut rng);
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
    Vec<Vec<isize>>,
    FsEncryptionCiphertext,
) {
    let sys = SysParam::global();
    let key_gen_assoc_data = rng.gen::<[u8; 32]>();

    let nodes = 3;

    let mut keys = Vec::new();
    for _ in 0..nodes {
        let key_pair = kgen(&key_gen_assoc_data, sys, rng);
        keys.push(key_pair);
    }
    let pks: Vec<_> = keys.iter().map(|key| key.0.key_value).collect();

    let sij = {
        let mut sij = Vec::with_capacity(nodes);

        for _ in 0..nodes {
            let mut chunks = Vec::with_capacity(NUM_CHUNKS);
            for _ in 0..NUM_CHUNKS {
                chunks.push(rng.gen::<u16>() as isize);
            }
            // this ensures that chunks is the encoding of a scalar less
            // than the group order:
            chunks[0] %= 0x73ee;

            sij.push(chunks);
        }

        sij
    };

    let tau = tau_from_epoch(sys, epoch);
    let (crsz, _witness) =
        enc_chunks(&sij[..], &pks, &tau, associated_data, sys, rng).expect("Encryption failed");
    (keys, sij, crsz)
}

#[test]
fn integrity_check_should_return_error_on_wrong_associated_data() {
    let sys = SysParam::global();
    let mut rng = test_rng();
    let epoch = Epoch::from(0);
    let associated_data = rng.gen::<[u8; 32]>();

    let wrong_associated_data = {
        let mut wrong = associated_data;
        wrong[0] ^= 1;
        wrong
    };

    let (_keys, _message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);
    let tau = tau_from_epoch(sys, epoch);

    assert!(verify_ciphertext_integrity(&crsz, &tau, &wrong_associated_data, sys).is_err());
}

#[test]
fn should_encrypt_with_empty_associated_data() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let mut rng = test_rng();
    let associated_data = [];
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let out = dec_chunks(&keys[i].1, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

/// Encrypt chunks as a cheating dealer. This is the same as enc_chunks
/// except that the range checks on the input are skipped
fn enc_chunks_cheating<R: RngCore + CryptoRng>(
    sij: &[Vec<isize>],
    pks: &[G1Affine],
    tau: &[Bit],
    associated_data: &[u8],
    sys: &SysParam,
    rng: &mut R,
) -> FsEncryptionCiphertext {
    let receivers = pks.len();
    let chunks = sij[0].len();

    let g1 = G1Affine::generator();

    // do
    //   spec_r <- replicateM chunks getRandom
    //   s <- replicateM chunks getRandom
    //   let rr = (g1^) <$> spec_r
    //   let ss = (g1^) <$> s
    let mut spec_r = Vec::with_capacity(chunks);
    let mut s = Vec::with_capacity(chunks);
    let mut rr = Vec::with_capacity(chunks);
    let mut ss = Vec::with_capacity(chunks);
    for _j in 0..chunks {
        {
            let tmp = Scalar::random(rng);
            spec_r.push(tmp);
            rr.push(G1Affine::from(g1 * tmp));
        }
        {
            let tmp = Scalar::random(rng);
            s.push(tmp);
            ss.push(G1Affine::from(g1 * tmp));
        }
    }

    // cc = [[pk^spec_r * g1^s | (spec_r, s) <- zip rs si] | (pk, si) <- zip pks sij]
    let cc = {
        let mut cc: Vec<Vec<G1Affine>> = Vec::with_capacity(pks.len());

        let g1 = G1Projective::from(g1);

        for i in 0..receivers {
            let pk = G1Projective::from(pks[i]);

            let mut enc_chunks = Vec::with_capacity(chunks);

            for j in 0..chunks {
                let s = Scalar::from_isize(sij[i][j]);
                enc_chunks.push(G1Projective::mul2(&pk, &spec_r[j], &g1, &s).to_affine());
            }

            cc.push(enc_chunks);
        }

        cc
    };

    let extended_tau = extend_tau(&cc, &rr, &ss, tau, associated_data);
    let id = ftau(&extended_tau, sys).expect("extended_tau not the correct size");
    let mut zz = Vec::with_capacity(chunks);

    for j in 0..chunks {
        zz.push(G2Projective::mul2(&id, &spec_r[j], &sys.h.into(), &s[j]).to_affine())
    }

    FsEncryptionCiphertext { cc, rr, ss, zz }
}

#[test]
fn should_decrypt_correctly_for_cheating_dealer() {
    let epoch = Epoch::from(0);
    let mut rng = test_rng();
    let associated_data = rng.gen::<[u8; 10]>();

    let sys = SysParam::global();
    let key_gen_assoc_data = rng.gen::<[u8; 32]>();

    let nodes = 3;

    let mut keys = Vec::new();
    for _ in 0..nodes {
        let key_pair = kgen(&key_gen_assoc_data, sys, &mut rng);
        keys.push(key_pair);
    }
    let pks: Vec<_> = keys.iter().map(|key| key.0.key_value).collect();

    let mut sij = {
        let mut sij = Vec::with_capacity(nodes);

        for _ in 0..nodes {
            let mut chunks = Vec::with_capacity(NUM_CHUNKS);

            for _ in 0..NUM_CHUNKS {
                // ensure that multiplying by delta pushes us out of Chunk range
                let chunk = (0x8000 | rng.gen::<u16>()) as isize;
                chunks.push(chunk);
            }
            // this ensures that chunks is the encoding of a scalar less
            // than the group order:
            chunks[0] %= 0x73ee;

            sij.push(chunks);
        }

        sij
    };

    let cheating_i = rng.gen::<usize>() % nodes;
    let cheating_j = std::cmp::max(1, rng.gen::<usize>() % NUM_CHUNKS);

    let delta = (2 + rng.gen::<usize>() % 10) as isize;
    sij[cheating_i][cheating_j] *= delta; // doesn't overflow as delta is small and isize >> u16

    // however the new sij *is* larger than the maximum "legal" chunk
    assert!(sij[cheating_i][cheating_j] > CHUNK_MAX);

    let tau = tau_from_epoch(sys, epoch);
    let crsz = enc_chunks_cheating(&sij[..], &pks, &tau, &associated_data, sys, &mut rng);

    // still a valid ciphertext
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

    // account for overflow in chunk -> scalar conversions
    let mut overflow = 0;
    for idx in (0..=cheating_j).rev() {
        sij[cheating_i][idx] += overflow;
        overflow = sij[cheating_i][idx] >> 16;
        sij[cheating_i][idx] &= 0xffff;
    }

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), sij[i], "Message decrypted wrongly");
    }
}

#[test]
fn should_decrypt_correctly_for_epoch_0() {
    let sys = SysParam::global();
    let epoch = Epoch::from(0);
    let mut rng = test_rng();
    let associated_data = rng.gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

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
    let mut rng = test_rng();
    let associated_data = rng.gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

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
    let mut rng = test_rng();
    let associated_data = rng.gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

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
    let mut rng = test_rng();
    let associated_data = rng.gen::<[u8; 10]>();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, &mut rng);

    let tau = tau_from_epoch(sys, epoch);
    assert!(verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys).is_ok());

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
