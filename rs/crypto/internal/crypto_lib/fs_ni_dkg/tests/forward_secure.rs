#![allow(clippy::unwrap_used)]
//! Tests for combined forward secure encryption and ZK proofs

use dkg::forward_secure::*;
use dkg::utils::RAND_ChaCha20;
use ic_crypto_internal_fs_ni_dkg as dkg;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use miracl_core::rand::RAND;

#[test]
fn fs_keys_should_be_valid() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([99; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[3u8, 0u8, 0u8, 0u8];

    let (pk, _dk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    assert!(
        pk.verify(KEY_GEN_ASSOCIATED_DATA),
        "Generated public key should be valid"
    );
}

#[test]
fn encrypt_decrypt_single() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([45; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 5u8, 0u8, 4u8];

    let (mut pk, mut dk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    let v = pk.serialize();
    pk = PublicKeyWithPop::deserialize(&v);
    assert!(
        pk.verify(KEY_GEN_ASSOCIATED_DATA),
        "Forward secure public key failed validation"
    );
    let epoch0 = vec![Bit::Zero; 5];
    let message = 123;
    let ct = enc_single(&pk.key_value, message, &epoch0, rng, sys);
    let plain = dec_single(&mut dk, &ct, sys);
    assert!(plain == message, "plaintext mismatch");
}

fn keys_and_ciphertext_for(
    epoch: Epoch,
    associated_data: &[u8],
    rng: &mut impl RAND,
) -> (Vec<(PublicKeyWithPop, SecretKey)>, Vec<Vec<isize>>, CRSZ) {
    let sys = &mk_sys_params();
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[0u8, 1u8, 0u8, 6u8];

    let mut keys = Vec::new();
    for i in 0u8..3 {
        println!("generating key pair {}...", i);
        rng.seed(32, &[0x10 | i; 32]);
        let key_pair = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
        println!("{:#?}", &key_pair.0);
        keys.push(key_pair);
    }
    let public_keys_with_zk: Vec<_> = keys.iter().map(|key| &key.0).collect();
    let pks = public_keys_with_zk
        .iter()
        .map(|key| &key.key_value)
        .collect();

    let sij: Vec<_> = (0..keys.len())
        .map(|receiver_index| {
            let chunk =
                (receiver_index | (receiver_index << 8) | 0x0FF00FF0) % (CHUNK_SIZE as usize);
            vec![chunk as isize; NUM_CHUNKS]
        })
        .collect();
    println!("Messages: {:#?}", sij);

    let tau = tau_from_epoch(sys, epoch);
    let (crsz, _toxic) =
        enc_chunks(&sij[..], pks, &tau, associated_data, sys, rng).expect("Encryption failed");
    (keys, sij, crsz)
}

#[test]
fn integrity_check_should_return_error_on_wrong_associated_data() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([82; 32]);
    let epoch = Epoch::from(0);
    let associated_data: Vec<u8> = vec![3u8; 12];
    let wrong_associated_data: Vec<u8> = vec![1u8; 7];

    let (_keys, _message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);
    let tau = tau_from_epoch(sys, epoch);

    assert_eq!(
        Err(()),
        verify_ciphertext_integrity(&crsz, &tau, &wrong_associated_data, sys)
    );
}

#[test]
fn should_encrypt_with_empty_associated_data() {
    let sys = &mk_sys_params();
    let epoch = Epoch::from(0);
    let rng = &mut RAND_ChaCha20::new([50; 32]);
    let associated_data: Vec<u8> = Vec::new();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let out = dec_chunks(&keys[i].1, i, &crsz, &tau, &associated_data, sys);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

#[test]
fn should_decrypt_correctly_for_epoch_0() {
    let sys = &mk_sys_params();
    let epoch = Epoch::from(0);
    let rng = &mut RAND_ChaCha20::new([12; 32]);
    let associated_data: Vec<u8> = (0..10).map(|_| rng.getbyte()).collect();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data, sys);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_1() {
    let sys = &mk_sys_params();
    let epoch = Epoch::from(1);
    let rng = &mut RAND_ChaCha20::new([24; 32]);
    let associated_data: Vec<u8> = (0..10).map(|_| rng.getbyte()).collect();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data, sys);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_5() {
    let sys = &mk_sys_params();
    let epoch = Epoch::from(5);
    let rng = &mut RAND_ChaCha20::new([36; 32]);
    let associated_data: Vec<u8> = (0..10).map(|_| rng.getbyte()).collect();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data, sys);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}
#[test]
fn should_decrypt_correctly_for_epoch_10() {
    let sys = &mk_sys_params();
    let epoch = Epoch::from(10);
    let rng = &mut RAND_ChaCha20::new([48; 32]);
    let associated_data: Vec<u8> = (0..10).map(|_| rng.getbyte()).collect();
    let (keys, message, crsz) = keys_and_ciphertext_for(epoch, &associated_data, rng);

    let tau = tau_from_epoch(sys, epoch);
    assert_eq!(
        Ok(()),
        verify_ciphertext_integrity(&crsz, &tau, &associated_data, sys)
    );

    for i in 0..keys.len() {
        let secret_key = &keys[i].1;
        let out = dec_chunks(secret_key, i, &crsz, &tau, &associated_data, sys);
        assert_eq!(out.unwrap(), message[i], "Message decrypted wrongly");
    }
}

// Returns a random element of FP12 of order CURVE_ORDER (i.e. call fexp()
// before returning).
// Our tests call FP12::pow(), which only works on elements of order
// CURVE_ORDER.
fn fp12_rand(rng: &mut impl RAND) -> miracl_core::bls12381::fp12::FP12 {
    use miracl_core::bls12381::fp12::FP12;
    use miracl_core::bls12381::fp4::FP4;
    use miracl_core::bls12381::pair;
    pair::fexp(&FP12::new_fp4s(
        &FP4::new_rand(rng),
        &FP4::new_rand(rng),
        &FP4::new_rand(rng),
    ))
}

#[test]
fn baby_giant_1000() {
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    for x in 0..1000 {
        let base = fp12_rand(rng);
        let tgt = base.pow(&BIG::new_int(x));
        assert!(
            baby_giant(&tgt, &base, -24, 1024).unwrap() == x,
            "baby-giant finds x"
        );
    }
}

#[test]
fn baby_giant_negative() {
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    for x in 0..1000 {
        let base = fp12_rand(rng);
        let mut tgt = base.pow(&BIG::new_int(x));
        tgt.inverse();
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
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let base = fp12_rand(rng);
    let x = (1 << 39) + 123;
    let tgt = base.pow(&BIG::new_int(x));
    assert!(
        baby_giant(&tgt, &base, -(1 << 10), 1 << 40).unwrap() == x,
        "baby-giant finds x"
    );
}

// Find the log for a cheater who exceeds the bounds by a little.
#[test]
fn slightly_dishonest_dlog() {
    use miracl_core::bls12381::big::BIG;
    use miracl_core::bls12381::ecp::ECP;
    use miracl_core::bls12381::ecp2::ECP2;
    use miracl_core::bls12381::pair;
    use miracl_core::bls12381::rom;

    let base = pair::fexp(&pair::ate(&ECP2::generator(), &ECP::generator()));
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    // Last I checked:
    //   E = 128
    //   Z = 31960108800 * m * n
    // So searching for Delta < 10 with m = n = 1 should be tolerable.
    let mut answer = BIG::new_int(8);
    answer.invmodp(&spec_r);
    answer = BIG::modmul(&answer, &BIG::new_int(12345678), &spec_r);
    answer.norm();
    let soln = solve_cheater_log(1, 1, &base.pow(&answer)).unwrap();
    assert!(BIG::comp(&soln, &answer) == 0);

    // Check negative numbers also work.
    let mut answer = BIG::new_int(5);
    answer.invmodp(&spec_r);
    answer = BIG::modmul(&answer, &negative_safe_new_int(-12345678), &spec_r);
    answer.norm();
    let soln = solve_cheater_log(1, 1, &base.pow(&answer)).unwrap();
    assert!(BIG::comp(&soln, &answer) == 0);
}

#[test]
fn deserialize_invalid_point() {
    use miracl_core::bls12381::ecp::ECP;
    let g1 = ECP::generator();
    let mut buf = [0; 1 + 2 * 48];
    g1.tobytes(&mut buf, false);
    for (cell, i) in buf[10..20].iter_mut().zip(10..) {
        *cell = i;
    }
    let y = ECP::frombytes(&buf);
    assert!(y.is_infinity(), "invalid point deserializes as infinity");
}
