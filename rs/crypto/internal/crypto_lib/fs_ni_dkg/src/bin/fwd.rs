//! Demonstration of forward secure encryption

use ic_crypto_internal_fs_ni_dkg as dkg;

use dkg::forward_secure::*;
use dkg::utils::RAND_ChaCha20;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use std::vec::Vec;

fn main() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([42; 32]);

    let associated_data = &[1u8; 4];
    println!("generating key pair...");
    let (mut pk, mut dk) = kgen(associated_data, sys, rng);
    let v = pk.serialize();
    pk = PublicKeyWithPop::deserialize(&v);
    assert!(
        pk.verify(associated_data),
        "Forward secure public key failed validation"
    );
    println!("public key verified");
    let epoch10 = tau_from_epoch(sys, Epoch::from(10));
    for _i in 0..10 {
        println!("upgrading private key...");
        dk.update(sys, rng);
        let v = dk.serialize();
        dk = SecretKey::deserialize(&v);
    }
    /* Faster than the above loop:
    dk.update_to(&epoch10, sys, rng);
    let v = dk.serialize();
    dk = SecretKey::deserialize(&v);
    */

    let mut keys = Vec::new();
    for i in 0..4 {
        println!("generating key pair {}...", i);
        keys.push(kgen(associated_data, sys, rng));
    }
    let pks = keys.iter().map(|key| &key.0.key_value).collect();
    let sij: Vec<_> = vec![
        vec![27, 18, 28],
        vec![31415, 8192, 8224],
        vec![99, 999, 9999],
        vec![123, 456, 789],
    ];
    let associated_data = vec![1u8];
    let (crsz, _toxic) = enc_chunks(&sij, pks, &epoch10, &associated_data, sys, rng).unwrap();

    let dk = &mut keys[1].1;

    println!(
        "integrity check: {:?}",
        verify_ciphertext_integrity(&crsz, &epoch10, &associated_data, sys)
    );
    let out = dec_chunks(dk, 1, &crsz, &epoch10, &associated_data);
    println!("dec_chunks initially: {:?}", out);

    for _i in 0..3 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }

    let out = dec_chunks(dk, 1, &crsz, &epoch10, &associated_data);
    println!("dec_chunks after 3 upgrades: {:?}", out);

    for _i in 0..8 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }
    // Should be impossible to decrypt now.
    let out = dec_chunks(dk, 1, &crsz, &epoch10, &associated_data);
    println!("dec_chunks after 8 additional upgrades: {:?}", out);
}
