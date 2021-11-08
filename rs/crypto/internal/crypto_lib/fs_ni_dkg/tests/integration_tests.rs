#![allow(clippy::unwrap_used)]
//! Tests for combined forward secure encryption and ZK proofs
#![allow(clippy::many_single_char_names)]

use ic_crypto_internal_bls12381_serde_miracl::miracl_fr_to_bytes;
use ic_crypto_internal_fs_ni_dkg as dkg;

use dkg::forward_secure::*;
use dkg::nizk_chunking::*;
use dkg::nizk_sharing::*;
use dkg::utils::RAND_ChaCha20;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::rom;
use miracl_core::rand::RAND;

#[test]
fn potpourri() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([16; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 0u8, 2u8, 1u8];

    println!("generating key pair...");
    let (mut pk, mut dk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    let v = pk.serialize();
    pk = PublicKeyWithPop::deserialize(&v);
    assert!(
        pk.verify(KEY_GEN_ASSOCIATED_DATA),
        "Forward secure public key failed validation"
    );
    for _i in 0..10 {
        println!("upgrading private key...");
        dk.update(sys, rng);
        let v = dk.serialize();
        dk = SecretKey::deserialize(&v);
    }
    let epoch10 = Epoch::from(10);
    let tau10 = tau_from_epoch(sys, epoch10);

    let mut keys = Vec::new();
    for i in 0..3 {
        println!("generating key pair {}...", i);
        keys.push(kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng));
    }
    let pks = keys.iter().map(|key| &key.0.key_value).collect();
    let sij: Vec<_> = vec![
        vec![27, 18, 28],
        vec![31415, 8192, 8224],
        vec![99, 999, 9999],
        vec![CHUNK_MIN, CHUNK_MAX, CHUNK_MIN],
    ];
    let associated_data = [rng.getbyte(); 4];
    let (crsz, _toxic) = enc_chunks(&sij, pks, &tau10, &associated_data, sys, rng).unwrap();

    let dk = &mut keys[1].1;
    for _i in 0..3 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }

    verify_ciphertext_integrity(&crsz, &tau10, &associated_data, sys)
        .expect("ciphertext integrity check failed");

    let out = dec_chunks(dk, 1, &crsz, &tau10, &associated_data)
        .expect("It should be possible to decrypt");
    println!("decrypted: {:?}", out);
    let mut last3 = vec![0; 3];
    last3[0] = out[13];
    last3[1] = out[14];
    last3[2] = out[15];
    assert!(last3 == sij[1], "decrypt . encrypt == id");

    for _i in 0..8 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }
    // Should be impossible to decrypt now.
    let out = dec_chunks(dk, 1, &crsz, &tau10, &associated_data);
    match out {
        Err(DecErr::ExpiredKey) => (),
        _ => panic!("old ciphertexts should be lost forever"),
    }
}

/// Tests that the fs proofs of an encrypted chunk validate.
///
/// # Arguments
/// * `epoch` - the epoch for which the data is encrypted.
///
/// Note: This can be extended further by:
/// * Varying the secret key epoch; this is always zero in this test.
/// * Varying the plaintexts more; here we have only fairly noddy variation.
fn encrypted_chunks_should_validate(epoch: Epoch) {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([88; 32]);
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[1u8, 9u8, 8u8, 4u8];

    let num_receivers = 3;
    let threshold = 2;
    let g1 = ECP::generator();
    let g2 = ECP2::generator();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);

    let receiver_fs_keys: Vec<_> = (0u8..num_receivers)
        .map(|i| {
            println!("generating key pair {}...", i);
            rng.seed(32, &[0x10 | i; 32]);
            let key_pair = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
            println!("{:#?}", &key_pair.0);
            key_pair
        })
        .collect();
    let public_keys_with_zk: Vec<&PublicKeyWithPop> =
        receiver_fs_keys.iter().map(|key| &key.0).collect();
    // Suggestion: Make the types used by fs encryption and zk proofs consistent.
    // One takes refs, one takes values:
    let receiver_fs_public_key_refs: Vec<&ECP> = public_keys_with_zk
        .iter()
        .map(|key| &key.key_value)
        .collect();
    let receiver_fs_public_keys: Vec<ECP> = public_keys_with_zk
        .iter()
        .map(|key| key.key_value.clone())
        .collect();

    let polynomial: Vec<BIG> = (0..threshold)
        .map(|_| BIG::randomnum(&spec_p, rng))
        .collect();
    let polynomial_exp: Vec<ECP2> = polynomial.iter().map(|term| g2.mul(term)).collect();

    // Plaintext, unchunked:
    // Note: This is never actually mutated.
    let mut plaintexts: Vec<BIG> = (1..)
        .zip(&receiver_fs_keys)
        .map(|(i, _)| {
            let ibig = BIG::new_int(i);
            let mut ipow = BIG::new_int(1);
            let mut acc = BIG::new_int(0);
            for ak in &polynomial {
                acc = BIG::modadd(&acc, &BIG::modmul(ak, &ipow, &spec_p), &spec_p);
                ipow = BIG::modmul(&ipow, &ibig, &spec_p);
            }
            acc
        })
        .collect();

    // Plaintext, chunked:
    // Note: The plaintext is not actually mutated.  The mutation is just required
    // by the API.
    let plaintext_chunks: Vec<Vec<isize>> = plaintexts
        .iter_mut()
        .map(|plaintext| {
            let mut bytes = miracl_fr_to_bytes(plaintext).0;
            bytes.reverse(); // Make little endian.
            let chunks = bytes[..].chunks(CHUNK_BYTES); // The last, most significant, chunk may be partial.
            chunks
                .map(|chunk| {
                    chunk
                        .iter()
                        .rev()
                        .fold(0, |acc, byte| (acc << 8) + (*byte as isize))
                })
                .rev()
                .collect() // Convert to big endian ints
        })
        .collect();
    println!("Messages: {:#?}", plaintext_chunks);

    // Encrypt
    let tau = tau_from_epoch(sys, epoch);
    let encryption_seed = [105; 32];
    rng.seed(32, &encryption_seed);
    let associated_data = [rng.getbyte(); 4];
    let (crsz, toxic_waste) = enc_chunks(
        &plaintext_chunks[..],
        receiver_fs_public_key_refs,
        &tau,
        &associated_data,
        sys,
        rng,
    )
    .expect("Encryption failed");
    println!(
        "Ciphertext:\n  Seed: {:?}\n  {:#?}",
        &encryption_seed, &crsz
    );

    // Check that decryption succeeds
    let dk = &receiver_fs_keys[1].1;
    let out = dec_chunks(dk, 1, &crsz, &tau, &associated_data);
    println!("decrypted: {:?}", out);
    assert!(
        out.unwrap() == plaintext_chunks[1],
        "decrypt . encrypt == id"
    );

    // chunking proof and verification
    {
        println!("Verifying chunking proof...");
        // Suggestion: Make this conversion in prove_chunking, so that the API types are
        // consistent.
        let big_plaintext_chunks: Vec<Vec<BIG>> = plaintext_chunks
            .iter()
            .map(|chunks| chunks.iter().copied().map(BIG::new_int).collect())
            .collect();

        let chunking_instance = ChunkingInstance {
            g1_gen: ECP::generator(),
            public_keys: receiver_fs_public_keys.clone(),
            ciphertext_chunks: crsz.cc.clone(),
            randomizers_r: crsz.rr.clone(),
        };

        let chunking_witness = ChunkingWitness {
            scalars_r: toxic_waste.spec_r.clone(),
            scalars_s: big_plaintext_chunks,
        };

        let nizk_chunking = prove_chunking(&chunking_instance, &chunking_witness, rng);

        assert_eq!(
            Ok(()),
            verify_chunking(&chunking_instance, &nizk_chunking),
            "verify_chunking verifies NIZK proof"
        );
    }

    // nizk sharing
    {
        println!("Verifying sharing proof...");
        /// Context: Most of this code converts the data used for the fs
        /// encryption to the form needed by the zk crypto. Suggestion:
        /// Put the conversion code in the library.

        /// Combine a big endian array of group elements (first chunk is the
        /// most significant) into a single group element.
        #[allow(clippy::ptr_arg)] // We have no use case for other types.
        fn ecp_from_big_endian_chunks(data: &Vec<ECP>) -> ECP {
            // Note: Relies on ECP::new() being zero == point at infinity.
            data.iter().fold(ECP::new(), |acc, term| {
                let mut acc = acc.mul(&BIG::new_int(CHUNK_SIZE));
                acc.add(term);
                acc.affine(); // Needed to avoid getting an overflow error.
                acc
            })
        }
        /// Combine a big endian array of field elements (first chunk is the
        /// most significant) into a single field element.
        ///
        /// Note: The field elements stored as Miracl BIG types, so we
        /// have to do the modular reduction ourselves.  As the array length is
        /// unbounded and BIG has finite size we cannot do the reduction safely
        /// at the end, so it is done on every iteration.  This is not cheap.
        #[allow(clippy::ptr_arg)] // We have no use case for other types.
        fn big_from_big_endian_chunks(data: &Vec<BIG>) -> BIG {
            // Note: Relies on BIG::new() being zero.
            data.iter().fold(BIG::new(), |mut acc, term| {
                acc.shl(CHUNK_BYTES << 3);
                acc.add(term);
                acc.rmod(&BIG::new_ints(&rom::CURVE_ORDER)); // Needed to avoid getting a buffer overflow.
                acc
            })
        }

        let combined_ciphertexts: Vec<ECP> =
            crsz.cc.iter().map(ecp_from_big_endian_chunks).collect();
        let combined_r: BIG = big_from_big_endian_chunks(&toxic_waste.spec_r);
        let combined_r_exp = ecp_from_big_endian_chunks(&crsz.rr);
        let combined_plaintexts: Vec<BIG> = plaintext_chunks
            .iter()
            .map(|receiver_chunks| {
                big_from_big_endian_chunks(
                    &receiver_chunks.iter().copied().map(BIG::new_int).collect(),
                )
            })
            .collect();

        // Check that the combination is correct:
        // ... for plaintexts:
        for (plaintext, reconstituted_plaintext) in plaintexts.iter().zip(&combined_plaintexts) {
            let mut diff = BIG::new_big(plaintext);
            diff.sub(reconstituted_plaintext);
            diff.rmod(&spec_p);
            assert!(diff.iszilch(), "Reconstituted plaintext does not match");
        }

        // ... for plaintexts:
        for ((ciphertext, plaintext), public_key) in combined_ciphertexts
            .iter()
            .zip(&plaintexts)
            .zip(&receiver_fs_public_keys)
        {
            let mut ciphertext_computed_directly: ECP =
                public_key.mul2(&combined_r, &g1, plaintext);
            ciphertext_computed_directly.affine();
            let mut ciphertext_copy = ECP::new();
            ciphertext_copy.copy(ciphertext);
            ciphertext_copy.affine();
            assert!(
                ciphertext_computed_directly.equals(&ciphertext_copy),
                "Reconstitued ciphertext doesn't match"
            );
        }

        let sharing_instance = SharingInstance {
            g1_gen: ECP::generator(),
            g2_gen: ECP2::generator(),
            public_keys: receiver_fs_public_keys,
            public_coefficients: polynomial_exp,
            combined_randomizer: combined_r_exp,
            combined_ciphertexts,
        };
        let sharing_witness = SharingWitness {
            scalar_r: combined_r,
            scalars_s: combined_plaintexts,
        };

        let sharing_proof = prove_sharing(&sharing_instance, &sharing_witness, rng);

        assert_eq!(
            Ok(()),
            verify_sharing(&sharing_instance, &sharing_proof),
            "verify_sharing verifies NIZK proof"
        );
    };
}

#[test]
fn encrypted_chunks_should_validate_00() {
    encrypted_chunks_should_validate(Epoch::from(0))
}

#[test]
fn encrypted_chunks_should_validate_01() {
    encrypted_chunks_should_validate(Epoch::from(1))
}

// TODO (CRP-831): Add a test that incorrect encryptions do not validate.
