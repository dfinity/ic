//! Tests for combined forward secure encryption and ZK proofs
#![allow(clippy::many_single_char_names)]

use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, G2Affine, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::{
    forward_secure::*, nizk_chunking::*, nizk_sharing::*,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

#[test]
fn potpourri() {
    let sys = SysParam::global();
    let rng = &mut reproducible_rng();
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 0u8, 2u8, 1u8];

    println!("generating key pair...");
    let (pk, mut dk) = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
    assert!(
        pk.verify(KEY_GEN_ASSOCIATED_DATA),
        "Forward secure public key failed validation"
    );
    for _i in 0..10 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }
    let epoch10 = Epoch::from(10);

    let associated_data = rng.r#gen::<[u8; 32]>();

    let mut keys = Vec::new();
    for i in 0..=3 {
        println!("generating key pair {i}...");
        keys.push(kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng));
    }
    let pks = keys
        .iter()
        .map(|key| key.0.public_key().clone())
        .collect::<Vec<_>>();

    let ptext = Scalar::batch_random(rng, keys.len());

    let ptext_chunks = ptext
        .iter()
        .map(PlaintextChunks::from_scalar)
        .collect::<Vec<_>>();

    let pk_and_chunks = pks
        .iter()
        .cloned()
        .zip(ptext_chunks.iter().cloned())
        .collect::<Vec<_>>();

    let (crsz, _toxic) = enc_chunks(&pk_and_chunks, epoch10, &associated_data, sys, rng);

    let dk = &mut keys[1].1;
    for _i in 0..3 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }

    verify_ciphertext_integrity(&crsz, epoch10, &associated_data, sys)
        .expect("ciphertext integrity check failed");

    let out = dec_chunks(dk, 1, &crsz, epoch10, &associated_data)
        .expect("It should be possible to decrypt");

    assert_eq!(out, ptext[1]);

    for _i in 0..8 {
        println!("upgrading private key...");
        dk.update(sys, rng);
    }
    // Should be impossible to decrypt now.
    let out = dec_chunks(dk, 1, &crsz, epoch10, &associated_data);
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
    let sys = SysParam::global();
    let rng = &mut reproducible_rng();
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[1u8, 9u8, 8u8, 4u8];

    let num_receivers = 3;
    let threshold = 2;
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let receiver_fs_keys: Vec<_> = (0..num_receivers)
        .map(|i| {
            println!("generating key pair {i}...");
            let key_pair = kgen(KEY_GEN_ASSOCIATED_DATA, sys, rng);
            println!("{:#?}", &key_pair.0);
            key_pair
        })
        .collect();
    let public_keys_with_zk: Vec<&PublicKeyWithPop> =
        receiver_fs_keys.iter().map(|key| &key.0).collect();
    // Suggestion: Make the types used by fs encryption and zk proofs consistent.
    // One takes refs, one takes values:
    let receiver_fs_public_keys: Vec<_> = public_keys_with_zk
        .iter()
        .map(|key| key.public_key().clone())
        .collect();

    let polynomial = Scalar::batch_random(rng, threshold);
    let polynomial_exp = g2.batch_mul(&polynomial);

    // Plaintext, unchunked:
    let plaintexts: Vec<Scalar> = (0..num_receivers)
        .map(|i| {
            let ibig = Scalar::from_usize(i + 1);
            let mut ipow = Scalar::one();
            let mut acc = Scalar::zero();
            for ak in &polynomial {
                acc += ak * &ipow;
                ipow *= &ibig;
            }
            acc
        })
        .collect();

    // Plaintext, chunked:
    let plaintext_chunks: Vec<PlaintextChunks> = plaintexts
        .iter()
        .map(PlaintextChunks::from_scalar)
        .collect();
    println!("Messages: {plaintext_chunks:#?}");

    let keys_and_chunks = receiver_fs_public_keys
        .iter()
        .cloned()
        .zip(plaintext_chunks.iter().cloned())
        .collect::<Vec<_>>();

    // Encrypt
    let associated_data = rng.r#gen::<[u8; 10]>();
    let (crsz, encryption_witness) =
        enc_chunks(&keys_and_chunks, epoch, &associated_data, sys, rng);

    // Check that decryption succeeds
    let dk = &receiver_fs_keys[1].1;
    let out = dec_chunks(dk, 1, &crsz, epoch, &associated_data);
    println!("decrypted: {out:?}");
    assert_eq!(out.unwrap(), plaintext_chunks[1].recombine_to_scalar(),);

    // chunking proof and verification
    {
        println!("Verifying chunking proof...");
        // Suggestion: Make this conversion in prove_chunking, so that the API types are
        // consistent.
        let big_plaintext_chunks: Vec<_> = plaintext_chunks
            .iter()
            .map(|chunks| chunks.chunks_as_scalars())
            .collect();

        let chunking_instance = ChunkingInstance::new(
            receiver_fs_public_keys.clone(),
            crsz.ciphertext_chunks().to_vec(),
            crsz.randomizers_r().clone(),
        );

        let chunking_witness =
            ChunkingWitness::new(encryption_witness.witness().clone(), big_plaintext_chunks);

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
        ///
        /// Combine a big endian array of group elements (first chunk is the
        /// most significant) into a single group element.
        fn g1_from_big_endian_chunks(terms: &[G1Affine]) -> G1Affine {
            let mut acc = G1Projective::identity();

            for term in terms {
                for _ in 0..16 {
                    acc = acc.double();
                }

                acc += term;
            }

            acc.to_affine()
        }

        /// Combine a big endian array of field elements (first chunk is the
        /// most significant) into a single field element.
        fn scalar_from_big_endian_chunks(terms: &[Scalar]) -> Scalar {
            let factor = Scalar::from_u64(1 << 16);

            let mut acc = Scalar::zero();
            for term in terms {
                acc *= &factor;
                acc += term;
            }

            acc
        }

        let combined_ciphertexts: Vec<G1Affine> = crsz
            .ciphertext_chunks()
            .iter()
            .map(|s| g1_from_big_endian_chunks(s))
            .collect();

        let combined_r = scalar_from_big_endian_chunks(encryption_witness.witness());
        let combined_r_exp = g1_from_big_endian_chunks(crsz.randomizers_r());
        let combined_plaintexts: Vec<Scalar> = plaintext_chunks
            .iter()
            .map(|receiver_chunks| receiver_chunks.recombine_to_scalar())
            .collect();

        // Check that the combination is correct:
        // ... for plaintexts:
        for (plaintext, reconstituted_plaintext) in plaintexts.iter().zip(&combined_plaintexts) {
            assert_eq!(
                plaintext, reconstituted_plaintext,
                "Reconstituted plaintext does not match"
            );
        }

        // ... for plaintexts:
        for ((ciphertext, plaintext), public_key) in combined_ciphertexts
            .iter()
            .zip(&plaintexts)
            .zip(&receiver_fs_public_keys)
        {
            let ciphertext_computed_directly =
                G1Projective::mul2(&public_key.into(), &combined_r, &g1.into(), plaintext)
                    .to_affine();
            assert_eq!(
                ciphertext_computed_directly, *ciphertext,
                "Reconstitued ciphertext doesn't match"
            );
        }

        let sharing_instance = SharingInstance::new(
            receiver_fs_public_keys,
            polynomial_exp,
            combined_r_exp,
            combined_ciphertexts,
        );
        let sharing_witness = SharingWitness::new(combined_r, combined_plaintexts);

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
