use super::super::api as tsig;
use super::super::crypto;
use super::super::test_utils::select_n;
use super::super::types::{
    CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, SecretKeyBytes,
};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::NumberOfNodes;
use proptest::prelude::*;
use rand::Rng;

mod util {
    use super::super::super::api as tsig;
    use super::super::super::types::SecretKeyBytes;
    use ic_crypto_internal_seed::Seed;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
    use ic_types::NumberOfNodes;
    use ic_types::crypto::CryptoResult;

    /// Shim for tests that use the old API that generated keys for all
    /// participants. The new API generates only select keys.
    pub fn generate_threshold_key(
        seed: Seed,
        threshold: NumberOfNodes,
        group_size: NumberOfNodes,
    ) -> CryptoResult<(PublicCoefficientsBytes, Vec<SecretKeyBytes>)> {
        tsig::generate_threshold_key(seed, threshold, group_size).map(
            |(public_coefficients, selected_keys)| {
                let all_keys: Vec<SecretKeyBytes> = selected_keys.into_iter().collect();
                (public_coefficients, all_keys)
            },
        )
    }
}

/// Individual signatures should be verifiable
fn test_individual_signature_verifies(
    seed: Seed,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let (public_coefficients, secret_keys) =
        util::generate_threshold_key(seed, threshold, group_size).expect("Failed to deal");
    for (index, secret_key) in (0..).zip(secret_keys) {
        let signature = tsig::sign_message(message, &secret_key).expect("Failed to sign");
        let public_key = tsig::individual_public_key(&public_coefficients, index)
            .expect("failed to generate public key");
        assert!(tsig::verify_individual_signature(message, signature, public_key).is_ok());
    }
}

fn test_combined_signature_verifies(
    seed: Seed,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let rng = &mut seed.into_rng();
    let (public_coefficients, secret_keys) =
        util::generate_threshold_key(Seed::from_rng(rng), threshold, group_size)
            .expect("Failed to deal");
    let signatures: Vec<IndividualSignatureBytes> = secret_keys
        .iter()
        .map(|secret_key| tsig::sign_message(message, secret_key).expect("Failed to sign"))
        .collect();
    let signatures = select_n(Seed::from_rng(rng), threshold, &signatures);
    let signature =
        tsig::combine_signatures(&signatures, threshold).expect("Failed to combine signatures");
    let public_key =
        tsig::combined_public_key(&public_coefficients).expect("Failed to get combined public key");
    assert_eq!(
        tsig::verify_combined_signature(message, signature, public_key),
        Ok(())
    );

    // test the functionality of the cached version:

    let initial_stats = crate::cache::SignatureCache::global().cache_statistics();

    let entry =
        crate::cache::SignatureCacheEntry::new(public_key.as_bytes(), &signature.0, message);

    assert!(!crate::cache::SignatureCache::global().contains(&entry));

    // test with cached version twice (once for miss case, once for hit case)
    assert_eq!(
        tsig::verify_combined_signature_with_cache(message, signature, public_key),
        Ok(())
    );

    // check that the entry is now in the cache:
    assert!(crate::cache::SignatureCache::global().contains(&entry));

    // there is now at least one additional miss in the cache stats:
    assert!(
        crate::cache::SignatureCache::global()
            .cache_statistics()
            .misses
            > initial_stats.misses
    );

    let initial_stats = crate::cache::SignatureCache::global().cache_statistics();

    assert_eq!(
        tsig::verify_combined_signature_with_cache(message, signature, public_key),
        Ok(())
    );

    // there is now at least one additional hit in the cache stats:
    assert!(
        crate::cache::SignatureCache::global()
            .cache_statistics()
            .hits
            > initial_stats.hits
    );
}

/// Assertion:  Computing with the external interface is equivalent to working
/// with the core library.
fn test_threshold_sig_api_and_core_match(
    seed: Seed,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let rng = &mut seed.into_rng();
    let seed_bytes = rng.r#gen::<[u8; 32]>();
    let (core_public_coefficients, core_secret_keys) = crypto::tests::util::generate_threshold_key(
        Seed::from_bytes(&seed_bytes),
        threshold,
        group_size,
    )
    .expect("Core failed to deal");
    let (tsig_public_coefficients, tsig_secret_keys) =
        util::generate_threshold_key(Seed::from_bytes(&seed_bytes), threshold, group_size)
            .expect("Threshold sig failed to deal");
    assert_eq!(
        PublicCoefficientsBytes::from(&core_public_coefficients),
        tsig_public_coefficients
    );
    assert_eq!(
        core_secret_keys
            .iter()
            .map(SecretKeyBytes::from)
            .collect::<Vec<_>>(),
        tsig_secret_keys
    );

    let core_signatures: Vec<IndividualSignature> = core_secret_keys
        .iter()
        .map(|secret_key| crypto::sign_message(message, secret_key))
        .collect();
    let tsig_signatures: Vec<IndividualSignatureBytes> = tsig_secret_keys
        .iter()
        .map(|secret_key| {
            tsig::sign_message(message, secret_key).expect("Threshold sig failed to sign")
        })
        .collect();
    assert_eq!(
        core_signatures
            .iter()
            .map(IndividualSignatureBytes::from)
            .collect::<Vec<_>>(),
        tsig_signatures
    );

    let core_signature_selection =
        select_n(Seed::from_bytes(&seed_bytes), threshold, &core_signatures);
    let tsig_signature_selection =
        select_n(Seed::from_bytes(&seed_bytes), threshold, &tsig_signatures);
    assert_eq!(
        core_signature_selection
            .iter()
            .map(|option| option
                .clone()
                .map(|signature| IndividualSignatureBytes::from(&signature)))
            .collect::<Vec<_>>(),
        tsig_signature_selection
    );

    let core_signature = crypto::combine_signatures(&core_signature_selection, threshold)
        .expect("Core failed to combine signatures");
    let tsig_signature = tsig::combine_signatures(&tsig_signature_selection, threshold)
        .expect("Threshold sig failed to combine signatures");
    assert_eq!(
        CombinedSignatureBytes::from(&core_signature),
        tsig_signature
    );

    let core_public_key = crypto::combined_public_key(&core_public_coefficients);
    let tsig_public_key = tsig::combined_public_key(&tsig_public_coefficients)
        .expect("Threshold sig failed to get combined public key");
    assert_eq!(
        PublicKeyBytes::from(core_public_key.clone()),
        tsig_public_key
    );

    assert_eq!(
        crypto::verify_combined_sig(message, &core_signature, &core_public_key),
        Ok(())
    );
    assert_eq!(
        tsig::verify_combined_signature(message, tsig_signature, tsig_public_key),
        Ok(())
    );

    // test cached version twice, one for the miss case and the second for the hit case
    assert_eq!(
        tsig::verify_combined_signature_with_cache(message, tsig_signature, tsig_public_key),
        Ok(())
    );
    assert_eq!(
        tsig::verify_combined_signature_with_cache(message, tsig_signature, tsig_public_key),
        Ok(())
    );
}

#[test]
fn should_invalid_threshold_signatures_not_be_cached() {
    use crate::cache::*;

    let rng = &mut reproducible_rng();

    for _ in 0..10000 {
        let mut pk = [0u8; 96];
        let mut sig = [0u8; 48];
        let mut msg = [0u8; 32];

        rng.fill_bytes(&mut pk);
        rng.fill_bytes(&mut sig);
        rng.fill_bytes(&mut msg);

        let entry = SignatureCacheEntry::new(&pk, &sig, &msg);

        // not found:
        assert!(!SignatureCache::global().contains(&entry));

        let pk = PublicKeyBytes(pk);
        let sig = CombinedSignatureBytes(sig);

        let initial_stats = SignatureCache::global().cache_statistics();

        assert!(tsig::verify_combined_signature_with_cache(&msg, sig, pk).is_err());

        // the invalid signature is still not included in the cache
        assert!(!SignatureCache::global().contains(&entry));

        assert!(SignatureCache::global().cache_statistics().misses > initial_stats.misses);
    }
}

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        #[test]
        fn individual_signature_verifies(seed: [u8;32], threshold in 1_u32..20, redundancy in 0_u32..20, message: Vec<u8>) {
            test_individual_signature_verifies(Seed::from_bytes(&seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
        #[test]
        fn combined_signature_verifies(seed: [u8;32], threshold in 1_u32..20, redundancy in 0_u32..20, message: Vec<u8>) {
            test_combined_signature_verifies(Seed::from_bytes(&seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
        #[test]
        fn threshold_sig_api_and_core_match(seed: [u8;32], threshold in 1_u32..10, redundancy in 0_u32..10, message: Vec<u8>) {
            test_threshold_sig_api_and_core_match(Seed::from_bytes(&seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
}
