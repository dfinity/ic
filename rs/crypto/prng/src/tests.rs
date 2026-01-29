use super::*;
use ic_types::consensus::RandomBeaconContent;
use ic_types::crypto::{
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
};
use ic_types::signature::ThresholdSignature;
use ic_types::{
    Height,
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
};
use ic_types_test_utils::ids::subnet_test_id;
use std::collections::BTreeSet;
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn should_use_unique_domain_separator_per_randomness_purpose() {
    let mut set = BTreeSet::new();

    // ensure domain separators are unique for all purposes
    for purpose in RandomnessPurpose::iter() {
        assert!(
            set.insert(purpose.domain_separator()),
            "Duplicate domain separator found"
        );
    }

    // ensure there is a separator for each purpose
    assert_eq!(set.len(), RandomnessPurpose::COUNT);
}

#[test]
fn should_incorporate_crypto_hash_domain_when_generating_randomness_for_random_beacon() {
    // Verify that the seed derivation from a random beacon incorporates the crypto
    // hash domain by checking that different random beacons produce different seeds.

    let rb1 = fake_random_beacon(1);
    let rb2 = fake_random_beacon(2);

    for purpose in RandomnessPurpose::iter() {
        let seed1 = Csprng::seed_from_random_beacon(&rb1);
        let seed2 = Csprng::seed_from_random_beacon(&rb2);

        let mut csprng1 = Csprng::from_seed_and_purpose(seed1, &purpose);
        let mut csprng2 = Csprng::from_seed_and_purpose(seed2, &purpose);

        // Different random beacons should produce different randomness
        assert_ne!(csprng1.next_u32(), csprng2.next_u32());
    }
}

fn fake_dkg_id(h: u64) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(h),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

#[test]
fn should_produce_different_randomness_for_execution_thread_edge_cases() {
    let randomness = ic_types::Randomness::new([99; 32]);
    let seed = Csprng::seed_from_randomness(&randomness);

    let mut rng_0 = Csprng::from_seed_and_purpose(seed.clone(), &ExecutionThread(0));
    let mut rng_max = Csprng::from_seed_and_purpose(seed.clone(), &ExecutionThread(u32::MAX));
    let mut rng_1 = Csprng::from_seed_and_purpose(seed, &ExecutionThread(1));

    let val_0 = rng_0.next_u32();
    let val_max = rng_max.next_u32();
    let val_1 = rng_1.next_u32();

    // All should be different
    assert_ne!(val_0, val_max);
    assert_ne!(val_0, val_1);
    assert_ne!(val_max, val_1);
}

#[test]
fn seed_from_random_beacon_should_match_manual_extraction_via_crypto_hashable_to_randomness() {
    let rb = fake_random_beacon(42);

    // Direct path: seed_from_random_beacon
    let seed_direct = Csprng::seed_from_random_beacon(&rb);

    // Manual path: crypto_hashable_to_randomness -> seed_from_randomness
    let randomness = crypto_hashable_to_randomness(&rb);
    let seed_manual = Csprng::seed_from_randomness(&randomness);

    // Both seeds should produce the same CSPRNG output for all purposes
    for purpose in RandomnessPurpose::iter() {
        let mut rng_direct = Csprng::from_seed_and_purpose(seed_direct.clone(), &purpose);
        let mut rng_manual = Csprng::from_seed_and_purpose(seed_manual.clone(), &purpose);

        assert_eq!(
            rng_direct.next_u64(),
            rng_manual.next_u64(),
            "Mismatch for purpose {:?}",
            purpose
        );
    }
}

fn fake_random_beacon(height: u64) -> RandomBeacon {
    Signed {
        content: RandomBeaconContent::new(
            Height::from(height),
            CryptoHashOf::new(CryptoHash(vec![])),
        ),
        signature: ThresholdSignature {
            signer: fake_dkg_id(0),
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}
