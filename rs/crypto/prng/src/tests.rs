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
    // Because the crypto hash domain of random beacons is hardcoded and cannot be
    // controlled from within a test, the only way to ensure that the crypto
    // hash domain of the random beacon is incorporated when generating the
    // randomness is to test the actual expected implementation.

    let rb = fake_random_beacon(1);
    for purpose in RandomnessPurpose::iter() {
        // Replicate the implementation: hash the random beacon, create a seed, derive for purpose
        let hash = ic_types::crypto::crypto_hash(&rb);
        let seed = ic_crypto_internal_seed::Seed::from_bytes(&hash.get().0);
        let seed_for_purpose = seed.derive(&purpose.domain_separator());
        let mut csprng = Csprng::from_seed(seed_for_purpose);

        assert_eq!(
            Csprng::from_random_beacon_and_purpose(&rb, &purpose).next_u32(),
            csprng.next_u32()
        )
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
    let seed = ic_types::Randomness::new([99; 32]);

    let mut rng_0 = Csprng::from_randomness_and_purpose(&seed, &ExecutionThread(0));
    let mut rng_max = Csprng::from_randomness_and_purpose(&seed, &ExecutionThread(u32::MAX));
    let mut rng_1 = Csprng::from_randomness_and_purpose(&seed, &ExecutionThread(1));

    let val_0 = rng_0.next_u32();
    let val_max = rng_max.next_u32();
    let val_1 = rng_1.next_u32();

    // All should be different
    assert_ne!(val_0, val_max);
    assert_ne!(val_0, val_1);
    assert_ne!(val_max, val_1);
}

#[test]
fn seed_from_random_beacon_should_match_manual_extraction_of_randomness() {
    let random_beacon = fake_random_beacon(42);

    // Manual randomness extraction from random_beacon
    let randomness = randomness_from_crypto_hashable(&random_beacon);

    // Both CSPRNG should produce the same output
    for purpose in RandomnessPurpose::iter() {
        let mut rng_direct = Csprng::from_random_beacon_and_purpose(&random_beacon, &purpose);
        let mut rng_manual = Csprng::from_randomness_and_purpose(&randomness, &purpose);

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
