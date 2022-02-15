use super::*;
use ic_interfaces::crypto::CryptoHashDomain;
use ic_test_utilities::types::ids::subnet_test_id;
use ic_types::consensus::{RandomBeaconContent, RandomTapeContent};
use ic_types::crypto::{
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
};
use ic_types::signature::ThresholdSignature;
use ic_types::{
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
    Height,
};
use std::collections::BTreeSet;
use std::hash::Hash;
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn should_produce_deterministic_randomness() {
    let mut rng = Csprng::from_seed([42; 32]);

    assert_eq!(rng.next_u32(), 1_176_443_288);
    assert_eq!(rng.next_u64(), 10_895_988_999_873_266_661);

    let mut buffer = [0; 32];
    rng.fill_bytes(&mut buffer);
    assert_eq!(
        buffer,
        [
            136, 3, 105, 122, 94, 58, 182, 27, 30, 137, 81, 212, 254, 154, 230, 123, 171, 97, 74,
            95, 123, 252, 253, 117, 68, 177, 7, 141, 218, 57, 124, 239
        ]
    );
}

#[test]
fn should_offer_methods_of_rng_trait() {
    use rand::Rng;

    let mut rng = Csprng::from_seed([42; 32]);

    assert_eq!(rng.gen::<u32>(), 1_176_443_288);
}

#[test]
fn should_use_unique_separator_byte_per_randomness_purpose() {
    let mut set = BTreeSet::new();

    // ensure separator bytes are unique
    assert!(set.insert(COMMITTEE_SAMPLING_SEPARATOR_BYTE));
    assert!(set.insert(BLOCKMAKER_RANKING_SEPARATOR_BYTE));
    assert!(set.insert(DKG_COMMITTEE_SAMPLING_SEPARATOR_BYTE));
    assert!(set.insert(EXECUTION_THREAD_SEPARATOR_BYTE));

    // ensure there is a separator for each purpose
    assert_eq!(set.len(), RandomnessPurpose::COUNT);
}

#[test]
fn should_generate_purpose_specific_randomness_for_random_beacon() {
    let rb = random_beacon();

    let mut rng_cs = Csprng::from_random_beacon_and_purpose(&rb, &CommitteeSampling);
    let mut rng_br = Csprng::from_random_beacon_and_purpose(&rb, &BlockmakerRanking);
    let mut rng_ds = Csprng::from_random_beacon_and_purpose(&rb, &DkgCommitteeSampling);
    let mut rng_et = Csprng::from_random_beacon_and_purpose(&rb, &ExecutionThread(0));

    let mut set = BTreeSet::new();
    assert!(set.insert(rng_cs.next_u32()));
    assert!(set.insert(rng_br.next_u32()));
    assert!(set.insert(rng_ds.next_u32()));
    assert!(set.insert(rng_et.next_u32()));

    // ensure _all_ purposes are compared (i.e., no purpose was forgotten)
    assert_eq!(set.len(), RandomnessPurpose::COUNT);
}

#[test]
fn should_generate_purpose_specific_randomness_for_randomness_seed() {
    let seed = seed();

    let mut rng_cs = Csprng::from_seed_and_purpose(&seed, &CommitteeSampling);
    let mut rng_br = Csprng::from_seed_and_purpose(&seed, &BlockmakerRanking);
    let mut rng_ds = Csprng::from_seed_and_purpose(&seed, &DkgCommitteeSampling);
    let mut rng_et = Csprng::from_seed_and_purpose(&seed, &ExecutionThread(0));

    let mut set = BTreeSet::new();
    assert!(set.insert(rng_cs.next_u32()));
    assert!(set.insert(rng_br.next_u32()));
    assert!(set.insert(rng_ds.next_u32()));
    assert!(set.insert(rng_et.next_u32()));

    // ensure _all_ purposes are compared (i.e., no purpose was forgotten)
    assert_eq!(set.len(), RandomnessPurpose::COUNT);
}

#[test]
fn should_produce_different_randomness_for_same_purpose_for_different_random_beacons() {
    let (rb1, rb2) = (random_beacon(), random_beacon_2());
    assert_ne!(rb1, rb2);
    let purpose = CommitteeSampling;

    let mut csprng1 = Csprng::from_random_beacon_and_purpose(&rb1, &purpose);
    let mut csprng2 = Csprng::from_random_beacon_and_purpose(&rb2, &purpose);

    assert_ne!(csprng1.next_u32(), csprng2.next_u32());
}

#[test]
fn should_produce_different_randomness_for_same_purpose_for_different_randomness_seeds() {
    let (s1, s2) = (seed(), seed_2());
    assert_ne!(s1, s2);
    let purpose = CommitteeSampling;

    let mut csprng1 = Csprng::from_seed_and_purpose(&s1, &purpose);
    let mut csprng2 = Csprng::from_seed_and_purpose(&s2, &purpose);

    assert_ne!(csprng1.next_u32(), csprng2.next_u32());
}

#[test]
fn should_produce_different_randomness_for_different_execution_threads_for_random_beacon() {
    let rb = random_beacon();
    let (thread_1, thread_2) = (1, 2);
    assert_ne!(thread_1, thread_2);

    let mut csprng1 = Csprng::from_random_beacon_and_purpose(&rb, &ExecutionThread(thread_1));
    let mut csprng2 = Csprng::from_random_beacon_and_purpose(&rb, &ExecutionThread(thread_2));

    assert_ne!(csprng1.next_u32(), csprng2.next_u32());
}

#[test]
fn should_produce_different_randomness_for_different_execution_threads_for_randomness_seed() {
    let seed = seed();
    let (thread_1, thread_2) = (1, 2);
    assert_ne!(thread_1, thread_2);

    let mut csprng1 = Csprng::from_seed_and_purpose(&seed, &ExecutionThread(thread_1));
    let mut csprng2 = Csprng::from_seed_and_purpose(&seed, &ExecutionThread(thread_2));

    assert_ne!(csprng1.next_u32(), csprng2.next_u32());
}

#[test]
fn should_incorporate_crypto_hash_domain_when_generating_randomness_for_random_beacon() {
    // Because the crypto hash domain of random beacons is hardcoded and cannot be
    // controlled from within a test, the only way to ensure that the crypto
    // hash domain of the random beacon is incorporated when generating the
    // randomness is to test the actual expected implementation.

    let rb = random_beacon();
    for purpose in RandomnessPurpose::iter() {
        let mut hasher = Sha256::new_with_context(&DomainSeparationContext::new(rb.domain()));
        rb.hash(&mut hasher);
        let seed = Randomness::from(hasher.finish());

        let mut hasher = Sha256::new();
        hasher.write(&seed.get());
        hasher.write(&purpose.domain_separator());
        let mut csprng = Csprng::from_seed(hasher.finish());

        assert_eq!(
            Csprng::from_random_beacon_and_purpose(&rb, &purpose).next_u32(),
            csprng.next_u32()
        )
    }
}

#[test]
fn should_produce_different_seeds_for_different_random_tapes() {
    let (tape_1, tape_2) = (random_tape(), random_tape_2());
    assert_ne!(tape_1, tape_2);

    let seed_1 = Csprng::seed_from_random_tape(&tape_1);
    let seed_2 = Csprng::seed_from_random_tape(&tape_2);

    assert_ne!(seed_1, seed_2);
}

fn random_beacon() -> RandomBeacon {
    fake_random_beacon(1)
}

fn random_beacon_2() -> RandomBeacon {
    fake_random_beacon(2)
}

fn random_tape() -> RandomTape {
    fake_random_tape(1)
}

fn random_tape_2() -> RandomTape {
    fake_random_tape(2)
}

fn seed() -> Randomness {
    Randomness::new([123; 32])
}

fn seed_2() -> Randomness {
    Randomness::new([234; 32])
}

fn fake_dkg_id(h: u64) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(h),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Local,
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

fn fake_random_tape(height: u64) -> RandomTape {
    Signed {
        content: RandomTapeContent::new(Height::from(height)),
        signature: ThresholdSignature {
            signer: fake_dkg_id(0),
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}
