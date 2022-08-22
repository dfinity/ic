use ic_crypto_prng::RandomnessPurpose::{
    BlockmakerRanking, CommitteeSampling, DkgCommitteeSampling, ExecutionThread,
};
use ic_crypto_prng::{Csprng, RandomnessPurpose};
use ic_types::consensus::{RandomBeacon, RandomTape};
use ic_types::consensus::{RandomBeaconContent, RandomTapeContent};
use ic_types::crypto::{
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
};
use ic_types::signature::ThresholdSignature;
use ic_types::Randomness;
use ic_types::{
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
    Height,
};
use ic_types_test_utils::ids::subnet_test_id;
use rand::RngCore;
use std::collections::BTreeSet;
use strum::EnumCount;

#[test]
fn should_produce_deterministic_randomness_from_random_beacon_and_purpose() {
    let random_beacon = fake_random_beacon(1);

    let mut rng = Csprng::from_random_beacon_and_purpose(&random_beacon, &BlockmakerRanking);

    assert_eq!(rng.next_u32(), 460_963_034);
}

#[test]
fn should_produce_deterministic_randomness_from_seed_and_purpose() {
    let seed = seed();

    let mut rng = Csprng::from_seed_and_purpose(&seed, &CommitteeSampling);

    assert_eq!(rng.next_u32(), 196_996_056);
}

#[test]
fn should_produce_deterministic_randomness_from_seed_from_random_tape() {
    let random_tape = fake_random_tape(1);

    let randomness = Csprng::seed_from_random_tape(&random_tape);

    assert_eq!(
        randomness.get(),
        [
            109, 145, 169, 77, 62, 78, 152, 146, 147, 81, 94, 181, 213, 81, 105, 131, 60, 109, 217,
            138, 33, 26, 94, 209, 110, 76, 228, 189, 126, 119, 13, 2
        ]
    );
}

#[test]
fn should_offer_methods_of_rng_trait() {
    use rand::Rng;
    let seed = seed();

    let mut rng = Csprng::from_seed_and_purpose(&seed, &CommitteeSampling);

    assert_eq!(rng.gen::<u32>(), 196_996_056);
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
fn should_produce_different_seeds_for_different_random_tapes() {
    let (tape_1, tape_2) = (random_tape(), random_tape_2());
    assert_ne!(tape_1, tape_2);

    let seed_1 = Csprng::seed_from_random_tape(&tape_1);
    let seed_2 = Csprng::seed_from_random_tape(&tape_2);

    assert_ne!(seed_1, seed_2);
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

fn fake_random_tape(height: u64) -> RandomTape {
    Signed {
        content: RandomTapeContent::new(Height::from(height)),
        signature: ThresholdSignature {
            signer: fake_dkg_id(0),
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}
