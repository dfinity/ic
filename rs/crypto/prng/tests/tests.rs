use ic_crypto_prng::RandomnessPurpose::{
    BlockmakerRanking, CommitteeSampling, DkgCommitteeSampling, ExecutionThread,
};
use ic_crypto_prng::{Csprng, RandomnessPurpose};
use ic_types::Randomness;
use ic_types::consensus::RandomBeacon;
use ic_types::consensus::RandomBeaconContent;
use ic_types::crypto::{
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
};
use ic_types::signature::ThresholdSignature;
use ic_types::{
    Height, ReplicaVersion,
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
};
use ic_types_test_utils::ids::subnet_test_id;
use rand::RngCore;
use std::collections::BTreeSet;
use strum::EnumCount;

/// Fix ReplicaVersion::default to 0.8.0
///
/// Some of the tests, namely those involving the random beacon, end
/// up incorporating the default replica version into the hash.
///
/// This can change if the crate versions are ever modified. To make these
/// tests immunte to such changes, set ReplicaVersion::default to 0.8.0,
/// or panic if that is not successful.
fn fix_replica_version() {
    let fixed_replica_version =
        ReplicaVersion::try_from("0.8.0").expect("Failed to create replica version");

    let _ = ReplicaVersion::set_default_version(fixed_replica_version.clone());

    // Either we were able to set it, or we were not. If we were not,
    // hopefully it is because we already did it previously.
    //
    // Either way, check that ReplicaVersion::default returns the value we need it to.

    assert_eq!(ReplicaVersion::default(), fixed_replica_version);
}

#[test]
fn should_produce_deterministic_randomness_from_random_beacon_and_purpose() {
    fix_replica_version();

    let random_beacon = fake_random_beacon(1);

    let mut rng = Csprng::from_random_beacon_and_purpose(&random_beacon, &BlockmakerRanking);

    assert_eq!(rng.next_u32(), 460_963_034);
}

#[test]
fn should_produce_deterministic_randomness_from_seed_and_purpose() {
    fix_replica_version();

    let seed = seed();

    let mut rng = Csprng::from_seed_and_purpose(&seed, &CommitteeSampling);

    assert_eq!(rng.next_u32(), 196_996_056);
}

#[test]
fn should_offer_methods_of_rng_trait() {
    use rand::Rng;
    let seed = seed();

    let mut rng = Csprng::from_seed_and_purpose(&seed, &CommitteeSampling);

    assert_eq!(rng.r#gen::<u32>(), 196_996_056);
}

#[test]
fn should_generate_purpose_specific_randomness_for_random_beacon() {
    fix_replica_version();

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
    fix_replica_version();

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
    fix_replica_version();

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
