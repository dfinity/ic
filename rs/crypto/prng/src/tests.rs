use super::*;
use ic_types::consensus::RandomBeaconContent;
use ic_types::crypto::{
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashDomain, CryptoHashOf,
    Signed,
};
use ic_types::signature::ThresholdSignature;
use ic_types::{
    Height,
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
};
use ic_types_test_utils::ids::subnet_test_id;
use std::collections::BTreeSet;
use std::hash::Hash;
use strum::{EnumCount, IntoEnumIterator};

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
fn should_incorporate_crypto_hash_domain_when_generating_randomness_for_random_beacon() {
    // Because the crypto hash domain of random beacons is hardcoded and cannot be
    // controlled from within a test, the only way to ensure that the crypto
    // hash domain of the random beacon is incorporated when generating the
    // randomness is to test the actual expected implementation.

    let rb = fake_random_beacon(1);
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
