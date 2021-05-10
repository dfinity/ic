use ic_crypto::crypto_hash;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        dkg, Block, CatchUpContent, CatchUpPackage, HashedBlock, HashedRandomBeacon, Payload,
        RandomBeaconContent, Rank, ThresholdSignature,
    },
    crypto::{
        threshold_sig::ni_dkg::NiDkgTag, CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash,
        Signed,
    },
    time::UNIX_EPOCH,
    Height,
};
use phantom_newtype::Id;

mod hashable;
pub use hashable::ConsensusMessageHashable;

/// Return the genesis BlockProposal and RandomBeacon made for the given height.
pub fn make_genesis(summary: dkg::Summary) -> CatchUpPackage {
    // Use the registry version and height, from which the summary package was
    // created.
    let registry_version = summary.registry_version;
    let height = summary.height;
    let low_dkg_id = summary.current_transcript(&NiDkgTag::LowThreshold).dkg_id;
    let high_dkg_id = summary.current_transcript(&NiDkgTag::HighThreshold).dkg_id;
    let block = Block::new(
        Id::from(CryptoHash(Vec::new())),
        Payload::new(crypto_hash, summary.into()),
        height,
        Rank(0),
        ValidationContext {
            certified_height: Height::from(0),
            registry_version,
            time: UNIX_EPOCH,
        },
    );
    let random_beacon = Signed {
        content: RandomBeaconContent::new(height, Id::from(CryptoHash(Vec::new()))),
        signature: ThresholdSignature {
            signer: low_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    };
    CatchUpPackage {
        content: CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            Id::from(CryptoHash(Vec::new())),
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    }
}
