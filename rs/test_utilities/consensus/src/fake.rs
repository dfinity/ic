use std::collections::BTreeMap;

use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
use ic_interfaces::{
    certification::{Verifier, VerifierError},
    validation::ValidationResult,
};
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    CryptoHashOfPartialState, Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId,
    batch::{BatchPayload, ValidationContext},
    consensus::{
        Block, BlockPayload, DataPayload, FinalizationContent, FinalizationShare,
        NotarizationContent, NotarizationShare, Payload, RandomBeacon, RandomBeaconContent,
        RandomBeaconShare, RandomTapeContent, RandomTapeShare, Rank, SummaryPayload,
        certification::{Certification, CertificationContent},
        dkg::{DkgDataPayload, DkgSummary},
        hashed,
    },
    crypto::{
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript},
        *,
    },
    signature::{
        BasicSignature, MultiSignature, MultiSignatureShare, ThresholdSignature,
        ThresholdSignatureShare,
    },
};
use serde::{Deserialize, Serialize};

pub trait Fake {
    fn fake() -> Self;
}

impl Fake for SummaryPayload {
    fn fake() -> Self {
        Self {
            dkg: DkgSummary::fake(),
            idkg: None,
        }
    }
}

impl Fake for DataPayload {
    fn fake() -> Self {
        Self {
            batch: BatchPayload::default(),
            dkg: DkgDataPayload::new_empty(Height::from(0)),
            idkg: None,
        }
    }
}

impl Fake for DkgSummary {
    fn fake() -> Self {
        let registry_version = 1;

        Self::new(
            /*configs=*/ Vec::default(),
            /*current_transcripts=*/
            empty_ni_dkg_transcripts_with_committee(registry_version),
            /*next_transcripts=*/ BTreeMap::default(),
            /*transcript_for_new_subnets=*/ Vec::default(),
            RegistryVersion::from(registry_version),
            /*interval_length=*/ Height::new(59),
            /*next_interval_length=*/ Height::new(59),
            /*height=*/ Height::new(0),
            /*initial_dkg_attempts=*/ BTreeMap::default(),
        )
    }
}

impl Fake for Certification {
    fn fake() -> Self {
        Certification {
            height: Height::new(0),
            signed: Signed {
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    vec![],
                ))),
                signature: ThresholdSignature::fake(),
            },
        }
    }
}

fn empty_ni_dkg_transcripts_with_committee(
    registry_version: u64,
) -> BTreeMap<NiDkgTag, NiDkgTranscript> {
    let committee = vec![node_test_id(0)];

    BTreeMap::from([
        (
            NiDkgTag::LowThreshold,
            dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::LowThreshold,
                NiDkgTag::LowThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
        (
            NiDkgTag::HighThreshold,
            dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
    ])
}

impl<T> Fake for MultiSignature<T> {
    fn fake() -> MultiSignature<T> {
        MultiSignature {
            signers: Vec::new(),
            signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
        }
    }
}

impl<T> Fake for ThresholdSignature<T> {
    fn fake() -> ThresholdSignature<T> {
        ThresholdSignature {
            signer: NiDkgId {
                start_block_height: Height::from(0),
                dealer_subnet: subnet_test_id(0),
                dkg_tag: NiDkgTag::LowThreshold,
                target_subnet: NiDkgTargetSubnet::Local,
            },
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        }
    }
}

pub trait FakeSigner {
    fn fake(signer: NodeId) -> Self;
}

impl<T> FakeSigner for BasicSignature<T> {
    fn fake(signer: NodeId) -> BasicSignature<T> {
        BasicSignature {
            signer,
            signature: BasicSigOf::new(BasicSig(vec![])),
        }
    }
}

impl<T> FakeSigner for MultiSignatureShare<T> {
    fn fake(signer: NodeId) -> MultiSignatureShare<T> {
        MultiSignatureShare {
            signer,
            signature: IndividualMultiSigOf::new(IndividualMultiSig(vec![])),
        }
    }
}

impl<T> FakeSigner for ThresholdSignatureShare<T> {
    fn fake(signer: NodeId) -> ThresholdSignatureShare<T> {
        ThresholdSignatureShare {
            signer,
            signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![])),
        }
    }
}

pub trait FakeContent<T> {
    fn fake(content: T) -> Self;
}

impl<T> FakeContent<T> for Signed<T, MultiSignature<T>> {
    fn fake(content: T) -> Signed<T, MultiSignature<T>> {
        Signed {
            content,
            signature: MultiSignature::fake(),
        }
    }
}

impl<T> FakeContent<T> for Signed<T, ThresholdSignature<T>> {
    fn fake(content: T) -> Signed<T, ThresholdSignature<T>> {
        Signed {
            content,
            signature: ThresholdSignature::fake(),
        }
    }
}
pub trait FakeContentUpdate {
    fn update_content(&mut self);
}

impl<T: CryptoHashable + Clone, S: Signable> FakeContentUpdate
    for Signed<hashed::Hashed<CryptoHashOf<T>, T>, BasicSignature<S>>
{
    fn update_content(&mut self) {
        self.content =
            hashed::Hashed::new(ic_types::crypto::crypto_hash, self.content.as_ref().clone());
    }
}

pub trait FakeContentSigner<T> {
    fn fake(content: T, signer: NodeId) -> Self;
}

impl<T> FakeContentSigner<T> for Signed<T, BasicSignature<T>> {
    fn fake(content: T, signer: NodeId) -> Signed<T, BasicSignature<T>> {
        Signed {
            content,
            signature: BasicSignature::fake(signer),
        }
    }
}

impl<T: CryptoHashable, S: Signable> FakeContentSigner<T>
    for Signed<hashed::Hashed<CryptoHashOf<T>, T>, BasicSignature<S>>
{
    fn fake(
        content: T,
        signer: NodeId,
    ) -> Signed<hashed::Hashed<CryptoHashOf<T>, T>, BasicSignature<S>> {
        Signed {
            content: hashed::Hashed::new(ic_types::crypto::crypto_hash, content),
            signature: BasicSignature::fake(signer),
        }
    }
}

impl FakeContentSigner<&Block> for NotarizationShare {
    fn fake(block: &Block, signer: NodeId) -> NotarizationShare {
        Signed {
            content: NotarizationContent::new(block.height, ic_types::crypto::crypto_hash(block)),
            signature: MultiSignatureShare::fake(signer),
        }
    }
}

impl FakeContentSigner<&Block> for FinalizationShare {
    fn fake(block: &Block, signer: NodeId) -> FinalizationShare {
        let height = block.height;
        let block = ic_types::crypto::crypto_hash(block);
        Signed {
            content: FinalizationContent::new(height, block),
            signature: MultiSignatureShare::fake(signer),
        }
    }
}

impl FakeContentSigner<&RandomBeacon> for RandomBeaconShare {
    fn fake(parent: &RandomBeacon, signer: NodeId) -> RandomBeaconShare {
        let signature = ThresholdSignatureShare {
            signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![])),
            signer,
        };
        let height = parent.content.height.increment();
        let beacon = RandomBeaconContent::new(height, ic_types::crypto::crypto_hash(parent));
        Signed {
            content: beacon,
            signature,
        }
    }
}

impl FakeContentSigner<Height> for RandomTapeShare {
    fn fake(height: Height, signer: NodeId) -> RandomTapeShare {
        let signature = ThresholdSignatureShare {
            signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![])),
            signer,
        };
        Signed {
            content: RandomTapeContent::new(height),
            signature,
        }
    }
}

pub trait FromParent {
    fn from_parent(parent: &Self) -> Self;
}

impl FromParent for Block {
    fn from_parent(parent: &Self) -> Self {
        let dkg_start = parent.payload.as_ref().dkg_interval_start_height();
        Block::new(
            ic_types::crypto::crypto_hash(parent),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new_empty(dkg_start),
                    idkg: parent.payload.as_ref().as_idkg().cloned(),
                }),
            ),
            parent.height.increment(),
            Rank(0),
            parent.context.clone(),
        )
    }
}

impl FromParent for RandomBeacon {
    fn from_parent(parent: &Self) -> Self {
        Self::fake(RandomBeaconContent::new(
            parent.content.height.increment(),
            ic_types::crypto::crypto_hash(parent),
        ))
    }
}

pub trait FakeVersion {
    fn fake_version(&self, version: ReplicaVersion) -> Self;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
struct FakeBlock {
    version: ReplicaVersion,
    pub parent: CryptoHashOf<Block>,
    pub payload: Payload,
    pub height: Height,
    pub rank: Rank,
    pub context: ValidationContext,
}

impl FakeVersion for Block {
    fn fake_version(&self, version: ReplicaVersion) -> Self {
        let bytes = bincode::serialize(self).unwrap();
        let mut fake_block = bincode::deserialize::<FakeBlock>(&bytes).unwrap();
        fake_block.version = version;
        let bytes = bincode::serialize(&fake_block).unwrap();
        bincode::deserialize::<Block>(&bytes).unwrap()
    }
}

#[derive(Default)]
pub struct FakeVerifier;

impl FakeVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Verifier for FakeVerifier {
    fn validate(
        &self,
        _subnet_id: SubnetId,
        _certification: &Certification,
        _registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ic_types::consensus::HasVersion;

    use super::*;

    #[test]
    fn test_fake_block_is_binary_compatible() {
        let block = Block::new(
            CryptoHashOf::from(CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new_empty(Height::from(1)),
                    idkg: None,
                }),
            ),
            Height::from(123),
            Rank(456),
            ValidationContext {
                registry_version: RegistryVersion::from(99),
                certified_height: Height::from(42),
                time: ic_types::time::UNIX_EPOCH,
            },
        );
        let bytes1 = bincode::serialize(&block).unwrap();
        let fake_block = bincode::deserialize::<FakeBlock>(&bytes1).unwrap();
        let bytes2 = bincode::serialize(&fake_block).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_fake_block() {
        use std::convert::TryFrom;
        let block = Block::new(
            CryptoHashOf::from(CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new_empty(Height::from(1)),
                    idkg: None,
                }),
            ),
            Height::from(123),
            Rank(456),
            ValidationContext {
                registry_version: RegistryVersion::from(99),
                certified_height: Height::from(42),
                time: ic_types::time::UNIX_EPOCH,
            },
        );

        // fake block is binary compatible
        let bytes1 = bincode::serialize(&block).unwrap();
        let fake_block = bincode::deserialize::<FakeBlock>(&bytes1).unwrap();
        let bytes2 = bincode::serialize(&fake_block).unwrap();
        assert_eq!(bytes1, bytes2);

        // fake version works as expected
        let new_version = ReplicaVersion::try_from(format!("{}.1234", block.version())).unwrap();
        let block2 = block.fake_version(new_version.clone());
        assert_eq!(block2.version(), &new_version);
    }
}
