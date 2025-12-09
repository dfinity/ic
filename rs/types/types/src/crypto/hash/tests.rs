mod crypto_hash_tests {
    use super::super::*;
    use CryptoHashDomain;
    use CryptoHashableTestDummy;
    use ic_crypto_sha2::{DomainSeparationContext, Sha256};
    use std::hash::Hash;

    #[test]
    fn crypto_hash_dependent_on_domain_and_bytes_from_hash_trait() {
        let struct_to_hash = CryptoHashableTestDummy(vec![1, 2, 3]);
        let hash_trait_bytes = bytes_fed_to_hasher_when_hashing_with_hash_trait(&struct_to_hash);
        let mut hash =
            Sha256::new_with_context(&DomainSeparationContext::new(struct_to_hash.domain()));
        hash.write(&hash_trait_bytes);
        let expected_hash_incl_domain_and_bytes_from_hash_trait =
            CryptoHash(hash.finish().to_vec());

        let crypto_hash = crypto_hash(&struct_to_hash);

        assert_eq!(
            crypto_hash.get(),
            expected_hash_incl_domain_and_bytes_from_hash_trait
        );

        fn bytes_fed_to_hasher_when_hashing_with_hash_trait<T: Hash>(
            hashable_struct: &T,
        ) -> Vec<u8> {
            let mut hasher_spy = SpyHasher::new();
            hashable_struct.hash(&mut hasher_spy);
            return hasher_spy.hashed_bytes;

            struct SpyHasher {
                hashed_bytes: Vec<u8>,
            }

            impl SpyHasher {
                fn new() -> Self {
                    SpyHasher {
                        hashed_bytes: Vec::new(),
                    }
                }
            }

            impl std::hash::Hasher for SpyHasher {
                fn finish(&self) -> u64 {
                    unimplemented!()
                }

                fn write(&mut self, bytes: &[u8]) {
                    self.hashed_bytes.extend_from_slice(bytes)
                }
            }
        }
    }
}

/// Stability test for crypto_hash output.
///
/// This test ensures that the crypto_hash function produces stable output
/// for types implementing CryptoHashDomain. The expected hashes are computed
/// once and must remain constant across code changes.
///
/// Each type is tested with a single, deterministic input to verify:
/// 1. The domain separator strings are correctly incorporated into the hash
/// 2. The Hash trait implementation for each type produces stable output
/// 3. The overall hash computation remains consistent
///
/// If any of these tests fail, it indicates a breaking change in the hash
/// computation that could affect consensus or other cryptographic protocols.
mod crypto_hash_stability {
    use crate::CryptoHashOfState;
    use crate::batch::{BatchPayload, ValidationContext};
    use crate::canister_http::{
        CanisterHttpRequestId, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseMetadata,
    };
    use crate::consensus::{
        Block, BlockMetadata, BlockPayload, CatchUpContent, CatchUpContentProtobufBytes,
        CatchUpPackage, CatchUpPackageShare, CatchUpShareContent, ConsensusMessage, DataPayload,
        EquivocationProof, FinalizationContent, HashedBlock, HashedRandomBeacon,
        NotarizationContent, Payload, RandomBeacon, RandomBeaconContent, RandomTapeContent, Rank,
        certification::{
            Certification, CertificationContent, CertificationMessage, CertificationShare,
        },
        dkg::{DealingContent, DkgDataPayload, Message as DkgMessage},
        hashed::Hashed,
        idkg::{
            EcdsaSigShare, IDkgComplaintContent, IDkgMessage, IDkgOpeningContent, RequestId,
            SchnorrSigShare, SignedIDkgComplaint, SignedIDkgOpening, VetKdKeyShare,
        },
    };
    use crate::crypto::AlgorithmId;
    use crate::crypto::CryptoHashableTestDummy;
    use crate::crypto::canister_threshold_sig::{
        ThresholdEcdsaSigShare, ThresholdSchnorrSigShare,
        idkg::{
            IDkgComplaint, IDkgDealing, IDkgDealingSupport, IDkgMaskedTranscriptOrigin,
            IDkgOpening, IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptType,
            SignedIDkgDealing,
        },
    };
    use crate::crypto::crypto_hash;
    use crate::crypto::threshold_sig::ni_dkg::{
        NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet,
    };
    use crate::crypto::vetkd::{VetKdEncryptedKeyShare, VetKdEncryptedKeyShareContent};
    use crate::crypto::{
        BasicSig, BasicSigOf, CombinedMultiSig, CombinedMultiSigOf, CombinedThresholdSig,
        CombinedThresholdSigOf, IndividualMultiSig, IndividualMultiSigOf, Signed,
        ThresholdSigShare, ThresholdSigShareOf,
    };
    use crate::crypto::{CryptoHash, CryptoHashOf};
    use crate::messages::{Blob, CallbackId, HttpCanisterUpdate, MessageId, SignedRequestBytes};
    use crate::signature::{
        BasicSignature, MultiSignature, MultiSignatureShare, ThresholdSignature,
        ThresholdSignatureShare,
    };
    use crate::time::UNIX_EPOCH;
    use crate::{
        CryptoHashOfPartialState, Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId,
    };
    use ic_base_types::PrincipalId;
    use ic_crypto_test_utils_ni_dkg::ni_dkg_csp_dealing;
    use ic_protobuf::types::v1 as pb;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// Helper to create a deterministic CryptoHashOf from a byte
    fn test_crypto_hash_of<T>(byte: u8) -> CryptoHashOf<T> {
        CryptoHashOf::new(CryptoHash(vec![byte; 32]))
    }

    /// Test stability of CryptoHashableTestDummy hash output
    #[test]
    fn crypto_hashable_test_dummy_stability() {
        let data = CryptoHashableTestDummy(vec![0x42]);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "e441ea49275512b34042c19b86821dab618732f93abd3dddd60fdfd3ac413df8",
            "Hash of CryptoHashableTestDummy changed"
        );
    }

    /// Test stability of MessageId hash output
    #[test]
    fn message_id_stability() {
        let data = MessageId::from([0x42u8; 32]);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "a583caa52347403500d1edc598cfa9e827124bce67cb6b77f92a68441d363491",
            "Hash of MessageId changed"
        );
    }

    /// Test stability of SignedRequestBytes hash output
    #[test]
    fn signed_request_bytes_stability() {
        let data = SignedRequestBytes::from(vec![0x42u8; 32]);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "12f352976ea50fa6f4f22cbf7634f3643287797989bd79e202cae14e580b3262",
            "Hash of SignedRequestBytes changed"
        );
    }

    /// Test stability of RandomTapeContent hash output
    #[test]
    fn random_tape_content_stability() {
        let data = RandomTapeContent::new(Height::from(42));
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "8dbec2ff7197fe47053d6e1e17a14d8a77858313d264ca828e89cd5aa1525bb3",
            "Hash of RandomTapeContent changed"
        );
    }

    /// Test stability of NotarizationContent hash output
    #[test]
    fn notarization_content_stability() {
        let data = NotarizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "dc2cf504a090b8e97bf98a2b5dbe37e34312dbe85bae42a2154cfe7edc5005df",
            "Hash of NotarizationContent changed"
        );
    }

    /// Test stability of Signed<NotarizationContent, MultiSignature<NotarizationContent>> hash output
    /// This is the "Notarization" type used in consensus
    #[test]
    fn notarization_stability() {
        let content = NotarizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<NotarizationContent, MultiSignature<NotarizationContent>> = Signed {
            content,
            signature: MultiSignature {
                signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![0x42; 48])),
                signers: vec![NodeId::from(PrincipalId::new_node_test_id(42))],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "adce8b217dcd4454ee31ea72342593d6734f1cbe8156bbc877d37fc00e633ffc",
            "Hash of Notarization changed"
        );
    }

    /// Test stability of Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>> hash output
    /// This is the "NotarizationShare" type used in consensus
    #[test]
    fn notarization_share_stability() {
        let content = NotarizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>> = Signed {
            content,
            signature: MultiSignatureShare {
                signature: IndividualMultiSigOf::new(IndividualMultiSig(vec![0x42; 48])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "b1719358e3e3ea11acefb2a0d66b6e867eaf721f9b33a3c75e525ee24ae3c195",
            "Hash of NotarizationShare changed"
        );
    }

    /// Test stability of FinalizationContent hash output
    #[test]
    fn finalization_content_stability() {
        let data = FinalizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "dadd6ce533b6819e63b34a29e69fef46008726e25ecbc99ca7dbdf33c3d89c81",
            "Hash of FinalizationContent changed"
        );
    }

    /// Test stability of Signed<FinalizationContent, MultiSignature<FinalizationContent>> hash output
    /// This is the "Finalization" type used in consensus
    #[test]
    fn finalization_stability() {
        let content = FinalizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<FinalizationContent, MultiSignature<FinalizationContent>> = Signed {
            content,
            signature: MultiSignature {
                signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![0x42; 48])),
                signers: vec![NodeId::from(PrincipalId::new_node_test_id(42))],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "a0836303b06da648eb0c5df8b48d3e15c5ce3677470a94c451bec0f65cf1b16c",
            "Hash of Finalization changed"
        );
    }

    /// Test stability of Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>> hash output
    /// This is the "FinalizationShare" type used in consensus
    #[test]
    fn finalization_share_stability() {
        let content = FinalizationContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>> = Signed {
            content,
            signature: MultiSignatureShare {
                signature: IndividualMultiSigOf::new(IndividualMultiSig(vec![0x42; 48])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "fe213fff29a3e9254307f0d044c2341a17e5569d64f439b5db4ab403bccdac65",
            "Hash of FinalizationShare changed"
        );
    }

    /// Test stability of RandomBeaconContent hash output
    #[test]
    fn random_beacon_content_stability() {
        let data = RandomBeaconContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "b81821fef1332d033e912d0976403f22c76eb73681d68e2f0a4aa36c736f9a3b",
            "Hash of RandomBeaconContent changed"
        );
    }

    /// Test stability of Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>> hash output
    /// This is the "RandomBeacon" type used in consensus
    #[test]
    fn random_beacon_stability() {
        let content = RandomBeaconContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>> = Signed {
            content,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                signer: test_ni_dkg_id(),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "c804349d1d1ebbb7c707408348d0d87bde256ff745ed37dd05827199fbecb43e",
            "Hash of RandomBeacon changed"
        );
    }

    /// Test stability of Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>> hash output
    /// This is the "RandomBeaconShare" type used in consensus
    #[test]
    fn random_beacon_share_stability() {
        let content = RandomBeaconContent::new(Height::from(42), test_crypto_hash_of(0x42));
        let data: Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>> =
            Signed {
                content,
                signature: ThresholdSignatureShare {
                    signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![0x42; 48])),
                    signer: NodeId::from(PrincipalId::new_node_test_id(42)),
                },
            };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "596f04a1ca01de949efe831405a780ddb0e2ac5e2a3f26aed1976a71326dd207",
            "Hash of RandomBeaconShare changed"
        );
    }

    /// Test stability of Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>> hash output
    /// This is the "RandomTape" type used in consensus
    #[test]
    fn random_tape_stability() {
        let content = RandomTapeContent::new(Height::from(42));
        let data: Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>> = Signed {
            content,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                signer: test_ni_dkg_id(),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "6bb598d1366061efa868e14fbcddf8230f08db4a48778182514c1d67b4855d4b",
            "Hash of RandomTape changed"
        );
    }

    /// Test stability of Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>> hash output
    /// This is the "RandomTapeShare" type used in consensus
    #[test]
    fn random_tape_share_stability() {
        let content = RandomTapeContent::new(Height::from(42));
        let data: Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>> = Signed {
            content,
            signature: ThresholdSignatureShare {
                signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![0x42; 48])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "37fca59988657a32693a2bdfbc54fb32621853a74de8879e5e1cd87d374b9f54",
            "Hash of RandomTapeShare changed"
        );
    }

    /// Test stability of consensus_dkg::DealingContent hash output
    #[test]
    fn dkg_dealing_content_stability() {
        let dealing = NiDkgDealing {
            internal_dealing: ni_dkg_csp_dealing(0x42),
        };
        let data = DealingContent::new(dealing, test_ni_dkg_id());
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "fde40da19d6f63f41ea08e1ac6d53af5a10eda842c37d245a44a66011fee2eee",
            "Hash of DealingContent changed"
        );
    }

    /// Test stability of consensus_dkg::Message hash output
    /// Message is BasicSigned<DealingContent>
    #[test]
    fn dkg_message_stability() {
        let dealing = NiDkgDealing {
            internal_dealing: ni_dkg_csp_dealing(0x42),
        };
        let content = DealingContent::new(dealing, test_ni_dkg_id());
        let data: DkgMessage = Signed {
            content,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "05ed4e7823575286d45e2f39d4b5f0bb8bb2dab4388765e0750067eb2999c09e",
            "Hash of DkgMessage changed"
        );
    }

    /// Test stability of CertificationContent hash output
    #[test]
    fn certification_content_stability() {
        let state_hash: CryptoHashOfPartialState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let data = CertificationContent::new(state_hash);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "73600e4a71b877c9fd4e3ee6c36cfff3db72abf6272c1c7f5e035beb1844d6d8",
            "Hash of CertificationContent changed"
        );
    }

    /// Helper to create a deterministic NiDkgId
    fn test_ni_dkg_id() -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(42),
            dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(42)),
            dkg_tag: NiDkgTag::LowThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        }
    }

    /// Test stability of Certification hash output
    #[test]
    fn certification_stability() {
        let state_hash: CryptoHashOfPartialState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let content = CertificationContent::new(state_hash);
        let data = Certification {
            height: Height::from(42),
            signed: Signed {
                content,
                signature: ThresholdSignature {
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                    signer: test_ni_dkg_id(),
                },
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "a8833f9cda71c9b857ff4c1a6d83e6a187982fc9187fa184733248c1723163c3",
            "Hash of Certification changed"
        );
    }

    /// Test stability of CertificationShare hash output
    #[test]
    fn certification_share_stability() {
        let state_hash: CryptoHashOfPartialState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let content = CertificationContent::new(state_hash);
        let data = CertificationShare {
            height: Height::from(42),
            signed: Signed {
                content,
                signature: ThresholdSignatureShare {
                    signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![0x42; 48])),
                    signer: NodeId::from(PrincipalId::new_node_test_id(42)),
                },
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "c860ffa9b824e46ae0fd68f8f7db2568f754c6ce119509c7b1a22db47780f71a",
            "Hash of CertificationShare changed"
        );
    }

    /// Helper to create a test RandomBeacon for CatchUp content
    fn test_random_beacon() -> RandomBeacon {
        let content = RandomBeaconContent::new(Height::from(42), test_crypto_hash_of(0x42));
        Signed {
            content,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                signer: test_ni_dkg_id(),
            },
        }
    }

    /// Test stability of CatchUpContent hash output
    #[test]
    fn catch_up_content_stability() {
        let block = test_block();
        let hashed_block: HashedBlock = Hashed::new(crypto_hash, block);
        let beacon = test_random_beacon();
        let hashed_beacon: HashedRandomBeacon = Hashed::new(crypto_hash, beacon);
        let state_hash: CryptoHashOfState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let data = CatchUpContent::new(
            hashed_block,
            hashed_beacon,
            state_hash,
            None, // oldest_registry_version_in_use_by_replicated_state
        );
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "5c698f370c0f6bf8d53f71c65309a50aefc5114091e34d40cb027e2340581413",
            "Hash of CatchUpContent changed"
        );
    }

    /// Test stability of CatchUpShareContent hash output
    #[test]
    fn catch_up_share_content_stability() {
        let block = test_block();
        let hashed_block: HashedBlock = Hashed::new(crypto_hash, block);
        let beacon = test_random_beacon();
        let hashed_beacon: HashedRandomBeacon = Hashed::new(crypto_hash, beacon);
        let state_hash: CryptoHashOfState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let cup_content = CatchUpContent::new(
            hashed_block,
            hashed_beacon,
            state_hash,
            None, // oldest_registry_version_in_use_by_replicated_state
        );
        let data = CatchUpShareContent::from(&cup_content);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "ae57d4db84330cb8ab8f0040e894b0b4a9b7ce22f107be0c3c86c841b580fe7d",
            "Hash of CatchUpShareContent changed"
        );
    }

    /// Test stability of CatchUpContentProtobufBytes hash output
    /// This is created from a pb::CatchUpPackage's content field
    #[test]
    fn catch_up_content_protobuf_bytes_stability() {
        // Create a pb::CatchUpPackage with deterministic content
        let pb_cup = pb::CatchUpPackage {
            content: vec![0x42; 32],
            signature: vec![0x42; 48],
            signer: Some(pb::NiDkgId {
                start_block_height: 42,
                dealer_subnet: vec![0x42; 29], // PrincipalId bytes
                dkg_tag: 1,                    // HighThreshold
                remote_target_id: None,
                key_id: None,
            }),
        };
        let data = CatchUpContentProtobufBytes::from(&pb_cup);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "5c81bbee172ee4578a5b7fa506db08e2980958e0b53a77b9da98f0b112db1295",
            "Hash of CatchUpContentProtobufBytes changed"
        );
    }

    /// Test stability of Signed<CatchUpContent, ThresholdSignature<CatchUpContent>> hash output
    /// This is the "CatchUpPackage" type used in consensus
    #[test]
    fn catch_up_package_stability() {
        let block = test_block();
        let hashed_block: HashedBlock = Hashed::new(crypto_hash, block);
        let beacon = test_random_beacon();
        let hashed_beacon: HashedRandomBeacon = Hashed::new(crypto_hash, beacon);
        let state_hash: CryptoHashOfState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let content = CatchUpContent::new(
            hashed_block,
            hashed_beacon,
            state_hash,
            None, // oldest_registry_version_in_use_by_replicated_state
        );
        let data: CatchUpPackage = Signed {
            content,
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                signer: test_ni_dkg_id(),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "998dcb7e71838ac32c2615f61ddd986676f9a3f9d6a8ab3f5db42a4f80dd49a9",
            "Hash of CatchUpPackage changed"
        );
    }

    /// Test stability of Signed<CatchUpShareContent, ThresholdSignatureShare<CatchUpContent>> hash output
    /// This is the "CatchUpPackageShare" type used in consensus
    #[test]
    fn catch_up_package_share_stability() {
        let block = test_block();
        let hashed_block: HashedBlock = Hashed::new(crypto_hash, block);
        let beacon = test_random_beacon();
        let hashed_beacon: HashedRandomBeacon = Hashed::new(crypto_hash, beacon);
        let state_hash: CryptoHashOfState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let cup_content = CatchUpContent::new(
            hashed_block,
            hashed_beacon,
            state_hash,
            None, // oldest_registry_version_in_use_by_replicated_state
        );
        let content = CatchUpShareContent::from(&cup_content);
        let data: CatchUpPackageShare = Signed {
            content,
            signature: ThresholdSignatureShare {
                signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![0x42; 48])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "44335947edd911fd04952bc699a411889801764e6e2e814bb77cc3fafc58b4f9",
            "Hash of CatchUpPackageShare changed"
        );
    }

    /// Test stability of ConsensusMessage hash output
    /// Using RandomBeacon variant as representative
    #[test]
    fn consensus_message_stability() {
        let beacon = test_random_beacon();
        let data = ConsensusMessage::RandomBeacon(beacon);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "1fca027c174658a829408379d908889031d675f775d825a82be25dedc4ff129b",
            "Hash of ConsensusMessage changed"
        );
    }

    /// Test stability of CertificationMessage hash output
    /// Using Certification variant as representative
    #[test]
    fn certification_message_stability() {
        let state_hash: CryptoHashOfPartialState = CryptoHashOf::new(CryptoHash(vec![0x42; 32]));
        let content = CertificationContent::new(state_hash);
        let cert = Certification {
            height: Height::from(42),
            signed: Signed {
                content,
                signature: ThresholdSignature {
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0x42; 48])),
                    signer: test_ni_dkg_id(),
                },
            },
        };
        let data = CertificationMessage::Certification(cert);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "e9407ce84f50ba618d3fc6ebd05477e949958619605c5dbebeba3f946debabd5",
            "Hash of CertificationMessage changed"
        );
    }

    /// Helper to create a test IDkgTranscriptId
    fn test_idkg_transcript_id() -> IDkgTranscriptId {
        IDkgTranscriptId::new(
            SubnetId::from(PrincipalId::new_subnet_test_id(42)),
            42,
            Height::from(42),
        )
    }

    /// Test stability of IDkgDealing hash output
    #[test]
    fn idkg_dealing_stability() {
        let data = IDkgDealing {
            transcript_id: test_idkg_transcript_id(),
            internal_dealing_raw: vec![0x42; 32],
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "45602e1c916bf7e7715482de4f47c9d05bf8cb4fe1ba21cd740594d46e8d3286",
            "Hash of IDkgDealing changed"
        );
    }

    /// Test stability of SignedIDkgDealing hash output
    #[test]
    fn signed_idkg_dealing_stability() {
        let dealing = IDkgDealing {
            transcript_id: test_idkg_transcript_id(),
            internal_dealing_raw: vec![0x42; 32],
        };
        let data: SignedIDkgDealing = Signed {
            content: dealing,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "b50eada3d1be529f551e9b66849f255a30c05129499eec5ff3f892e018e38a45",
            "Hash of SignedIDkgDealing changed"
        );
    }

    /// Test stability of IDkgDealingSupport hash output
    #[test]
    fn idkg_dealing_support_stability() {
        let dealing = IDkgDealing {
            transcript_id: test_idkg_transcript_id(),
            internal_dealing_raw: vec![0x42; 32],
        };
        let signed_dealing: SignedIDkgDealing = Signed {
            content: dealing,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let data = IDkgDealingSupport {
            transcript_id: test_idkg_transcript_id(),
            dealer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
            dealing_hash: crypto_hash(&signed_dealing),
            sig_share: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(43)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "22d7874a7eb230496ebe2c2970bf13a38069dd31dc535fe9bbbd9e8802b0dcd5",
            "Hash of IDkgDealingSupport changed"
        );
    }

    /// Test stability of IDkgMessage hash output
    /// Using Dealing variant as representative
    #[test]
    fn idkg_message_stability() {
        let dealing = IDkgDealing {
            transcript_id: test_idkg_transcript_id(),
            internal_dealing_raw: vec![0x42; 32],
        };
        let signed_dealing: SignedIDkgDealing = Signed {
            content: dealing,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let data = IDkgMessage::Dealing(signed_dealing);
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "82bfff9509e6f2f83bdd6a47806738996fff76c7c3690b8633b9fb73c0a5a67c",
            "Hash of IDkgMessage changed"
        );
    }

    /// Test stability of IDkgTranscript hash output
    #[test]
    fn idkg_transcript_stability() {
        let receivers = IDkgReceivers::new(
            [NodeId::from(PrincipalId::new_node_test_id(42))]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let data = IDkgTranscript {
            transcript_id: test_idkg_transcript_id(),
            receivers,
            registry_version: RegistryVersion::from(1),
            verified_dealings: Arc::new(BTreeMap::new()),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![0x42; 32],
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "c08822b87a31d8da8a48878e136a0fc1b06f2d3e16074379bf778d7430f7e7ca",
            "Hash of IDkgTranscript changed"
        );
    }

    /// Helper to create a test RequestId
    fn test_request_id() -> RequestId {
        RequestId {
            callback_id: CallbackId::from(42),
            height: Height::from(42),
        }
    }

    /// Test stability of EcdsaSigShare hash output
    #[test]
    fn ecdsa_sig_share_stability() {
        let data = EcdsaSigShare {
            signer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
            request_id: test_request_id(),
            share: ThresholdEcdsaSigShare {
                sig_share_raw: vec![0x42; 32],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "af51e218d866ac2590012f6c538ba9eccca8c2787cea21ba4c9e76dd029648bb",
            "Hash of EcdsaSigShare changed"
        );
    }

    /// Test stability of SchnorrSigShare hash output
    #[test]
    fn schnorr_sig_share_stability() {
        let data = SchnorrSigShare {
            signer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
            request_id: test_request_id(),
            share: ThresholdSchnorrSigShare {
                sig_share_raw: vec![0x42; 32],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "95ef71a4e6b41d2df6a229a9e1af4fae529e9ceef8b9f6018802e8231e58c954",
            "Hash of SchnorrSigShare changed"
        );
    }

    /// Test stability of VetKdKeyShare hash output
    #[test]
    fn vetkd_key_share_stability() {
        let data = VetKdKeyShare {
            signer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
            request_id: test_request_id(),
            share: VetKdEncryptedKeyShare {
                encrypted_key_share: VetKdEncryptedKeyShareContent(vec![0x42; 32]),
                node_signature: vec![0x42; 64],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "2b94aa137a64735e5aa4b6eb134c6dc441e9390a783e2c42c5412e227d84e423",
            "Hash of VetKdKeyShare changed"
        );
    }

    /// Test stability of IDkgComplaintContent hash output
    #[test]
    fn idkg_complaint_content_stability() {
        let data = IDkgComplaintContent {
            idkg_complaint: IDkgComplaint {
                transcript_id: test_idkg_transcript_id(),
                dealer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                internal_complaint_raw: vec![0x42; 32],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "12415f344332c025c85d0f10c1744cf046e6ea18daa7984386ec365bf037766c",
            "Hash of IDkgComplaintContent changed"
        );
    }

    /// Test stability of SignedIDkgComplaint hash output
    #[test]
    fn signed_idkg_complaint_stability() {
        let content = IDkgComplaintContent {
            idkg_complaint: IDkgComplaint {
                transcript_id: test_idkg_transcript_id(),
                dealer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                internal_complaint_raw: vec![0x42; 32],
            },
        };
        let data: SignedIDkgComplaint = Signed {
            content,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(43)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "05631e4511c1b1a9dc1ea981d62572102514072065ad49dd3627b73a89740bf4",
            "Hash of SignedIDkgComplaint changed"
        );
    }

    /// Test stability of IDkgOpeningContent hash output
    #[test]
    fn idkg_opening_content_stability() {
        let data = IDkgOpeningContent {
            idkg_opening: IDkgOpening {
                transcript_id: test_idkg_transcript_id(),
                dealer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                internal_opening_raw: vec![0x42; 32],
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "041501bc65d655a695b1a76b13383e74cbf0f61c0c442fe395db1d00d692c329",
            "Hash of IDkgOpeningContent changed"
        );
    }

    /// Test stability of SignedIDkgOpening hash output
    #[test]
    fn signed_idkg_opening_stability() {
        let content = IDkgOpeningContent {
            idkg_opening: IDkgOpening {
                transcript_id: test_idkg_transcript_id(),
                dealer_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                internal_opening_raw: vec![0x42; 32],
            },
        };
        let data: SignedIDkgOpening = Signed {
            content,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(43)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "ec2089153513ff43e52699c3500b11ec9c5ad139aba2147e272a3571e3f7bf52",
            "Hash of SignedIDkgOpening changed"
        );
    }

    /// Test stability of Block hash output
    #[test]
    fn block_stability() {
        let data = Block::new(
            test_crypto_hash_of(0x42), // parent
            Payload::new(
                crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new_empty(Height::from(0)),
                    idkg: None,
                }),
            ),
            Height::from(42),
            Rank(0),
            ValidationContext {
                registry_version: RegistryVersion::from(1),
                certified_height: Height::from(41),
                time: UNIX_EPOCH,
            },
        );
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "0043108046ad04abcc970730f1e7e1cd4b3918725362adc620fe391a3239d6b4",
            "Hash of Block changed"
        );
    }

    /// Helper to create a test block for use in other tests
    fn test_block() -> Block {
        Block::new(
            test_crypto_hash_of(0x42),
            Payload::new(
                crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload::default(),
                    dkg: DkgDataPayload::new_empty(Height::from(0)),
                    idkg: None,
                }),
            ),
            Height::from(42),
            Rank(0),
            ValidationContext {
                registry_version: RegistryVersion::from(1),
                certified_height: Height::from(41),
                time: UNIX_EPOCH,
            },
        )
    }

    /// Test stability of Signed<HashedBlock, BasicSignature<BlockMetadata>> hash output
    /// This is the "BlockProposal" type used in consensus
    #[test]
    fn block_proposal_stability() {
        let block = test_block();
        let hashed_block: HashedBlock = Hashed::new(crypto_hash, block);
        let data: Signed<HashedBlock, BasicSignature<BlockMetadata>> = Signed {
            content: hashed_block,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "ead07112fa9ef8117f3d4171cf66c3d49bfd9d39b6a3c2d44b5c0ce3ecf4c903",
            "Hash of BlockProposal changed"
        );
    }

    /// Test stability of EquivocationProof hash output
    #[test]
    fn equivocation_proof_stability() {
        let data = EquivocationProof {
            signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            version: ReplicaVersion::default(),
            height: Height::from(42),
            subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(42)),
            hash1: test_crypto_hash_of(0x42),
            signature1: BasicSigOf::new(BasicSig(vec![0x42; 64])),
            hash2: test_crypto_hash_of(0x43),
            signature2: BasicSigOf::new(BasicSig(vec![0x43; 64])),
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "e6bb7c1053dedf17239fc52bb5c5b27b60fe7990df7a07268708d637adf75001",
            "Hash of EquivocationProof changed"
        );
    }

    /// Test stability of BlockPayload hash output
    #[test]
    fn block_payload_stability() {
        let data = BlockPayload::Data(DataPayload {
            batch: BatchPayload::default(),
            dkg: DkgDataPayload::new_empty(Height::from(0)),
            idkg: None,
        });
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "e6030b101e9c9d92eb352d6ada01bd6dc64e1f358d30a3c113411f4f8201b369",
            "Hash of BlockPayload changed"
        );
    }

    /// Test stability of HttpCanisterUpdate hash output
    #[test]
    fn http_canister_update_stability() {
        let data = HttpCanisterUpdate {
            canister_id: Blob(vec![0x42; 10]),
            method_name: "test_method".to_string(),
            arg: Blob(vec![0x42; 8]),
            sender: Blob(vec![0x42; 29]),
            ingress_expiry: 1234567890,
            nonce: Some(Blob(vec![0x42; 8])),
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "1fc89a61eb9215d4c379b3ac99c23ff73140ff1ba89a8fbd531c7fc62fc0c762",
            "Hash of HttpCanisterUpdate changed"
        );
    }

    /// Test stability of CanisterHttpResponse hash output
    #[test]
    fn canister_http_response_stability() {
        let data = CanisterHttpResponse {
            id: CanisterHttpRequestId::from(42),
            timeout: UNIX_EPOCH,
            canister_id: ic_base_types::CanisterId::from_u64(42),
            content: CanisterHttpResponseContent::Success(vec![0x42; 16]),
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "48f996c026833b51d8e34775ee8ca1354abe0b4fd29d9795290e3747ad477650",
            "Hash of CanisterHttpResponse changed"
        );
    }

    /// Test stability of CanisterHttpResponseMetadata hash output
    #[test]
    fn canister_http_response_metadata_stability() {
        let data = CanisterHttpResponseMetadata {
            id: CallbackId::from(42),
            timeout: UNIX_EPOCH,
            content_hash: test_crypto_hash_of(0x42),
            registry_version: RegistryVersion::from(1),
            replica_version: ReplicaVersion::default(),
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "5b1f5808c5e36cb70254914aeb76682e158889b6071c2c1c7b2a6667b2d5a699",
            "Hash of CanisterHttpResponseMetadata changed"
        );
    }

    /// Test stability of CanisterHttpResponseShare hash output
    #[test]
    fn canister_http_response_share_stability() {
        let metadata = CanisterHttpResponseMetadata {
            id: CallbackId::from(42),
            timeout: UNIX_EPOCH,
            content_hash: test_crypto_hash_of(0x42),
            registry_version: RegistryVersion::from(1),
            replica_version: ReplicaVersion::default(),
        };
        let data = Signed {
            content: metadata,
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![0x42; 64])),
                signer: NodeId::from(PrincipalId::new_node_test_id(42)),
            },
        };
        let hash = crypto_hash(&data);
        assert_eq!(
            hex::encode(hash.get_ref().0.as_slice()),
            "e1f245d7fafe2fc4db847ac67141ebe869dcc1901c6779fe46c876341c797b68",
            "Hash of CanisterHttpResponseShare changed"
        );
    }
}
