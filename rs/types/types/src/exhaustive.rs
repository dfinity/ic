//! Implementations and serialization tests of the ExhaustiveSet trait

use crate::consensus::hashed::Hashed;
use crate::consensus::idkg::common::{PreSignatureInCreation, PreSignatureRef};
use crate::consensus::idkg::ecdsa::{QuadrupleInCreation, ThresholdEcdsaSigInputsRef};
use crate::consensus::idkg::{
    CompletedReshareRequest, CompletedSignature, HasMasterPublicKeyId, IDkgPayload,
    IDkgReshareRequest, IDkgUIDGenerator, MaskedTranscript, MasterKeyTranscript, PreSigId,
    PseudoRandomId, RandomTranscriptParams, RandomUnmaskedTranscriptParams, RequestId,
    ReshareOfMaskedParams, ReshareOfUnmaskedParams, UnmaskedTimesMaskedParams, UnmaskedTranscript,
};
use crate::consensus::{
    Block, BlockPayload, CatchUpShareContent, ConsensusMessageHashable, Payload, SummaryPayload,
};
use crate::consensus::{CatchUpContent, CatchUpPackage, HashedBlock, HashedRandomBeacon};
use crate::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealers, IDkgDealing, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    InitialIDkgDealings, SignedIDkgDealing,
};
use crate::crypto::threshold_sig::ni_dkg::{
    config::{tests::valid_dkg_config_data, NiDkgConfig},
    NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTranscript,
};
use crate::crypto::{
    crypto_hash, AlgorithmId, BasicSig, BasicSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, CryptoHashable,
    IndividualMultiSig, IndividualMultiSigOf, Signed, ThresholdSigShare, ThresholdSigShareOf,
};
use crate::signature::{
    BasicSignature, BasicSignatureBatch, MultiSignature, MultiSignatureShare, ThresholdSignature,
    ThresholdSignatureShare,
};
use crate::xnet::CertifiedStreamSlice;
use crate::{CryptoHashOfState, ReplicaVersion};
use ic_base_types::{CanisterId, NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_btc_replica_types::{
    BitcoinAdapterResponse, BitcoinAdapterResponseWrapper, BitcoinReject,
    GetSuccessorsResponseComplete, SendTransactionResponse,
};
use ic_crypto_internal_types::NodeIndex;
use ic_error_types::RejectCode;
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
};
use ic_protobuf::types::v1 as pb;
use phantom_newtype::{AmountOf, Id};
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use strum::IntoEnumIterator;

/// A trait for creating an exhaustive set of fake values for a type, which we
/// use to test serialization correctness.
///
/// For basic types like integers, byte arrays, byte vectors, Strings etc.
/// a random NON-ZERO(!) value is considered an "exhaustive" set (with regards
/// to our goal of testing for serialization correctness). For integers, our
/// implementation also includes the maximum value (::MAX) in the set.
///
/// For algebraic data types, every member's exhaustive set needs to be present
/// at least once in the ADT's set. We do not require every combination of
/// values to be in the set, as that would make the set grow exponential.
///
/// NOTE(Implementation): You should never manually implement this trait for
/// enums. Instead, use the #[derive(ExhaustiveSet)] and implement the trait
/// for the inner enum type. Example:
///
/// ```
/// #[derive(ExhaustiveSet)]
/// pub enum Foo {
///     Variant1,
///     Variant2(InnerType)
/// }
///
/// impl ExhaustiveSet for InnerType {
///     fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
///         /* your implementation */
///     }
/// }
/// ```
///
/// This ensures that the exhaustive set of enums always contains every variant
/// (this logic is contained in the derive macro).
pub trait ExhaustiveSet: Clone + Sized {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self>;
}

impl<A: ExhaustiveSet, B: ExhaustiveSet, C: ExhaustiveSet> ExhaustiveSet for (A, B, C) {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let a_set = A::exhaustive_set(rng);
        let b_set = B::exhaustive_set(rng);
        let c_set = C::exhaustive_set(rng);
        let max = [a_set.len(), b_set.len(), c_set.len()]
            .into_iter()
            .max()
            .unwrap();

        let mut a_set = a_set.iter().cycle();
        let mut b_set = b_set.iter().cycle();
        let mut c_set = c_set.iter().cycle();

        let mut result = Vec::new();
        for _ in 0..max {
            result.push((
                a_set.next().unwrap().clone(),
                b_set.next().unwrap().clone(),
                c_set.next().unwrap().clone(),
            ));
        }
        result
    }
}

impl<A: ExhaustiveSet, B: ExhaustiveSet> ExhaustiveSet for (A, B) {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let a_set = A::exhaustive_set(rng);
        let b_set = B::exhaustive_set(rng);
        let max = std::cmp::max(a_set.len(), b_set.len());

        let mut a_set = a_set.iter().cycle();
        let mut b_set = b_set.iter().cycle();

        let mut result = Vec::new();
        for _ in 0..max {
            result.push((a_set.next().unwrap().clone(), b_set.next().unwrap().clone()));
        }
        result
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Option<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        T::exhaustive_set(rng)
            .into_iter()
            .map(|elem| Some(elem))
            .chain(std::iter::once(None))
            .collect()
    }
}

impl<T: ExhaustiveSet, E: ExhaustiveSet> ExhaustiveSet for Result<T, E> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        // join exhaustive sets of T and E
        let ok_set = T::exhaustive_set(rng).into_iter().map(|v| Ok(v));
        let err_set = E::exhaustive_set(rng).into_iter().map(|e| Err(e));
        ok_set.chain(err_set).collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Vec<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut set = Vec::new();
        // add a couple of random variations
        for _ in 0..8 {
            set.append(&mut T::exhaustive_set(rng));
        }
        vec![set, vec![]]
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Box<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        T::exhaustive_set(rng)
            .into_iter()
            .map(|elem| Box::new(elem))
            .collect()
    }
}

impl<T: ExhaustiveSet, const N: usize> ExhaustiveSet for [T; N] {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let exhaust_t = T::exhaustive_set(rng);
        let mut exhaust_iter = exhaust_t.iter().cycle();
        assert!(!exhaust_t.is_empty(), "exhaustive set must not be zero");

        // We consider a first case, where the exhaustive set of T is smaller than N.
        //
        // exhaust_t: [A, B, C]           length: 3
        // [T; N]:    [_, _, _, _]        length: 4
        // Result:    [[A, B, C, A]]
        //
        // Now, if exhaust_t.len() is larger than N, we can't stuff all variants into a
        // single array. So we need to spread them out over multiple instance of [T; N]:
        //
        // exhaust_t: [A, B, C, D, E, F]              length: 6
        // [T; N]:    [_, _, _, _]                    length: 4
        // Result:    [[A, B, C, D], [E, F, A, B]]
        //
        // With `1 + exhaust_t.len() / N` number of arrays, we can include every variant
        // of exhaust_t.
        let mut result = Vec::new();
        let bound = 1 + exhaust_t.len() / N;
        for _ in 0..bound {
            // populate array with cyclic iterator
            let elem = std::array::from_fn::<T, N, _>(|_| exhaust_iter.next().unwrap().clone());

            result.push(elem);
        }
        result
    }
}

impl<T> ExhaustiveSet for std::marker::PhantomData<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec![std::marker::PhantomData]
    }
}

impl ExhaustiveSet for () {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec![()]
    }
}

impl ExhaustiveSet for String {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec!["0123abcd!@#$.,;()[]<>".to_string(), "".to_string()]
    }
}

macro_rules! impl_for_integer {
    ($t: ty) => {
        impl ExhaustiveSet for $t {
            fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
                let val = rng.next_u64();
                vec![<$t>::MAX, val as $t, 0]
            }
        }
    };
    ($t: ty, $($y:ty),+) => {
        impl_for_integer!($t);
        impl_for_integer!($($y),+);
    };
}

impl_for_integer! { u8, u16, u32, u64, u128 }

impl<T: ExhaustiveSet> ExhaustiveSet for std::sync::Arc<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        T::exhaustive_set(rng)
            .into_iter()
            .map(std::sync::Arc::new)
            .collect()
    }
}

impl<K: ExhaustiveSet + std::cmp::Ord, V: ExhaustiveSet + HasId<K>> ExhaustiveSet
    for BTreeMap<K, V>
{
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let (k_set, v_set): (Vec<_>, Vec<_>) = <(K, V)>::exhaustive_set(rng).into_iter().unzip();
        let mut k_set = k_set.into_iter();

        let mut result = vec![BTreeMap::new()];
        for v in v_set {
            let id = v.get_id().unwrap_or_else(|| k_set.next().unwrap());
            let mut inserted = false;
            for map in &mut result {
                if !map.contains_key(&id) {
                    map.insert(id.clone(), v.clone());
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                result.push(BTreeMap::from([(id, v)]));
            }
        }
        result.push(BTreeMap::new());
        result
    }
}

impl<K: ExhaustiveSet + std::cmp::Ord> ExhaustiveSet for BTreeSet<K> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        Vec::<K>::exhaustive_set(rng)
            .into_iter()
            .map(BTreeSet::from_iter)
            .collect()
    }
}

impl ExhaustiveSet for RejectCode {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        RejectCode::iter().collect()
    }
}

impl ExhaustiveSet for PrincipalId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut data = [0u8; Self::MAX_LENGTH_IN_BYTES];
        rng.fill_bytes(&mut data);
        vec![Self::new(data.len(), data)]
    }
}

impl ExhaustiveSet for CanisterId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        PrincipalId::exhaustive_set(rng)
            .into_iter()
            .map(CanisterId::unchecked_from_principal)
            .collect()
    }
}

impl<Unit, Repr: ExhaustiveSet> ExhaustiveSet for AmountOf<Unit, Repr> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        Repr::exhaustive_set(rng)
            .into_iter()
            .map(AmountOf::new)
            .collect()
    }
}

impl<Entity, Repr: ExhaustiveSet> ExhaustiveSet for Id<Entity, Repr> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        Repr::exhaustive_set(rng).into_iter().map(Id::new).collect()
    }
}

impl ExhaustiveSet for crate::consensus::Payload {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        BlockPayload::exhaustive_set(rng)
            .into_iter()
            .map(|elem| Self::new(crypto_hash, elem))
            .collect()
    }
}

impl ExhaustiveSet for ReplicaVersion {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        vec![
            ReplicaVersion::try_from(format!("2020-09.{}.{}", rng.next_u32(), rng.next_u32()))
                .unwrap(),
        ]
    }
}

impl ExhaustiveSet for EcdsaCurve {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        EcdsaCurve::iter().collect()
    }
}

impl ExhaustiveSet for EcdsaKeyId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(EcdsaCurve, String)>::exhaustive_set(rng)
            .into_iter()
            .map(|elem| Self {
                curve: elem.0,
                name: elem.1,
            })
            .collect()
    }
}

impl ExhaustiveSet for SchnorrAlgorithm {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        SchnorrAlgorithm::iter().collect()
    }
}

impl ExhaustiveSet for SchnorrKeyId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(SchnorrAlgorithm, String)>::exhaustive_set(rng)
            .into_iter()
            .map(|elem| Self {
                algorithm: elem.0,
                name: elem.1,
            })
            .collect()
    }
}

impl ExhaustiveSet for MasterPublicKeyId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let ecdsa_key_ids = EcdsaKeyId::exhaustive_set(rng);
        let schnorr_key_ids = SchnorrKeyId::exhaustive_set(rng);

        ecdsa_key_ids
            .into_iter()
            .map(MasterPublicKeyId::Ecdsa)
            .chain(schnorr_key_ids.into_iter().map(MasterPublicKeyId::Schnorr))
            .collect()
    }
}

impl<V: ExhaustiveSet + CryptoHashable> ExhaustiveSet for Hashed<CryptoHashOf<V>, V> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut res = Vec::new();
        for v in V::exhaustive_set(rng) {
            res.push(Hashed::new(crypto_hash, v));
        }
        res
    }
}

#[derive(Clone)]
struct HashedSummaryBlock {
    summary_block: HashedBlock,
}

impl ExhaustiveSet for HashedSummaryBlock {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let summary_payloads = SummaryPayload::exhaustive_set(rng);
        let mut index = 0;

        Block::exhaustive_set(rng)
            .into_iter()
            .map(|mut block| {
                let summary = match block.payload.as_ref() {
                    BlockPayload::Summary(summary) => summary.clone(),
                    BlockPayload::Data(_) => {
                        let summary = summary_payloads[index % summary_payloads.len()].clone();
                        index += 1;
                        summary
                    }
                };
                block.payload = Payload::new(crypto_hash, BlockPayload::Summary(summary));

                Self {
                    summary_block: Hashed::new(crypto_hash, block),
                }
            })
            .collect()
    }
}

impl ExhaustiveSet for CatchUpContent {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let registry_versions = Option::<RegistryVersion>::exhaustive_set(rng);
        <(HashedSummaryBlock, HashedRandomBeacon, CryptoHashOfState)>::exhaustive_set(rng)
            .into_iter()
            .enumerate()
            .map(|(i, (block, random_beacon, state_hash))| {
                Self::new(
                    block.summary_block,
                    random_beacon,
                    state_hash,
                    registry_versions[i % registry_versions.len()],
                )
            })
            .collect()
    }
}

impl ExhaustiveSet for CatchUpShareContent {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <CatchUpContent>::exhaustive_set(rng)
            .iter()
            .map(|cup| cup.into())
            .collect()
    }
}

/*
 * Below implementations are outside of the scope of consensus, and thus not
 * required to be "exhaustive". We could replace much of this with the #[derive],
 * if the other components also want to adopt this.
 */

impl ExhaustiveSet for BitcoinReject {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(RejectCode, String)>::exhaustive_set(rng)
            .into_iter()
            .map(|(reject_code, message)| BitcoinReject {
                reject_code,
                message,
            })
            .collect()
    }
}

impl ExhaustiveSet for BitcoinAdapterResponseWrapper {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let blobs = <Vec<Vec<u8>>>::exhaustive_set(rng);
        let successors = blobs.into_iter().map(|blob| {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(GetSuccessorsResponseComplete {
                blocks: blob.clone(),
                next: blob,
            })
        });
        let transactions = std::iter::once(BitcoinAdapterResponseWrapper::SendTransactionResponse(
            SendTransactionResponse {},
        ));
        let rejects = BitcoinReject::exhaustive_set(rng)
            .into_iter()
            .enumerate()
            .map(|(i, reject)| {
                if i % 2 == 0 {
                    BitcoinAdapterResponseWrapper::GetSuccessorsReject(reject)
                } else {
                    BitcoinAdapterResponseWrapper::SendTransactionReject(reject)
                }
            });
        let result: Vec<_> = successors.chain(transactions).chain(rejects).collect();
        match &result[0] {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(_) => (),
            BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => (),
            BitcoinAdapterResponseWrapper::GetSuccessorsReject(_) => (),
            BitcoinAdapterResponseWrapper::SendTransactionReject(_) => (),
            // Any new variants should be inserted to `result` above!
        }
        result
    }
}

impl ExhaustiveSet for BitcoinAdapterResponse {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(BitcoinAdapterResponseWrapper, u64)>::exhaustive_set(rng)
            .into_iter()
            .map(|(response, callback_id)| BitcoinAdapterResponse {
                response,
                callback_id,
            })
            .collect()
    }
}

impl ExhaustiveSet for CryptoHash {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut data = [0; 32];
        rng.fill_bytes(&mut data);
        vec![Self(data.to_vec())]
    }
}

impl<T> ExhaustiveSet for BasicSigOf<T> {
    fn exhaustive_set<R: RngCore + CryptoRng>(_rng: &mut R) -> Vec<Self> {
        vec![BasicSigOf::new(BasicSig(vec![1, 2, 3]))]
    }
}

impl<T: ExhaustiveSet, U: ExhaustiveSet> ExhaustiveSet for Signed<T, BasicSignature<U>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(T, NodeId)>::exhaustive_set(rng)
            .into_iter()
            .map(|(content, signer)| Self {
                content,
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![1, 2, 3, 4, 5, 6])),
                    signer,
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, BasicSignatureBatch<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let signatures_map: BTreeMap<_, _> = NodeId::exhaustive_set(rng)
            .into_iter()
            .map(|id| (id, BasicSigOf::new(BasicSig(vec![1, 2, 3, 4, 5, 6]))))
            .collect();

        T::exhaustive_set(rng)
            .into_iter()
            .map(|content| Self {
                content,
                signature: BasicSignatureBatch {
                    signatures_map: signatures_map.clone(),
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, ThresholdSignature<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(T, NiDkgId)>::exhaustive_set(rng)
            .into_iter()
            .map(|(content, signer)| Self {
                content,
                signature: ThresholdSignature {
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![
                        1, 2, 3, 4, 5, 6,
                    ])),
                    signer,
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet, U: ExhaustiveSet> ExhaustiveSet for Signed<T, ThresholdSignatureShare<U>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(T, NodeId)>::exhaustive_set(rng)
            .into_iter()
            .map(|(content, signer)| Self {
                content,
                signature: ThresholdSignatureShare {
                    signature: ThresholdSigShareOf::new(ThresholdSigShare(vec![1, 2, 3, 4, 5, 6])),
                    signer,
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, MultiSignatureShare<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(T, NodeId)>::exhaustive_set(rng)
            .into_iter()
            .map(|(content, signer)| Self {
                content,
                signature: MultiSignatureShare {
                    signature: IndividualMultiSigOf::new(IndividualMultiSig(vec![
                        1, 2, 3, 4, 5, 6,
                    ])),
                    signer,
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, MultiSignature<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <(T, Vec<NodeId>)>::exhaustive_set(rng)
            .into_iter()
            .map(|(content, signers)| Self {
                content,
                signature: MultiSignature {
                    signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![1, 2, 3, 4, 5, 6])),
                    signers,
                },
            })
            .collect()
    }
}

impl ExhaustiveSet for NiDkgConfig {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec![NiDkgConfig::new(valid_dkg_config_data()).unwrap()]
    }
}

impl ExhaustiveSet for NiDkgTranscript {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let nodes = NodeId::exhaustive_set(rng);
        vec![NiDkgTranscript::dummy_transcript_for_tests_with_params(
            nodes,
            NiDkgTag::HighThreshold,
            1,
            rng.next_u32() as u64,
        )]
    }
}

impl ExhaustiveSet for NiDkgDealing {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        vec![NiDkgDealing::dummy_dealing_for_tests(rng.next_u32() as u8)]
    }
}

impl ExhaustiveSet for InitialIDkgDealings {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let dealers = BTreeSet::<NodeId>::exhaustive_set(rng);
        let mut receivers = BTreeSet::<NodeId>::exhaustive_set(rng)
            .into_iter()
            .find(|set| !set.is_empty())
            .unwrap();
        while !receivers.is_disjoint(&dealers[0]) {
            receivers = BTreeSet::<NodeId>::exhaustive_set(rng)
                .into_iter()
                .find(|set| !set.is_empty())
                .unwrap();
        }
        let mut previous_transcript = IDkgTranscript::exhaustive_set(rng)
            .into_iter()
            .find(|t| matches!(t.transcript_type, IDkgTranscriptType::Unmasked(_)))
            .unwrap();
        // Invariant: dealers need to be contained in previous receivers,
        // and the receivers need to be disjoint from the dealers (for XNet resharing, which is what
        // `InitialIdkgDealings::new` is used for).
        previous_transcript.receivers = IDkgReceivers::new(dealers[0].clone()).unwrap();
        let params = IDkgTranscriptParams::new(
            IDkgTranscriptId::exhaustive_set(rng).pop().unwrap(),
            dealers[0].clone(),
            receivers,
            RegistryVersion::exhaustive_set(rng).pop().unwrap(),
            AlgorithmId::ThresholdEcdsaSecp256k1,
            IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        )
        .unwrap();
        let dealings = dummy_dealings(params.transcript_id(), &dealers[0]);
        vec![Self::new(params, dealings).unwrap()]
    }
}

impl ExhaustiveSet for IDkgTranscriptParams {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let all_threshold_algs = AlgorithmId::all_threshold_ecdsa_algorithms()
            .into_iter()
            .chain(AlgorithmId::all_threshold_schnorr_algorithms())
            .collect::<Vec<_>>();
        <(IDkgTranscriptId, IDkgTranscriptOperation, RegistryVersion)>::exhaustive_set(rng)
            .into_iter()
            .enumerate()
            .map(|(i, (id, transcript, version))| {
                let node_ids = match &transcript {
                    IDkgTranscriptOperation::ReshareOfMasked(t)
                    | IDkgTranscriptOperation::ReshareOfUnmasked(t)
                    | IDkgTranscriptOperation::UnmaskedTimesMasked(t, _) => {
                        t.receivers.get().clone()
                    }
                    IDkgTranscriptOperation::Random | IDkgTranscriptOperation::RandomUnmasked => {
                        BTreeSet::<NodeId>::exhaustive_set(rng).pop().unwrap()
                    }
                };
                Self::new(
                    id,
                    node_ids.clone(),
                    node_ids.clone(),
                    version,
                    all_threshold_algs[all_threshold_algs.len() % i],
                    transcript,
                )
                .unwrap()
            })
            .collect()
    }
}

impl ExhaustiveSet for IDkgDealers {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let node_ids = BTreeSet::from(<[NodeId; 8]>::exhaustive_set(rng)[0]);
        vec![IDkgDealers::new(node_ids).unwrap()]
    }
}

impl ExhaustiveSet for IDkgReceivers {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let node_ids = BTreeSet::from(<[NodeId; 8]>::exhaustive_set(rng)[0]);
        vec![IDkgReceivers::new(node_ids).unwrap()]
    }
}

impl ExhaustiveSet for IDkgTranscriptOperation {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let transcripts = IDkgTranscript::exhaustive_set(rng);

        let mut masked = transcripts
            .iter()
            .find(|t| matches!(t.transcript_type, IDkgTranscriptType::Masked(_)))
            .unwrap()
            .clone();
        let unmasked = transcripts
            .iter()
            .find(|t| matches!(t.transcript_type, IDkgTranscriptType::Unmasked(_)))
            .unwrap()
            .clone();
        masked.receivers = unmasked.receivers.clone();

        let mut operations = transcripts
            .into_iter()
            .map(|t| match t.transcript_type {
                IDkgTranscriptType::Masked(_) => IDkgTranscriptOperation::ReshareOfMasked(t),
                IDkgTranscriptType::Unmasked(_) => IDkgTranscriptOperation::ReshareOfUnmasked(t),
            })
            .collect::<Vec<_>>();

        operations.append(&mut vec![
            IDkgTranscriptOperation::Random,
            IDkgTranscriptOperation::RandomUnmasked,
            IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked, masked),
        ]);

        match &operations[0] {
            IDkgTranscriptOperation::Random => (),
            IDkgTranscriptOperation::ReshareOfMasked(_) => (),
            IDkgTranscriptOperation::ReshareOfUnmasked(_) => (),
            IDkgTranscriptOperation::UnmaskedTimesMasked(_, _) => (),
            IDkgTranscriptOperation::RandomUnmasked => (),
            // Any new variants should be inserted to `operations` above!
        };

        operations
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DerivedQuadrupleInCreation {
    pub key_id: EcdsaKeyId,
    pub random_config: RandomTranscriptParams,
    pub random_unmasked_config: RandomUnmaskedTranscriptParams,
    pub reshare_config: ReshareOfMaskedParams,
    pub times_config: UnmaskedTimesMaskedParams,
    pub unmasked: UnmaskedTranscript,
    pub masked: MaskedTranscript,
}

impl ExhaustiveSet for QuadrupleInCreation {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut result = DerivedQuadrupleInCreation::exhaustive_set(rng)
            .into_iter()
            .map(|q| QuadrupleInCreation {
                key_id: q.key_id,
                lambda_config: q.random_config.clone(),
                lambda_masked: Some(q.masked),
                kappa_unmasked_config: q.random_unmasked_config.clone(),
                kappa_unmasked: Some(q.unmasked),
                key_times_lambda_config: Some(q.times_config.clone()),
                key_times_lambda: Some(q.masked),
                kappa_times_lambda_config: Some(q.times_config.clone()),
                kappa_times_lambda: Some(q.masked),
            })
            .collect::<Vec<_>>();

        result.push(QuadrupleInCreation {
            key_id: EcdsaKeyId::exhaustive_set(rng)[0].clone(),
            lambda_config: RandomTranscriptParams::exhaustive_set(rng)[0].clone(),
            lambda_masked: None,
            kappa_unmasked_config: RandomUnmaskedTranscriptParams::exhaustive_set(rng)[0].clone(),
            kappa_unmasked: None,
            key_times_lambda_config: None,
            key_times_lambda: None,
            kappa_times_lambda_config: None,
            kappa_times_lambda: None,
        });
        result
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DerivedIDkgPayload {
    pub signature_agreements: BTreeMap<PseudoRandomId, CompletedSignature>,
    pub available_pre_signatures: BTreeMap<PreSigId, PreSignatureRef>,
    pub pre_signatures_in_creation: BTreeMap<PreSigId, PreSignatureInCreation>,
    pub uid_generator: IDkgUIDGenerator,
    pub idkg_transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    pub ongoing_xnet_reshares: BTreeMap<IDkgReshareRequest, ReshareOfUnmaskedParams>,
    pub xnet_reshare_agreements: BTreeMap<IDkgReshareRequest, CompletedReshareRequest>,
    pub key_transcripts: BTreeMap<MasterPublicKeyId, MasterKeyTranscript>,
}

impl ExhaustiveSet for IDkgPayload {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        DerivedIDkgPayload::exhaustive_set(rng)
            .into_iter()
            .map(|payload| IDkgPayload {
                signature_agreements: payload.signature_agreements,
                available_pre_signatures: payload.available_pre_signatures,
                pre_signatures_in_creation: payload.pre_signatures_in_creation,
                uid_generator: payload.uid_generator,
                idkg_transcripts: payload.idkg_transcripts,
                ongoing_xnet_reshares: payload.ongoing_xnet_reshares,
                xnet_reshare_agreements: payload.xnet_reshare_agreements,
                key_transcripts: replace_by_singleton_if_empty(payload.key_transcripts, rng),
            })
            .collect()
    }
}

// taken from crypto/test_utils/../dummy_values.rs
fn dummy_dealings(
    transcript_id: IDkgTranscriptId,
    dealers: &BTreeSet<NodeId>,
) -> Vec<SignedIDkgDealing> {
    let mut dealings = Vec::new();
    for node_id in dealers {
        let signed_dealing = SignedIDkgDealing {
            content: IDkgDealing {
                transcript_id,
                internal_dealing_raw: format!("Dummy raw dealing for dealer {}", node_id)
                    .into_bytes(),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![1, 2, 3, 4])),
                signer: *node_id,
            },
        };
        dealings.push(signed_dealing);
    }
    dealings
}

/// If the map is empty generates a single key-value pair and returns it.
fn replace_by_singleton_if_empty<
    K: ExhaustiveSet + std::cmp::Ord,
    V: ExhaustiveSet + HasId<K>,
    R: RngCore + CryptoRng,
>(
    collection: BTreeMap<K, V>,
    rng: &mut R,
) -> BTreeMap<K, V> {
    if !collection.is_empty() {
        return collection;
    }

    let value = V::exhaustive_set(rng)
        .first()
        .expect("There should be at least one element")
        .clone();
    let key = value.get_id().unwrap_or_else(|| {
        K::exhaustive_set(rng)
            .first()
            .expect("There should be at least one element")
            .clone()
    });

    BTreeMap::from([(key, value)])
}

/// Some maps of the form Map<Id, (Id, Data)> are serialized as vectors of their values, throwing
/// all keys away. During deserialization, the key is then re-extracted from the value. By default,
/// `Exhaustive` will generate different keys independent of values, meaning a serialization round-
/// trip will change the data. To avoid this, this trait allows generating the Id from the Value.
trait HasId<T> {
    fn get_id(&self) -> Option<T> {
        None
    }
}

impl HasId<NiDkgId> for NiDkgConfig {
    fn get_id(&self) -> Option<NiDkgId> {
        Some(self.dkg_id())
    }
}
impl HasId<IDkgTranscriptId> for IDkgTranscript {
    fn get_id(&self) -> Option<IDkgTranscriptId> {
        Some(self.transcript_id)
    }
}
impl HasId<IDkgReshareRequest> for ReshareOfUnmaskedParams {}
impl HasId<PseudoRandomId> for CompletedSignature {}
impl HasId<IDkgReshareRequest> for CompletedReshareRequest {}
impl HasId<NodeIndex> for BatchSignedIDkgDealing {}
impl HasId<SubnetId> for CertifiedStreamSlice {}
impl HasId<NiDkgTag> for NiDkgTranscript {}
impl HasId<NiDkgTargetId> for u32 {}
impl HasId<RequestId> for ThresholdEcdsaSigInputsRef {}
impl HasId<PreSigId> for PreSignatureInCreation {}
impl HasId<PreSigId> for PreSignatureRef {}

impl HasId<MasterPublicKeyId> for MasterKeyTranscript {
    fn get_id(&self) -> Option<MasterPublicKeyId> {
        Some(self.key_id())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    use crate::consensus::ConsensusMessage;

    use super::*;

    const CUP_COMPATIBILITY_TEST_PATH: &str = "cup_compatibility_test";

    /// Serialize the set of [`CatchUpContent`]s to [`CUP_COMPATIBILITY_TEST_PATH`].
    /// Test is ignored as it should only be used by system or manual tests.
    #[ignore]
    #[test]
    fn serialize() {
        let directory = PathBuf::from(CUP_COMPATIBILITY_TEST_PATH);
        fs::create_dir(&directory).expect("Failed to create directory");
        let set = CatchUpContent::exhaustive_set(&mut reproducible_rng());
        println!("Number of CUP content variants: {}", set.len());

        for (i, cup) in set.into_iter().enumerate() {
            assert!(cup.check_integrity(), "Integrity check failed");
            let bytes = pb::CatchUpContent::from(&cup).encode_to_vec();
            let file_path = directory.join(format!("{i}.pb"));
            fs::write(file_path, bytes).expect("Failed to write bytes");
        }
    }

    /// Deserialize all [`CatchUpContent`]s found in [`CUP_COMPATIBILITY_TEST_PATH`].
    /// Test is ignored as it should only be used by system or manual tests.
    #[ignore]
    #[test]
    fn deserialize() {
        let directory = PathBuf::from(CUP_COMPATIBILITY_TEST_PATH);
        let entries = fs::read_dir(directory).expect("Failed to read test directory");

        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = fs::read(&path).expect("Failed to read file");
                let proto_cup =
                    pb::CatchUpContent::decode(bytes.as_slice()).expect("Failed to decode bytes");
                let cup =
                    CatchUpContent::try_from(proto_cup).expect("Failed to deserialize CUP content");
                if !cup.check_integrity() {
                    panic!(
                        "Integrity check of file {path:?} failed. Payload: {:?}",
                        cup.block.as_ref().payload.as_ref()
                    );
                }
            }
        }
    }

    #[test]
    fn verify_exhaustive_cup() {
        let set = CatchUpPackage::exhaustive_set(&mut reproducible_rng());
        println!("Number of CUP content variants: {}", set.len());
        for cup in &set {
            assert!(cup.check_integrity());
            // serialize -> deserialize round-trip
            let bytes = pb::CatchUpPackage::from(cup).encode_to_vec();
            let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).unwrap();
            let new_cup = CatchUpPackage::try_from(&proto_cup).unwrap();

            assert!(new_cup.check_integrity());
            assert_eq!(
                cup, &new_cup,
                "deserialized block is different from original"
            );
        }
    }

    #[test]
    fn verify_exhaustive_consensus_message() {
        let set = ConsensusMessage::exhaustive_set(&mut reproducible_rng());
        println!("Number of consensus message variants: {}", set.len());
        for msg in &set {
            // serialize -> deserialize round-trip
            let bytes = pb::ConsensusMessage::from(msg.clone()).encode_to_vec();
            let proto_msg = pb::ConsensusMessage::decode(bytes.as_slice()).unwrap();
            let new_msg = ConsensusMessage::try_from(proto_msg).unwrap();

            assert_eq!(
                msg, &new_msg,
                "deserialized consensus message is different from original"
            );
        }
    }

    /// Check if the BTreeMap implementation produces a correct minimal exhaustive set.
    #[test]
    fn check_impl_btreemap() {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ExhaustiveSet)]
        enum Small {
            A,
            B,
        }
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ExhaustiveSet)]
        enum Big {
            X,
            Y,
            Z,
        }
        impl HasId<Small> for Big {}
        impl HasId<Big> for Small {}
        let set = BTreeMap::<Small, Big>::exhaustive_set(&mut rand::thread_rng());
        assert_eq!(set.len(), 3);
        assert_eq!(set[0][&Small::A], Big::X);
        assert_eq!(set[0][&Small::B], Big::Y);
        assert_eq!(set[1][&Small::A], Big::Z);
        assert!(set[2].is_empty());

        let set = BTreeMap::<Big, Small>::exhaustive_set(&mut rand::thread_rng());
        assert_eq!(set.len(), 2);
        assert_eq!(set[0][&Big::X], Small::A);
        assert_eq!(set[0][&Big::Y], Small::B);
        assert_eq!(set[0][&Big::Z], Small::A);
        assert!(set[1].is_empty());
    }

    /// Check if named enum fields produce correct result
    #[test]
    fn derive_named_enum_field() {
        #[derive(Debug, Clone, PartialEq, Eq, ExhaustiveSet)]
        enum Enum1 {
            V1 { first: Enum2, second: Enum2 },
            V2,
        }
        #[derive(Debug, Clone, PartialEq, Eq, ExhaustiveSet)]
        enum Enum2 {
            A1,
            A2,
        }
        let set = Enum1::exhaustive_set(&mut rand::thread_rng());
        assert_eq!(set.len(), 3);
        assert_eq!(set[0], Enum1::V2);
        assert_eq!(
            set[1],
            Enum1::V1 {
                first: Enum2::A1,
                second: Enum2::A1
            }
        );
        assert_eq!(
            set[2],
            Enum1::V1 {
                first: Enum2::A2,
                second: Enum2::A2
            }
        );
    }
}
