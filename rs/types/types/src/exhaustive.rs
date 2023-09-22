//! Implementations and serialization tests of the ExhaustiveSet trait

use crate::consensus::{ecdsa::IDkgTranscriptAttributes, Block, BlockPayload};
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation,
    IDkgTranscriptParams, IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin, InitialIDkgDealings,
    SignedIDkgDealing,
};
use crate::crypto::threshold_sig::ni_dkg::{
    config::{tests::valid_dkg_config_data, NiDkgConfig},
    NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet, NiDkgTranscript,
};
use crate::crypto::{
    crypto_hash, AlgorithmId, BasicSig, BasicSigOf, CombinedThresholdSig, CombinedThresholdSigOf,
    CryptoHash, Signed,
};
use crate::signature::{BasicSignature, BasicSignatureBatch, ThresholdSignature};
use crate::{Height, ReplicaVersion};
use ic_base_types::{CanisterId, NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_btc_types_internal::{BitcoinAdapterResponse, BitcoinAdapterResponseWrapper};
use ic_crypto_test_utils_canister_threshold_sigs::random_node_id_excluding;
use ic_error_types::RejectCode;
use ic_exhaustive_derive::ExhaustiveSet;
use ic_ic00_types::{EcdsaCurve, EcdsaKeyId};
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
        vec![set]
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
            // populate array with cylic iterator
            let elem = std::array::from_fn::<T, N, _>(|_| exhaust_iter.next().unwrap().clone());

            result.push(elem);
        }
        result
    }
}

impl ExhaustiveSet for () {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec![()]
    }
}

impl ExhaustiveSet for String {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        vec!["0123abcd!@#$.,;()[]<>".to_string()]
    }
}

macro_rules! impl_for_integer {
    ($t: ty) => {
        impl ExhaustiveSet for $t {
            fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
                let val = rng.next_u64();
                vec![<$t>::MAX, val as $t]
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

impl<K: ExhaustiveSet + std::cmp::Ord, V: ExhaustiveSet> ExhaustiveSet for BTreeMap<K, V> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let k_set = K::exhaustive_set(rng);
        let v_set = V::exhaustive_set(rng);

        let mut result = Vec::new();
        let mut i = 0;
        let mut map = BTreeMap::new();
        for v in v_set.into_iter() {
            map.insert(k_set[i].clone(), v);
            i += 1;
            // if we've exceeded the available keys, we push the map to our result vector
            // and start populating a new clean map. We can't use the cyclic iterator
            // pattern because keys are deduplicated in maps.
            if i % k_set.len() == 0 {
                i = 0;
                result.push(map.clone());
                map.clear();
            }
        }
        if !map.is_empty() {
            result.push(map.clone());
        }
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
            .map(|id| CanisterId::new(id).unwrap())
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

/*
 * Below implementations are outside of the scope of consensus, and thus not
 * required to be "exhaustive". We could replace much of this with the #[derive],
 * if the other components also want to adopt this.
 */

impl ExhaustiveSet for BitcoinAdapterResponse {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        vec![BitcoinAdapterResponse {
            response: BitcoinAdapterResponseWrapper::SendTransactionResponse(
                ic_btc_types_internal::SendTransactionResponse {},
            ),
            callback_id: rng.next_u32() as u64,
        }]
    }
}

impl ExhaustiveSet for CryptoHash {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let mut data = [0; 32];
        rng.fill_bytes(&mut data);
        vec![Self(data.to_vec())]
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, BasicSignature<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let node_id = NodeId::exhaustive_set(rng).pop().unwrap();
        T::exhaustive_set(rng)
            .into_iter()
            .map(|t| Self {
                content: t,
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![1, 2, 3, 4, 5, 6])),
                    signer: node_id,
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
            .map(|t| Self {
                content: t,
                signature: BasicSignatureBatch {
                    signatures_map: signatures_map.clone(),
                },
            })
            .collect()
    }
}

impl<T: ExhaustiveSet> ExhaustiveSet for Signed<T, ThresholdSignature<T>> {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let nidkg_id = NiDkgId::exhaustive_set(rng).pop().unwrap();
        T::exhaustive_set(rng)
            .into_iter()
            .map(|t| Self {
                content: t,
                signature: ThresholdSignature {
                    signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![
                        1, 2, 3, 4, 5, 6,
                    ])),
                    signer: nidkg_id,
                },
            })
            .collect()
    }
}

impl ExhaustiveSet for NiDkgTargetId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        <[u8; NiDkgTargetId::SIZE]>::exhaustive_set(rng)
            .into_iter()
            .map(|elem| NiDkgTargetId::new(elem))
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

impl ExhaustiveSet for NiDkgTag {
    fn exhaustive_set<R: RngCore + CryptoRng>(_: &mut R) -> Vec<Self> {
        NiDkgTag::iter().collect()
    }
}

impl ExhaustiveSet for NiDkgDealing {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        vec![NiDkgDealing::dummy_dealing_for_tests(rng.next_u32() as u8)]
    }
}

impl ExhaustiveSet for NiDkgId {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        vec![NiDkgId {
            start_block_height: Height::exhaustive_set(rng).pop().unwrap(),
            dealer_subnet: SubnetId::exhaustive_set(rng).pop().unwrap(),
            dkg_tag: crate::crypto::threshold_sig::ni_dkg::NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        }]
    }
}

impl ExhaustiveSet for InitialIDkgDealings {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let dealers = BTreeSet::<NodeId>::exhaustive_set(rng);
        let mut receivers = BTreeSet::<NodeId>::exhaustive_set(rng).pop().unwrap();
        while !receivers.is_disjoint(&dealers[0]) {
            receivers = BTreeSet::<NodeId>::exhaustive_set(rng).pop().unwrap();
        }
        let mut previous_transcript = IDkgTranscript::exhaustive_set(rng).pop().unwrap();
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

impl ExhaustiveSet for IDkgTranscriptAttributes {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let tecdsa_algo = AlgorithmId::ThresholdEcdsaSecp256k1;
        let node_ids: BTreeSet<_> = (0..10)
            .map(|_| random_node_id_excluding(&BTreeSet::new(), rng))
            .collect();
        let registry_versions = RegistryVersion::exhaustive_set(rng);
        let mut result = Vec::new();
        for reg in registry_versions {
            result.push(Self::new(node_ids.clone(), tecdsa_algo, reg));
        }
        result
    }
}

impl ExhaustiveSet for IDkgTranscript {
    fn exhaustive_set<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Self> {
        let idkg_id = IDkgTranscriptId::exhaustive_set(rng);
        let t = IDkgTranscript {
            transcript_id: idkg_id[0],
            receivers: IDkgReceivers::new(BTreeSet::<NodeId>::exhaustive_set(rng).pop().unwrap())
                .unwrap(),
            registry_version: RegistryVersion::exhaustive_set(rng)[1],
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(idkg_id[1]),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: Vec::<u8>::exhaustive_set(rng).pop().unwrap(),
        };
        vec![t]
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

#[test]
fn verify_exhaustive_block() {
    let set = Block::exhaustive_set(&mut rand::thread_rng());
    println!("number of block variants: {}", set.len());
    for block in &set {
        // serialize & encode the block
        let bytes = pb::Block::from(block).encode_to_vec();

        // flip bits and check that conversion fails
        let tampered_bytes = bytes
            .iter()
            .enumerate()
            .map(|(idx, byte)| byte ^ (idx as u8))
            .collect::<Vec<_>>();
        assert!(pb::Block::decode(tampered_bytes.as_slice()).is_err());

        // decode the untampered bytes
        let proto_block = pb::Block::decode(bytes.as_slice()).unwrap();
        // deserialize the block
        let new_block = Block::try_from(proto_block).unwrap();

        assert_eq!(
            block, &new_block,
            "deserialized block is different from original"
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
    let set = BTreeMap::<Small, Big>::exhaustive_set(&mut rand::thread_rng());
    assert_eq!(set.len(), 2);
    assert_eq!(set[0][&Small::A], Big::X);
    assert_eq!(set[0][&Small::B], Big::Y);
    assert_eq!(set[1][&Small::A], Big::Z);
}
