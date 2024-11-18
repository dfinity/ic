use ic_crypto_internal_seed::Seed;
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use serde::Serialize;

use ic_crypto_internal_threshold_sig_bls12381::api::{
    combine_signatures, combined_public_key, generate_threshold_key, sign_message,
};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_tree_hash::{
    flatmap, Digest, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, MixedHashTree,
    WitnessGenerator,
};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_types::messages::Blob;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::Signable,
    crypto::{threshold_sig::ThresholdSigPublicKey, CryptoHash},
    crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    CanisterId, CryptoHashOfPartialState, NumberOfNodes, SubnetId,
};

const REPLICA_TIME: u64 = 1234567;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Certificate {
    tree: MixedHashTree,
    signature: Blob,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<CertificateDelegation>,
}

impl Certificate {
    pub fn tree(&self) -> MixedHashTree {
        self.tree.clone()
    }

    pub fn signature(&self) -> Blob {
        self.signature.clone()
    }

    pub fn delegation(&self) -> Option<CertificateDelegation> {
        self.delegation.clone()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CertificateDelegation {
    pub subnet_id: Blob,
    pub certificate: Blob,
}

#[derive(Clone, Debug)]
pub enum CertificateData {
    CustomTree(LabeledTree<Vec<u8>>),
    CanisterData {
        canister_id: CanisterId,
        certified_data: Digest,
    },
    SubnetData {
        subnet_id: SubnetId,
        canister_id_ranges: Vec<(CanisterId, CanisterId)>,
    },
}

impl CertificateData {
    fn get_tree(
        &self,
        subnet_pub_key: Option<ThresholdSigPublicKey>,
        time: Option<u64>,
    ) -> LabeledTree<Vec<u8>> {
        let encoded_time = encoded_time(time.unwrap_or(REPLICA_TIME));
        match self {
            CertificateData::CustomTree(tree) => tree.clone(),
            CertificateData::CanisterData {
                canister_id,
                certified_data,
            } => LabeledTree::SubTree(flatmap![
                Label::from("canister") => LabeledTree::SubTree(flatmap![
                    Label::from(canister_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                        Label::from("certified_data") => LabeledTree::Leaf(certified_data.to_vec()),
                    ])
                ]),
                Label::from("time") => LabeledTree::Leaf(encoded_time)
            ]),
            CertificateData::SubnetData {
                subnet_id,
                canister_id_ranges,
            } => {
                let public_key = subnet_pub_key.expect("no delegation public_key. Note: Subnet data cannot be used at the lowest certificate level");
                LabeledTree::SubTree(flatmap![
                    Label::from("subnet") => LabeledTree::SubTree(flatmap![
                        Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(canister_id_ranges)),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&public_key.into_bytes()).unwrap()),
                        ])
                    ]),
                    Label::from("time") => LabeledTree::Leaf(encoded_time)
                ])
            }
        }
    }
}

#[derive(Clone, Debug)]
/// A `CertificateBuilder` can be used to construct a valid certificate with an
/// optional delegation, if the signing subnet is not the root subnet.
///
/// An example of building a certificate:
///
/// ```compile_fail
/// use ic_certification_test_utils::{CertificateBuilder, CertificateData};
/// use ic_crypto_tree_hash::Digest;
///
/// let (_cert, _pk, _cbor) = CertificateBuilder::new(CertificateData::CanisterData {
///     canister_id: canister_test_id(1),
///     certified_data: Digest::try_from(vec![42; 32]).unwrap(),
/// })
/// .with_delegation(CertificateBuilder::new(CertificateData::SubnetData {
///     subnet_id: subnet_test_id(1),
///     canister_id_ranges: vec![(canister_test_id(0), canister_test_id(10))],
/// }))
/// .build();
/// ```
///
/// The builder returns the certificate (with the optional delegation), the
/// public root key (which can be used for verification purposes) and finally
/// a CBOR encoded version of the certificate.
///
/// The outer builder should contain the data you're interested in certifying
/// while the nested builder should contain the `SubnetData` signaling which
/// canister ranges the subnet is delegated to sign for by the root of trust.
/// In this example, some dummy `CanisterData` is certified but anything
/// could be used, e.g. a custom hash tree.
pub struct CertificateBuilder {
    public_key: ThresholdSigPublicKey,
    secret_key: SecretKeyBytes,
    data: CertificateData,
    override_sig: Option<CombinedThresholdSig>,
    delegatee_pub_key: Option<ThresholdSigPublicKey>,
    subnet_id: Option<SubnetId>,
    delegation: Option<Box<CertificateBuilder>>,
    time: Option<u64>,
}

impl CertificateBuilder {
    pub fn new(data: CertificateData) -> Self {
        Self::new_with_rng(data, &mut thread_rng())
    }

    pub fn new_with_rng<R: Rng + RngCore + CryptoRng>(data: CertificateData, rng: &mut R) -> Self {
        let (public_key, secret_key) = generate_root_of_trust(rng);

        CertificateBuilder {
            public_key,
            secret_key,
            data,
            delegatee_pub_key: None,
            override_sig: None,
            subnet_id: None,
            delegation: None,
            time: None,
        }
    }

    pub fn with_root_of_trust(
        mut self,
        public_key: ThresholdSigPublicKey,
        secret_key: SecretKeyBytes,
    ) -> Self {
        self.public_key = public_key;
        self.secret_key = secret_key;
        self
    }

    pub fn with_time(mut self, time: u64) -> Self {
        self.time = Some(time);
        self
    }

    pub fn with_delegation_subnet_id(mut self, subnet_id: SubnetId) -> Self {
        self.subnet_id = Some(subnet_id);
        self
    }

    pub fn with_invalid_sig(mut self) -> Self {
        self.override_sig = Some(CombinedThresholdSig(
            b"invalid sig -----padding to get to 48 bytes-----".to_vec(),
        ));
        self
    }

    pub fn with_sig(mut self, sig: CombinedThresholdSig) -> Self {
        self.override_sig = Some(sig);
        self
    }

    pub fn with_delegation(mut self, mut delegation_builder: CertificateBuilder) -> Self {
        delegation_builder.delegatee_pub_key = Some(self.public_key);
        self.delegation = Some(Box::from(delegation_builder));
        self
    }

    pub fn get_root_public_key(&self) -> ThresholdSigPublicKey {
        match &self.delegation {
            None => self.public_key,
            Some(delegation) => delegation.get_root_public_key(),
        }
    }

    /// Builds the certificate given this builder.
    /// # Returns
    /// a tuple of (Certificate, ThresholdSigPublicKey, Vec<u8> containing the cbor encoded certificate)
    pub fn build(&self) -> (Certificate, ThresholdSigPublicKey, Vec<u8>) {
        let mut b = HashTreeBuilderImpl::new();
        let tree = &self.data.get_tree(self.delegatee_pub_key, self.time);
        hash_full_tree(&mut b, tree);

        let witness_gen = b.witness_generator().unwrap();
        let hash_tree_digest = witness_gen.hash_tree().digest();
        let mixed_tree = witness_gen.mixed_hash_tree(tree).unwrap();
        let root_hash = CryptoHashOfPartialState::from(CryptoHash(hash_tree_digest.to_vec()));

        let sig = if let Some(override_sig) = &self.override_sig {
            CombinedThresholdSigOf::from(override_sig.clone())
        } else {
            self.sign(&CertificationContent::new(root_hash))
        };

        let certificate = Certificate {
            tree: mixed_tree,
            signature: Blob(sig.get().0),
            delegation: self.build_delegation(),
        };
        let cert_cbor = serialize_to_cbor(&certificate);
        (certificate, self.get_root_public_key(), cert_cbor)
    }

    fn sign<T: Signable>(&self, message: &T) -> CombinedThresholdSigOf<T> {
        let signature_bytes =
            Some(sign_message(message.as_signed_bytes().as_slice(), &self.secret_key).unwrap());
        let signature = combine_signatures(&[signature_bytes], NumberOfNodes::new(1)).unwrap();
        CombinedThresholdSigOf::from(CombinedThresholdSig(signature.0.to_vec()))
    }

    fn get_subnet_id(&self) -> SubnetId {
        if let Some(subnet_id) = self.subnet_id {
            return subnet_id;
        }
        if let Some(delegation_builder) = &self.delegation {
            if let CertificateData::SubnetData { subnet_id, .. } = delegation_builder.data {
                return subnet_id;
            }
        }
        panic!("No subnet_id present. Either set a delegation with SubnetData or set the subnet_id manually using 'with_delegation_subnet_id'")
    }

    fn build_delegation(&self) -> Option<CertificateDelegation> {
        self.delegation
            .as_ref()
            .map(|builder| builder.build())
            .map(|(cert, _, _)| CertificateDelegation {
                certificate: Blob(serialize_to_cbor(&cert)),
                subnet_id: Blob(self.get_subnet_id().get().to_vec()),
            })
    }
}

pub fn generate_root_of_trust<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (ThresholdSigPublicKey, SecretKeyBytes) {
    let mut seed: [u8; 32] = [0; 32];
    rng.fill(&mut seed);

    let (public_coefficients, secret_key_bytes) = generate_threshold_key(
        Seed::from_bytes(&seed),
        NumberOfNodes::new(1),
        NumberOfNodes::new(1),
    )
    .unwrap();
    let public_key = ThresholdSigPublicKey::from(CspThresholdSigPublicKey::from(
        combined_public_key(&public_coefficients).unwrap(),
    ));
    (public_key, secret_key_bytes.first().unwrap().clone())
}

pub fn serialize_to_cbor<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    payload.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

pub fn encoded_time(time: u64) -> Vec<u8> {
    let mut encoded_time = vec![];
    leb128::write::unsigned(&mut encoded_time, time).unwrap();
    encoded_time
}

pub fn hash_full_tree(b: &mut HashTreeBuilderImpl, t: &LabeledTree<Vec<u8>>) {
    match t {
        LabeledTree::Leaf(bytes) => {
            b.start_leaf();
            b.write_leaf(&bytes[..]);
            b.finish_leaf();
        }
        LabeledTree::SubTree(map) => {
            b.start_subtree();
            for (l, child) in map.iter() {
                b.new_edge(l.clone());
                hash_full_tree(b, child);
            }
            b.finish_subtree();
        }
    }
}
