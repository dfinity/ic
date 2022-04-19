use rand::{thread_rng, Rng};
use serde::Serialize;

use ic_crypto_internal_threshold_sig_bls12381::api::{
    combine_signatures, combined_public_key, keygen, sign_message,
};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_tree_hash::{
    flatmap, Digest, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, MixedHashTree,
    WitnessGenerator,
};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_interfaces::crypto::Signable;
use ic_types::messages::Blob;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CryptoHash},
    crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    CanisterId, CryptoHashOfPartialState, NumberOfNodes, Randomness, SubnetId,
};

const REPLICA_TIME: u64 = 1234567;

#[derive(serde::Serialize)]
pub struct Certificate {
    tree: MixedHashTree,
    signature: Blob,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<CertificateDelegation>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct CertificateDelegation {
    pub subnet_id: Blob,
    pub certificate: Blob,
}

#[derive(Debug, Clone)]
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
        let mut encoded_time = vec![];
        leb128::write::unsigned(&mut encoded_time, time.unwrap_or(REPLICA_TIME)).unwrap();
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

#[derive(Debug, Clone)]
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
        let mut seed: [u8; 32] = [0; 32];
        thread_rng().fill(&mut seed);

        let (public_coefficients, secret_key_bytes) =
            keygen(Randomness::from(seed), NumberOfNodes::new(1), &[true; 1]).unwrap();
        let public_key = ThresholdSigPublicKey::from(CspThresholdSigPublicKey::from(
            combined_public_key(&public_coefficients).unwrap(),
        ));

        CertificateBuilder {
            public_key,
            secret_key: secret_key_bytes.get(0).unwrap().unwrap(),
            data,
            delegatee_pub_key: None,
            override_sig: None,
            subnet_id: None,
            delegation: None,
            time: None,
        }
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
        panic!("No subnet_id present. Either set a delegation with SubnetData or set the subnet_id manually using 'with_subnet_id'")
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

fn serialize_to_cbor<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    payload.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

fn hash_full_tree(b: &mut HashTreeBuilderImpl, t: &LabeledTree<Vec<u8>>) {
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
