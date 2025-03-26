use ic_certification_test_utils::{hash_full_tree, CertificateBuilder, CertificateData};
use ic_crypto_sha2::Sha256;
use ic_crypto_tree_hash::{
    flatmap, Digest, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, MixedHashTree,
    WitnessGenerator,
};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use rand::{CryptoRng, Rng, RngCore};

pub struct CanisterCertificate {
    pub root_pk: ThresholdSigPublicKey,
    /// CBOR-encoded certificate
    pub cbor: Vec<u8>,
    /// Witness for the signature (see [`new_random_canister_state`])
    pub witness: MixedHashTree,
    pub seed: Vec<u8>,
    pub msg: Vec<u8>,
    pub canister_id: CanisterId,
}

/// Returns a random certificate generated using using `rng`.
/// Depending on the `with_delegation` flag, the certificate
/// will contain a subnet delegation.
pub fn new_random_cert<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    with_delegation: bool,
) -> CanisterCertificate {
    let canister_state = new_random_canister_state(rng);
    const CANISTER_ID: CanisterId = canister_id(1);
    let cert_builder = CertificateBuilder::new_with_rng(
        CertificateData::CanisterData {
            canister_id: CANISTER_ID,
            certified_data: canister_state.root_digest,
        },
        rng,
    );

    let cert_builder = conditionally_add_delegation_cert(cert_builder, with_delegation, rng);
    let (_cert, root_pk, cert_cbor) = cert_builder.build();

    CanisterCertificate {
        root_pk,
        cbor: cert_cbor,
        witness: canister_state.witness,
        seed: canister_state.seed,
        msg: canister_state.msg,
        canister_id: CANISTER_ID,
    }
}

fn conditionally_add_delegation_cert<R: Rng + CryptoRng>(
    cert_builder: CertificateBuilder,
    with_delegation: bool,
    rng: &mut R,
) -> CertificateBuilder {
    if with_delegation {
        cert_builder.with_delegation(CertificateBuilder::new_with_rng(
            CertificateData::SubnetData {
                subnet_id: subnet_id(123),
                canister_id_ranges: vec![(canister_id(0), canister_id(10))],
            },
            rng,
        ))
    } else {
        cert_builder
    }
}

pub struct CanisterState {
    /// Public key seed
    pub seed: Vec<u8>,
    /// Signed message
    pub msg: Vec<u8>,
    /// Witness s.t. lookup(`/sig/<seed_hash>/<msg_hash>`) = Found("")
    pub witness: MixedHashTree,
    /// Root hash of the canister state's tree
    pub root_digest: Digest,
}

/// Creates a canister state with a valid path `/sig/<seed_hash>/<msg_hash>`, where
/// <seed_hash> is SHA256 of a randomly generated seed and <msg_hash> of a randomly
/// generated message.
fn new_random_canister_state<R: Rng + RngCore + CryptoRng>(rng: &mut R) -> CanisterState {
    let canister_sig_seed = random_bytes(rng, 32);
    let canister_sig_message = random_bytes(rng, 32);
    let canister_state_tree =
        new_canister_state_tree(&canister_sig_seed[..], &canister_sig_message[..]);
    let mixed_tree = witness_from_tree(canister_state_tree);
    let hash_tree_digest = mixed_tree.digest();

    CanisterState {
        seed: canister_sig_seed,
        msg: canister_sig_message,
        witness: mixed_tree,
        root_digest: hash_tree_digest,
    }
}

pub fn witness_from_tree(tree: LabeledTree<Vec<u8>>) -> MixedHashTree {
    let mut b = HashTreeBuilderImpl::new();
    hash_full_tree(&mut b, &tree);
    let witness_gen = b.witness_generator().unwrap();
    witness_gen.mixed_hash_tree(&tree).unwrap()
}

fn random_bytes<R: Rng + RngCore + CryptoRng>(rng: &mut R, size: usize) -> Vec<u8> {
    let mut buffer = vec![0; size];
    rng.fill(&mut buffer[..]);
    buffer
}

pub fn new_canister_state_tree(
    canister_sig_seed: &[u8],
    canister_sig_message: &[u8],
) -> LabeledTree<Vec<u8>> {
    let seed_hash = Sha256::hash(canister_sig_seed);
    let msg_hash = Sha256::hash(canister_sig_message);

    LabeledTree::SubTree(flatmap![
        Label::from("sig") => LabeledTree::SubTree(flatmap![
            Label::from(seed_hash.to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from(msg_hash.to_vec()) => LabeledTree::Leaf(vec![]),
                ]),
        ]),
    ])
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}
