//! Utilities for testing canister signature operations.

use std::sync::Arc;

use ic_certification_test_utils::CertificateData::{CanisterData, SubnetData};
use ic_certification_test_utils::{hash_full_tree, CertificateBuilder};
use ic_crypto_internal_basic_sig_iccsa::types::Signature;
use ic_crypto_sha::Sha256;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
use ic_crypto_tree_hash::{
    flatmap, Digest, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, MixedHashTree,
    WitnessGenerator,
};
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_crypto_threshold_signing_pubkey_key, ROOT_SUBNET_ID_KEY};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::{
    threshold_sig::ThresholdSigPublicKey, AlgorithmId, CanisterSig, CanisterSigOf, SignableMock,
    UserPublicKey,
};
use ic_types::messages::Blob;
use ic_types::RegistryVersion;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use ic_types_test_utils::ids::SUBNET_1;
use rand::{CryptoRng, Rng, RngCore};

const GLOBAL_CANISTER_ID: CanisterId = canister_id(1);
const ROOT_SUBNET_ID: SubnetId = SUBNET_1;

pub struct CanisterSigTestData {
    pub crypto: TempCryptoComponent,
    pub msg: SignableMock,
    pub canister_sig: CanisterSigOf<SignableMock>,
    pub canister_pk: UserPublicKey,
    pub root_pk: ThresholdSigPublicKey,
}

/// Initializes an environment for benchmarking or testing canister signature verification.
/// The message, seed and keys are randomly generated based on the randomness from `rng`.
pub fn new_valid_sig_and_crypto_component<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    reg_ver: RegistryVersion,
    with_delegation: bool,
) -> CanisterSigTestData {
    let cert = new_random_cert(rng, with_delegation);
    let temp_crypto = temp_crypto_with_registry_with_root_pubkey(cert.root_pk, reg_ver);

    let signable_msg = SignableMock {
        domain: vec![],
        signed_bytes_without_domain: cert.msg,
    };
    let sig_with_canister_witness = Signature {
        certificate: Blob(cert.cbor),
        tree: cert.witness,
    };
    let canister_sig = CanisterSigOf::from(CanisterSig(encode_sig(sig_with_canister_witness)));
    let canister_pk = derive_canister_pk(&cert.seed[..]);
    CanisterSigTestData {
        crypto: temp_crypto,
        msg: signable_msg,
        canister_sig,
        canister_pk,
        root_pk: cert.root_pk,
    }
}

struct CanisterState {
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

fn random_bytes<R: Rng + RngCore + CryptoRng>(rng: &mut R, size: usize) -> Vec<u8> {
    let mut buffer = vec![0; size];
    rng.fill(&mut buffer[..]);
    buffer
}

fn new_canister_state_tree(
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

fn witness_from_tree(tree: LabeledTree<Vec<u8>>) -> MixedHashTree {
    let mut b = HashTreeBuilderImpl::new();
    hash_full_tree(&mut b, &tree);
    let witness_gen = b.witness_generator().unwrap();
    witness_gen.mixed_hash_tree(&tree).unwrap()
}

fn encode_sig(sig: Signature) -> Vec<u8> {
    let cbor_tag = vec![0xd9, 0xd9, 0xf7];
    cbor_tag
        .into_iter()
        .chain(serde_cbor::to_vec::<Signature>(&sig).unwrap().into_iter())
        .collect()
}

fn derive_canister_pk(canister_seed: &[u8]) -> UserPublicKey {
    let public_key_bytes = canister_sig_pub_key_to_bytes(GLOBAL_CANISTER_ID, canister_seed);

    UserPublicKey {
        key: public_key_bytes,
        algorithm_id: AlgorithmId::IcCanisterSignature,
    }
}

struct CanisterCertificate {
    pub root_pk: ThresholdSigPublicKey,
    /// CBOR-encoded certificate
    pub cbor: Vec<u8>,
    /// Witness for the signature (see [`new_random_canister_state`])
    pub witness: MixedHashTree,
    pub seed: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Returns a random certificate generated using using `rng`.
/// Depending on the `with_delegation` flag, the certificate
/// will contain a subnet delegation.
fn new_random_cert<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    with_delegation: bool,
) -> CanisterCertificate {
    let canister_state = new_random_canister_state(rng);
    let cert_builder = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: GLOBAL_CANISTER_ID,
            certified_data: canister_state.root_digest,
        },
        rng,
    );

    let cert_builder = conditionally_add_delegation_cert(cert_builder, with_delegation);
    let (_cert, root_pk, cert_cbor) = cert_builder.build();

    CanisterCertificate {
        root_pk,
        cbor: cert_cbor,
        witness: canister_state.witness,
        seed: canister_state.seed,
        msg: canister_state.msg,
    }
}

fn conditionally_add_delegation_cert(
    cert_builder: CertificateBuilder,
    with_delegation: bool,
) -> CertificateBuilder {
    if with_delegation {
        cert_builder.with_delegation(CertificateBuilder::new(SubnetData {
            subnet_id: subnet_id(123),
            canister_id_ranges: vec![(canister_id(0), canister_id(10))],
        }))
    } else {
        cert_builder
    }
}

/// Initializes a [`TempCryptoComponent`] with the input root public key
/// and registry version.
pub fn temp_crypto_with_registry_with_root_pubkey(
    threshold_sig_pubkey: ThresholdSigPublicKey,
    registry_version: RegistryVersion,
) -> TempCryptoComponent {
    TempCryptoComponent::builder()
        .with_registry(new_registry_with_root_pk(
            threshold_sig_pubkey,
            registry_version,
        ))
        .build()
}

fn new_registry_with_root_pk(
    threshold_sig_pubkey: ThresholdSigPublicKey,
    registry_version: RegistryVersion,
) -> Arc<FakeRegistryClient> {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    populate_registry_data(
        registry_data.as_ref(),
        threshold_sig_pubkey,
        registry_version,
    );
    registry.update_to_latest_version();
    registry
}

fn populate_registry_data(
    registry_data: &ProtoRegistryDataProvider,
    threshold_sig_pubkey: ThresholdSigPublicKey,
    registry_version: RegistryVersion,
) {
    let root_subnet_id = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: ROOT_SUBNET_ID.get_ref().to_vec(),
        }),
    };
    registry_data
        .add(ROOT_SUBNET_ID_KEY, registry_version, Some(root_subnet_id))
        .expect("failed to add root subnet ID to registry");

    let root_subnet_pubkey = PublicKeyProto::from(threshold_sig_pubkey);
    registry_data
        .add(
            &make_crypto_threshold_signing_pubkey_key(ROOT_SUBNET_ID),
            registry_version,
            Some(root_subnet_pubkey),
        )
        .expect("failed to add root subnet ID to registry");
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}
