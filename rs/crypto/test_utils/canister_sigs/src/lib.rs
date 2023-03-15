//! Utilities for testing canister signature operations.

use std::sync::Arc;

use ic_certification_test_utils::serialize_to_cbor;
use ic_crypto_internal_basic_sig_iccsa::types::Signature;
use ic_crypto_internal_basic_sig_iccsa_test_utils::new_random_cert;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
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
use ic_types::{CanisterId, SubnetId};
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
    let canister_sig =
        CanisterSigOf::from(CanisterSig(serialize_to_cbor(&sig_with_canister_witness)));
    let canister_pk = derive_canister_pk(&cert.seed[..]);
    CanisterSigTestData {
        crypto: temp_crypto,
        msg: signable_msg,
        canister_sig,
        canister_pk,
        root_pk: cert.root_pk,
    }
}

fn derive_canister_pk(canister_seed: &[u8]) -> UserPublicKey {
    let public_key_bytes = canister_sig_pub_key_to_bytes(GLOBAL_CANISTER_ID, canister_seed);

    UserPublicKey {
        key: public_key_bytes,
        algorithm_id: AlgorithmId::IcCanisterSignature,
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

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}
