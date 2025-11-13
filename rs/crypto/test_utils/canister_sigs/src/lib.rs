//! Utilities for testing canister signature operations.

use ic_certification_test_utils::serialize_to_cbor;
use ic_crypto_internal_basic_sig_iccsa::types::Signature;
use ic_crypto_internal_basic_sig_iccsa_test_utils::new_random_cert;
use ic_crypto_temp_crypto::{TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
use ic_types::CanisterId;
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use ic_types::crypto::{AlgorithmId, CanisterSig, CanisterSigOf, SignableMock, UserPublicKey};
use ic_types::messages::Blob;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const GLOBAL_CANISTER_ID: CanisterId = canister_id(1);

pub struct CanisterSigTestData {
    pub crypto: TempCryptoComponentGeneric<ChaCha20Rng>,
    pub msg: SignableMock,
    pub canister_sig: CanisterSigOf<SignableMock>,
    pub canister_pk: UserPublicKey,
    pub root_of_trust: IcRootOfTrust,
}

/// Initializes an environment for benchmarking or testing canister signature verification.
/// The message, seed and keys are randomly generated based on the randomness from `rng`.
pub fn new_valid_sig_and_crypto_component<R: Rng + RngCore + CryptoRng>(
    rng: &mut R,
    with_delegation: bool,
) -> CanisterSigTestData {
    let cert = new_random_cert(rng, with_delegation);
    let temp_crypto = TempCryptoComponent::builder()
        .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
        .build();

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
        root_of_trust: IcRootOfTrust::from(cert.root_pk),
    }
}

fn derive_canister_pk(canister_seed: &[u8]) -> UserPublicKey {
    let public_key_bytes = canister_sig_pub_key_to_bytes(GLOBAL_CANISTER_ID, canister_seed);

    UserPublicKey {
        key: public_key_bytes,
        algorithm_id: AlgorithmId::IcCanisterSignature,
    }
}

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}
