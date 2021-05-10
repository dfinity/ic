#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;
use crate::common::test_utils::mock_csp::{
    dummy_signature, MockCryptoServiceProvider, MockCryptoServiceProviderBuilder,
};
use crate::common::test_utils::multi_bls12_381::MultiBls12381TestVector::{
    STABILITY_1, STABILITY_2,
};
use crate::common::test_utils::multi_threading::{
    assert_elapsed_time_smaller_than, crypto_sharing_csp, crypto_sharing_csp_and_registry,
    join_threads, repeat_until_success,
};
use crate::common::test_utils::CryptoRegistryRecord;
use crate::common::test_utils::{basic_sig, hex_to_byte_vec, multi_bls12_381};
use crate::sign::tests::*;
use crate::CryptoComponentFatClient;
use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2;
use ic_interfaces::crypto::{BasicSigner, SignableMock};
use ic_test_utilities::types::ids::{NODE_1, NODE_2};
use ic_types::crypto::{CombinedMultiSigOf, KeyId};
use ic_types::messages::MessageId;
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

const SLEEP_DURATION: u64 = 200;

#[test]
fn should_allow_parallel_execution_of_sign_basic() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_sign_returning(Ok(dummy_signature()))
            .build();
        let (msg, key_record, _sig, _pk) = basic_sig_multi_thread_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp_and_registry(csp, registry_with(key_record));
        let start_time = Instant::now();

        let thread_1 = spawn_sign_basic_thread(msg.clone(), crypto_1);
        let thread_2 = spawn_sign_basic_thread(msg, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_verify_basic_sig() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_verify_returning(Ok(()))
            .build();
        let (msg, key_record, sig, _pk) = basic_sig_multi_thread_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp_and_registry(csp, registry_with(key_record));
        let start_time = Instant::now();

        let thread_1 = spawn_verify_basic_sig_thread(msg.clone(), sig.clone(), crypto_1);
        let thread_2 = spawn_verify_basic_sig_thread(msg, sig, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_verify_request_id_sig() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_verify_returning(Ok(()))
            .build();
        let (pk, msg, sig) = request_id_sig_multi_threading_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp(csp);
        let start_time = Instant::now();

        let thread_1 =
            spawn_verify_request_id_sig_thread(pk.clone(), msg.clone(), sig.clone(), crypto_1);
        let thread_2 = spawn_verify_request_id_sig_thread(pk, msg, sig, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_sign_multi() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_sign_returning(Ok(dummy_signature()))
            .build();
        let (msg, _sig, key_record) = multi_sig_multi_threading_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp_and_registry(csp, registry_with(key_record));
        let start_time = Instant::now();

        let thread_1 = spawn_sign_multi_thread(msg.clone(), crypto_1);
        let thread_2 = spawn_sign_multi_thread(msg, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_verify_multi_sig_individual() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_verify_returning(Ok(()))
            .build();
        let (msg, sig, key_record) = multi_sig_multi_threading_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp_and_registry(csp, registry_with(key_record));
        let start_time = Instant::now();

        let thread_1 = spawn_verify_multi_sig_individual_thread(msg.clone(), sig.clone(), crypto_1);
        let thread_2 = spawn_verify_multi_sig_individual_thread(msg, sig, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_combine_multi_sig_individuals() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_combine_sigs_returning(Ok(dummy_signature()))
            .build();
        let (pk_rec, sigs) = multi_sig_individuals_multi_threading_test_vec();
        let (crypto_1, crypto_2) =
            crypto_sharing_csp_and_registry(csp, registry_with_records(vec![pk_rec]));
        let start_time = Instant::now();

        let thread_1 = spawn_combine_multi_sig_individuals_thread(sigs.clone(), crypto_1);
        let thread_2 = spawn_combine_multi_sig_individuals_thread(sigs, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_verify_multi_sig_combined() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_verify_multisig_returning(Ok(()))
            .build();
        let (msg_1, msg_2, pk_rec_1, pk_rec_2, nodes, comb_sig) =
            multi_sig_combined_multi_threading_test_vec();
        let (crypto_1, crypto_2) =
            crypto_sharing_csp_and_registry(csp, registry_with_records(vec![pk_rec_1, pk_rec_2]));
        let start_time = Instant::now();

        let thread_1 = spawn_verify_multi_sig_combined_thread(
            msg_1,
            nodes.clone(),
            comb_sig.clone(),
            crypto_1,
        );
        let thread_2 = spawn_verify_multi_sig_combined_thread(msg_2, nodes, comb_sig, crypto_2);
        join_threads(thread_1, thread_2);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

#[test]
fn should_allow_parallel_execution_of_two_different_reading_functions() {
    repeat_until_success(100, || {
        let csp = MockCryptoServiceProviderBuilder::new()
            .with_sleep_duration_millis(SLEEP_DURATION)
            .with_sign_returning(Ok(dummy_signature()))
            .with_verify_returning(Ok(()))
            .build();
        let (msg, key_record, sig, _pk) = basic_sig_multi_thread_test_vec();
        let (crypto_1, crypto_2) = crypto_sharing_csp_and_registry(csp, registry_with(key_record));
        let start_time = Instant::now();

        let sign_thread = spawn_sign_basic_thread(msg.clone(), crypto_1);
        let verify_thread = spawn_verify_basic_sig_thread(msg, sig, crypto_2);
        join_threads(sign_thread, verify_thread);

        assert_elapsed_time_smaller_than(start_time, 2 * SLEEP_DURATION)
    });
}

fn multi_sig_individuals_multi_threading_test_vec() -> (
    CryptoRegistryRecord,
    BTreeMap<NodeId, IndividualMultiSigOf<SignableMock>>,
) {
    let (_, pk, _, _, sig) = multi_bls12_381::testvec(STABILITY_1);
    let pk_rec = committee_signing_record_with(
        NODE_1,
        pk.multi_bls12_381_bytes().unwrap().to_vec(),
        KeyId::from(KEY_ID_1),
        REG_V1,
    );
    let signatures = vec![(NODE_1, sig)].into_iter().collect();
    (pk_rec, signatures)
}

fn multi_sig_combined_multi_threading_test_vec() -> (
    SignableMock,
    SignableMock,
    CryptoRegistryRecord,
    CryptoRegistryRecord,
    BTreeSet<NodeId>,
    CombinedMultiSigOf<SignableMock>,
) {
    let (_, pk_1, _, msg_1, _) = multi_bls12_381::testvec(STABILITY_1);
    let (_, pk_2, _, msg_2, _) = multi_bls12_381::testvec(STABILITY_2);
    let pk_rec_1 = committee_signing_record_with(
        NODE_1,
        pk_1.multi_bls12_381_bytes().unwrap().to_vec(),
        KeyId::from(KEY_ID_1),
        REG_V1,
    );
    let pk_rec_2 = committee_signing_record_with(
        NODE_2,
        pk_2.multi_bls12_381_bytes().unwrap().to_vec(),
        KeyId::from(KEY_ID_2),
        REG_V1,
    );
    let nodes: BTreeSet<NodeId> = vec![NODE_1, NODE_2].into_iter().collect();
    let combined_sig = CombinedMultiSigOf::new(CombinedMultiSig(hex_to_byte_vec(
        TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2,
    )));
    (msg_1, msg_2, pk_rec_1, pk_rec_2, nodes, combined_sig)
}

fn basic_sig_multi_thread_test_vec() -> (
    SignableMock,
    CryptoRegistryRecord,
    BasicSigOf<SignableMock>,
    UserPublicKey,
) {
    let (_sk, csp_pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
    let pk = UserPublicKey::try_from(csp_pk.clone()).unwrap();
    let key_record = node_signing_record_with(
        NODE_1,
        csp_pk.ed25519_bytes().unwrap().to_vec(),
        KeyId::from(KEY_ID),
        REG_V1,
    );
    (msg, key_record, sig, pk)
}

fn request_id_sig_multi_threading_test_vec() -> (UserPublicKey, MessageId, BasicSigOf<MessageId>) {
    let request_id = MessageId::from([7; 32]);
    let (sig, pk) = request_id_signature_and_public_key(&request_id, AlgorithmId::Ed25519);
    (pk, request_id, sig)
}

fn multi_sig_multi_threading_test_vec() -> (
    SignableMock,
    IndividualMultiSigOf<SignableMock>,
    CryptoRegistryRecord,
) {
    let (_sk, pk, _pop, msg, sig) = multi_bls12_381::testvec(STABILITY_1);
    let key_record = committee_signing_record_with(
        NODE_1,
        pk.multi_bls12_381_bytes().unwrap().to_vec(),
        KeyId::from(KEY_ID),
        REG_V1,
    );
    (msg, sig, key_record)
}

fn spawn_sign_basic_thread(
    msg: SignableMock,
    crypto_for_thread: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto_for_thread.sign_basic(&msg, NODE_1, REG_V1).unwrap();
    })
}

fn spawn_verify_basic_sig_thread(
    msg: SignableMock,
    sig: BasicSigOf<SignableMock>,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V1).unwrap();
    })
}

fn spawn_verify_request_id_sig_thread(
    pk: UserPublicKey,
    msg: MessageId,
    sig: BasicSigOf<MessageId>,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto
            .verify_basic_sig_by_public_key(&sig, &msg, &pk)
            .unwrap();
    })
}

fn spawn_sign_multi_thread(
    msg: SignableMock,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto.sign_multi(&msg, NODE_1, REG_V1).unwrap();
    })
}

fn spawn_verify_multi_sig_individual_thread(
    msg: SignableMock,
    sig: IndividualMultiSigOf<SignableMock>,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto
            .verify_multi_sig_individual(&sig, &msg, NODE_1, REG_V1)
            .unwrap();
    })
}

fn spawn_combine_multi_sig_individuals_thread(
    signatures: BTreeMap<NodeId, IndividualMultiSigOf<SignableMock>>,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto
            .combine_multi_sig_individuals(signatures, REG_V1)
            .unwrap();
    })
}

fn spawn_verify_multi_sig_combined_thread(
    msg: SignableMock,
    nodes: BTreeSet<NodeId>,
    combined_sig: CombinedMultiSigOf<SignableMock>,
    crypto: Arc<CryptoComponentFatClient<MockCryptoServiceProvider>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        crypto
            .verify_multi_sig_combined(&combined_sig, &msg, nodes, REG_V1)
            .unwrap();
    })
}
